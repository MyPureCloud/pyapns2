import collections
import json
import logging
from enum import Enum
from typing import Dict, Iterable, Optional, Tuple, Union, Any

from .credentials import CertificateCredentials, Credentials
from .errors import exception_class_for_reason
# We don't generally need to know about the Credentials subclasses except to
# keep the old API, where APNsClient took a cert_file
from .payload import Payload


class NotificationPriority(Enum):
    Immediate = '10'
    Delayed = '5'


class NotificationType(Enum):
    Alert = 'alert'
    Background = 'background'
    VoIP = 'voip'
    Complication = 'complication'
    FileProvider = 'fileprovider'
    MDM = 'mdm'


RequestStream = collections.namedtuple('RequestStream', ['stream_id', 'token'])
Notification = collections.namedtuple('Notification', ['token', 'payload'])

DEFAULT_APNS_PRIORITY = NotificationPriority.Immediate
CONCURRENT_STREAMS_SAFETY_MAXIMUM = 1000
MAX_CONNECTION_RETRIES = 3

logger = logging.getLogger(__name__)


class APNsClient(object):
    SANDBOX_SERVER = 'api.development.push.apple.com'
    LIVE_SERVER = 'api.push.apple.com'

    DEFAULT_PORT = 443
    ALTERNATIVE_PORT = 2197

    def __init__(self,
                 credentials: Union[Credentials, str],
                 use_sandbox: bool = False, use_alternative_port: bool = False, proto: Optional[str] = None,
                 json_encoder: Optional[type] = None, password: Optional[str] = None,
                 proxy_host: Optional[str] = None, proxy_port: Optional[int] = None,
                 heartbeat_period: Optional[float] = None) -> None:
        if isinstance(credentials, str):
            self.__credentials = CertificateCredentials(credentials, password)  # type: Credentials
        else:
            self.__credentials = credentials
        self._init_connection(use_sandbox, use_alternative_port, proto, proxy_host, proxy_port)

        if heartbeat_period:
            raise NotImplementedError("heartbeat not supported")

        self.__json_encoder = json_encoder
        self.__max_concurrent_streams = 0
        self.__previous_server_max_concurrent_streams = None

    def _init_connection(self, use_sandbox: bool, use_alternative_port: bool, proto: Optional[str],
                         proxy_host: Optional[str], proxy_port: Optional[int]) -> None:
        server = self.SANDBOX_SERVER if use_sandbox else self.LIVE_SERVER
        port = self.ALTERNATIVE_PORT if use_alternative_port else self.DEFAULT_PORT
        self._connection = self.__credentials.create_connection(server, port, proto, proxy_host, proxy_port)

    def send_notification(self, token_hex: str, notification: Payload, topic: Optional[str] = None,
                          priority: NotificationPriority = NotificationPriority.Immediate,
                          expiration: Optional[int] = None, collapse_id: Optional[str] = None) -> None:
        status, reason = self.send_notification_async(token_hex, notification, topic, priority, expiration, collapse_id)
        result = self.get_notification_result(status, reason)
        if result != 'Success':
            if isinstance(result, tuple):
                reason, info = result
                raise exception_class_for_reason(reason)(info)
            else:
                raise exception_class_for_reason(result)

    async def send_notification_async(self, token_hex: str, notification: Payload, topic: Optional[str] = None,
                                      priority: NotificationPriority = NotificationPriority.Immediate,
                                      expiration: Optional[int] = None, collapse_id: Optional[str] = None,
                                      push_type: Optional[NotificationType] = None) -> tuple[Any, Any]:
        json_str = json.dumps(notification.dict(), cls=self.__json_encoder, ensure_ascii=False, separators=(',', ':'))
        json_payload = json_str.encode('utf-8')

        headers = {}

        inferred_push_type = None  # type: Optional[str]
        if topic is not None:
            headers['apns-topic'] = topic
            if topic.endswith('.voip'):
                inferred_push_type = NotificationType.VoIP.value
            elif topic.endswith('.complication'):
                inferred_push_type = NotificationType.Complication.value
            elif topic.endswith('.pushkit.fileprovider'):
                inferred_push_type = NotificationType.FileProvider.value
            elif any([
                notification.alert is not None,
                notification.badge is not None,
                notification.sound is not None,
            ]):
                inferred_push_type = NotificationType.Alert.value
            else:
                inferred_push_type = NotificationType.Background.value

        if push_type:
            inferred_push_type = push_type.value

        if inferred_push_type:
            headers['apns-push-type'] = inferred_push_type

        if priority != DEFAULT_APNS_PRIORITY:
            headers['apns-priority'] = priority.value

        if expiration is not None:
            headers['apns-expiration'] = '%d' % expiration

        auth_header = self.__credentials.get_authorization_header(topic)
        if auth_header is not None:
            headers['authorization'] = auth_header

        if collapse_id is not None:
            headers['apns-collapse-id'] = collapse_id

        with self._connection as client:
            url = '/3/device/{}'.format(token_hex)
            response = await client.request('POST', url, data=json_payload, headers=headers)

        return response.status_code, response.text

    def send_notification_batch(self, notifications: Iterable[Notification], topic: Optional[str] = None,
                                priority: NotificationPriority = NotificationPriority.Immediate,
                                expiration: Optional[int] = None, collapse_id: Optional[str] = None,
                                push_type: Optional[NotificationType] = None) -> Dict[str, Union[str, Tuple[str, str]]]:
        """
        Send a notification to a list of tokens in batch.

        The function returns a dictionary mapping each token to its result. The result is "Success"
        if the token was sent successfully, or the string returned by APNs in the 'reason' field of
        the response, if the token generated an error.
        """
        results = {}

        # Loop over notifications
        with self._connection as client:
            for next_notification in notifications:
                logger.info('Sending to token %s', next_notification.token)
                status, reason = self.send_notification_async(next_notification.token, next_notification.payload,
                                                              topic, priority, expiration, collapse_id, push_type)
                result = self.get_notification_result(status, reason)
                logger.info('Got response for %s: %s', next_notification.token, result)
                results[next_notification.token] = result

        return results

    @staticmethod
    def get_notification_result(status, reason):
        """
        Get result for specified stream
        The function returns: 'Success' or 'failure reason' or ('Unregistered', timestamp)
        """
        if status == 200:
            return 'Success'
        else:
            return reason
