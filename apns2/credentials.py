import ssl
import time
from os import PathLike
from typing import Optional, Tuple, Union

import jwt

DEFAULT_TOKEN_LIFETIME = 2700
DEFAULT_TOKEN_ENCRYPTION_ALGORITHM = 'ES256'


# Abstract Base class. This should not be instantiated directly.
class Credentials(object):
    def __init__(self, ssl_context: Optional[ssl.SSLContext] = None) -> None:
        super().__init__()
        self.ssl_context = ssl_context

    def get_authorization_header(self, topic: Optional[str]) -> Optional[str]:
        return None

    def get_cert_file(self):
        return None

    def get_password(self):
        return None

    def get_ssl_context(self):
        return self.ssl_context


# Credentials subclass for certificate authentication
class CertificateCredentials(Credentials):
    def __init__(self,
                 cert_file_path: Optional[Union[str, bytes, PathLike[str], PathLike[bytes]]] = None,
                 password: Optional[str] = None) -> None:
        self.ssl_context = ssl.create_default_context()
        # httpx only supports adding ssl certs to the chain as a path,
        # which precludes the use of a secrets manager without doing some temp file trickery
        self.ssl_context.load_cert_chain(certfile=cert_file_path, password=password)
        self.cert_file = cert_file_path
        self.password = password
        super(CertificateCredentials, self).__init__(self.ssl_context)

    def get_cert_file(self):
        return self.cert_file

    def get_password(self):
        return self.password


# Credentials subclass for JWT token based authentication
class TokenCredentials(Credentials):
    def __init__(self, auth_key: str, auth_key_id: str, team_id: str,
                 encryption_algorithm: str = DEFAULT_TOKEN_ENCRYPTION_ALGORITHM,
                 token_lifetime: int = DEFAULT_TOKEN_LIFETIME) -> None:
        self.key = auth_key
        self.__auth_key = self.key
        self.__auth_key_id = auth_key_id
        self.__team_id = team_id
        self.__encryption_algorithm = encryption_algorithm
        self.__token_lifetime = token_lifetime

        self.__jwt_token = None  # type: Optional[Tuple[float, str]]

        # Use the default constructor because we don't have an SSL context
        super(TokenCredentials, self).__init__()

    def get_authorization_header(self, topic: Optional[str]) -> str:
        token = self._get_or_create_topic_token()
        return 'bearer %s' % token

    def _is_expired_token(self, issue_date: float) -> bool:
        return time.time() > issue_date + self.__token_lifetime

    @staticmethod
    def _get_signing_key(key_path: str) -> str:
        secret = ''
        if key_path:
            with open(key_path) as f:
                secret = f.read()
        return secret

    def _get_or_create_topic_token(self) -> str:
        # dict of topic to issue date and JWT token
        token_pair = self.__jwt_token
        if token_pair is None or self._is_expired_token(token_pair[0]):
            # Create a new token
            issued_at = time.time()
            token_dict = {
                'iss': self.__team_id,
                'iat': issued_at,
            }
            headers = {
                'alg': self.__encryption_algorithm,
                'kid': self.__auth_key_id,
            }
            jwt_token = jwt.encode(token_dict, self.__auth_key,
                                   algorithm=self.__encryption_algorithm,
                                   headers=headers)

            # Cache JWT token for later use. One JWT token per connection.
            # https://developer.apple.com/documentation/usernotifications/setting_up_a_remote_notification_server/establishing_a_token-based_connection_to_apns
            self.__jwt_token = (issued_at, jwt_token)
            return jwt_token
        else:
            return token_pair[1]
