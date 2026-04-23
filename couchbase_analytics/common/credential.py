#  Copyright 2016-2025. Couchbase, Inc.
#  All Rights Reserved.
#
#  Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
#  You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
#  Unless required by applicable law or agreed to in writing, software
#  distributed under the License is distributed on an "AS IS" BASIS,
#  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#  See the License for the specific language governing permissions and
#  limitations under the License.


from __future__ import annotations

from base64 import b64encode
from enum import Enum
from typing import Callable, Dict


class CredentialType(Enum):
    PASSWORD = 'password'
    JWT = 'jwt'


class Credential:
    """Create a Credential instance.

    A Credential is required in order to connect to a Analytics endpoint.

    .. important::
        Use the the provided classmethods to create a :class:`.Credential` instance.

    """

    def __init__(self, **kwargs: str) -> None:
        token = kwargs.pop('jwt_token', None)
        username = kwargs.pop('username', None)
        password = kwargs.pop('password', None)

        if token is not None:
            if not isinstance(token, str):
                raise ValueError('The JWT token must be a str.')
            if username is not None or password is not None:
                raise ValueError('Cannot provide both a JWT token and username/password.')
            self._type = CredentialType.JWT
            self._token = token.strip()
            # Pre-compute the Authorization header so per-request dispatch is a cheap attribute read.
            self._auth_header = f'Bearer {self._token}'
            return

        if username is None:
            raise ValueError('Must provide a username.')
        if not isinstance(username, str):
            raise ValueError('The username must be a str.')

        if password is None:
            raise ValueError('Must provide a password.')
        if not isinstance(password, str):
            raise ValueError('The password must be a str.')

        self._type = CredentialType.PASSWORD
        self._username = username
        self._password = password
        # Pre-compute the Authorization header so per-request dispatch is a cheap attribute read.
        self._auth_header = 'Basic ' + b64encode(f'{username}:{password}'.encode('utf-8')).decode('ascii')

    @property
    def credential_type(self) -> CredentialType:
        return self._type

    def asdict(self) -> Dict[str, str]:
        """
        **INTERNAL**
        """
        if self._type is CredentialType.JWT:
            return {'jwt_token': self._token}
        return {'username': self._username, 'password': self._password}

    def http_authorization_header(self) -> str:
        return self._auth_header

    @classmethod
    def from_username_and_password(cls, username: str, password: str) -> Credential:
        """Create a :class:`.Credential` from a username and password.

        Args:
            username: The username for the Analytics endpoint.
            password: The password for the Analytics endpoint.

        Returns:
            A Credential instance.
        """
        return Credential(username=username, password=password)

    @classmethod
    def from_jwt(cls, token: str) -> Credential:
        """Create a :class:`.Credential` from a JSON Web Token (JWT).

        The SDK sends an ``Authorization: Bearer <jwt>`` header on every HTTP request.

        .. note::
            A JWT credential typically has a relatively short validity period.  To avoid
            authentication failures caused by stale credentials, periodically pass a
            fresh credential via :meth:`~couchbase_analytics.cluster.Cluster.set_credential`.

        Args:
            token: The JSON Web Token.

        Returns:
            A Credential instance.
        """
        return Credential(jwt_token=token)

    @classmethod
    def from_callable(cls, callback: Callable[[], Credential]) -> Credential:
        """Create a :class:`.Credential` from provided callback.

        Args:
            callback: Callback that returns a :class:`.Credential`.

        Returns:
            A Credential instance.

        Example:
            Retrieve credentials from environment variables::

                def _cred_from_env() -> Credential:
                    from os import getenv
                    return Credential.from_username_and_password(getenv('PYCBCC_USERNAME'),
                                                                 getenv('PYCBCC_PW'))

                cred = Credential.from_callable(_cred_from_env)

        """
        return Credential(**callback().asdict())

    def __repr__(self) -> str:
        if self._type is CredentialType.JWT:
            return 'Credential(jwt_token=****)'
        return f'Credential(username={self._username}, password=****)'

    def __str__(self) -> str:
        return self.__repr__()
