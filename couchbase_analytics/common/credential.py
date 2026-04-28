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

import ssl
from base64 import b64encode
from typing import Protocol, Union, runtime_checkable

from couchbase_analytics.common._core.utils import is_null_or_empty, validate_path


@runtime_checkable
class _SupportsAuthHeader(Protocol):
    """**INTERNAL** capability narrowing protocol — credentials that authenticate via an HTTP
    ``Authorization`` header. Used at SDK-internal call sites (e.g. ``DynamicCredentialAuth``)
    to dispatch on capability without coupling to concrete credential classes.
    """

    def http_authorization_header(self) -> str: ...


@runtime_checkable
class _SupportsClientCertChain(Protocol):
    """**INTERNAL** capability narrowing protocol — credentials that authenticate during the
    TLS handshake via a client certificate. Used at SDK-internal call sites to dispatch on
    capability without coupling to concrete credential classes.
    """

    def load_client_cert_chain(self, ctx: ssl.SSLContext) -> None: ...


class Credential:
    """RBAC username + password authentication, sent as HTTP Basic."""

    def __init__(self, username: str, password: str) -> None:
        if not isinstance(username, str):
            raise ValueError('Username must be a str.')
        if not isinstance(password, str):
            raise ValueError('Password must be a str.')
        self._username = username
        self._auth_header = 'Basic ' + b64encode(f'{username}:{password}'.encode('utf-8')).decode('ascii')

    def http_authorization_header(self) -> str:
        return self._auth_header

    def __repr__(self) -> str:
        return f'Credential(username={self._username}, password=****)'

    __str__ = __repr__


class JwtCredential:
    """JSON Web Token authentication, sent as HTTP Bearer.

    JWTs typically have a short validity window — rotate before expiry by
    passing a fresh credential to :meth:`Cluster.set_credential`.
    """

    def __init__(self, token: str) -> None:
        if not isinstance(token, str):
            raise ValueError('JWT token must be a str.')
        if is_null_or_empty(token):
            raise ValueError('JWT token must not be empty.')
        self._auth_header = f'Bearer {token.strip()}'

    def http_authorization_header(self) -> str:
        return self._auth_header

    def __repr__(self) -> str:
        return 'JwtCredential(jwt_token=****)'

    __str__ = __repr__


class CertificateCredential:
    """Client certificate (mTLS) authentication, established during the TLS handshake.

    Requires an ``https://`` endpoint.  Rotation rebuilds the underlying httpx
    Client because the cert is baked into the SSL context.
    """

    def __init__(self, cert_path: str, key_path: str) -> None:
        # Existence is validated up-front for a clear error at construction time;
        # the actual cert chain is read lazily by load_client_cert_chain when the
        # SSL context is built.
        self._cert_path = validate_path(cert_path)
        self._key_path = validate_path(key_path)

    def load_client_cert_chain(self, ctx: ssl.SSLContext) -> None:
        ctx.load_cert_chain(certfile=self._cert_path, keyfile=self._key_path)

    def __repr__(self) -> str:
        return f'CertificateCredential(cert_path={self._cert_path}, key_path=****)'

    __str__ = __repr__


# Public type alias for "any credential the SDK accepts". Use this in user code
# that takes a credential as a parameter.
AnyCredential = Union[Credential, JwtCredential, CertificateCredential]
