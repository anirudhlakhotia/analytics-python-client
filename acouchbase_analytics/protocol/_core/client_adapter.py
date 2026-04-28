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

import logging
from typing import TYPE_CHECKING, Optional, cast
from uuid import uuid4

from httpx import URL, AsyncClient, Response

from couchbase_analytics.common.credential import AnyCredential, _SupportsClientCertChain
from couchbase_analytics.common.deserializer import Deserializer
from couchbase_analytics.common.logging import LogLevel, log_message
from couchbase_analytics.protocol._core.auth import DynamicCredentialAuth
from couchbase_analytics.protocol.connection import _ConnectionDetails
from couchbase_analytics.protocol.options import OptionsBuilder

if TYPE_CHECKING:
    from couchbase_analytics.protocol._core.request import QueryRequest


class _AsyncClientAdapter:
    """
    **INTERNAL**
    """

    ANALYTICS_PATH = '/api/v1/request'
    LOGGER_NAME = 'acouchbase_analytics'

    def __init__(
        self, http_endpoint: str, credential: AnyCredential, options: Optional[object] = None, **kwargs: object
    ) -> None:
        self._client_id = str(uuid4())
        self._prefix = ''
        self._cluster_id = cast(str, kwargs.pop('cluster_id', ''))
        self._opts_builder = OptionsBuilder()
        kwargs['logger_name'] = self.logger_name
        self._conn_details = _ConnectionDetails.create(self._opts_builder, http_endpoint, credential, options, **kwargs)
        # PYCO-67:  Do we want to allow supporting custom HTTP transports?
        self._http_transport_cls = None

    @property
    def analytics_path(self) -> str:
        """
        **INTERNAL**
        """
        return self.ANALYTICS_PATH

    @property
    def client(self) -> AsyncClient:
        """
        **INTERNAL**
        """
        return self._client

    @property
    def client_id(self) -> str:
        """
        **INTERNAL**
        """
        return self._client_id

    @property
    def connection_details(self) -> _ConnectionDetails:
        """
        **INTERNAL**
        """
        return self._conn_details

    @property
    def default_deserializer(self) -> Deserializer:
        """
        **INTERNAL**
        """
        return self._conn_details.default_deserializer

    @property
    def has_client(self) -> bool:
        """
        **INTERNAL**
        """
        return hasattr(self, '_client')

    @property
    def log_prefix(self) -> str:
        """
        **INTERNAL**
        """
        if self._prefix:
            return self._prefix
        self._prefix = f'[{self._cluster_id}'
        if self.has_client:
            self._prefix += f'/{self._client_id}'
            if self.connection_details.is_secure():
                self._prefix += '/https]'
            else:
                self._prefix += '/http]'

        return self._prefix

    @property
    def logger_name(self) -> str:
        """
        **INTERNAL**
        """
        return self.LOGGER_NAME

    @property
    def options_builder(self) -> OptionsBuilder:
        """
        **INTERNAL**
        """
        return self._opts_builder

    async def close_client(self) -> None:
        """
        **INTERNAL**
        """
        if hasattr(self, '_client'):
            await self._client.aclose()
            self.log_message('Cluster HTTP client closed', LogLevel.INFO)

    def _build_client(self) -> AsyncClient:
        auth = DynamicCredentialAuth(self._conn_details)
        if self._conn_details.is_secure():
            if self._conn_details.ssl_context is None:
                raise ValueError('SSL context is required for secure connections.')
            transport = None
            if self._http_transport_cls is not None:
                transport = self._http_transport_cls(verify=self._conn_details.ssl_context)
            return AsyncClient(
                verify=self._conn_details.ssl_context,
                auth=auth,
                transport=transport,
            )
        transport = None
        if self._http_transport_cls is not None:
            transport = self._http_transport_cls()
        return AsyncClient(auth=auth, transport=transport)

    async def create_client(self) -> None:
        """
        **INTERNAL**
        """
        if not hasattr(self, '_client'):
            self._client = self._build_client()
            self.log_message(
                (f'Cluster HTTP client created: connection_details={self._conn_details.get_init_details()}'),
                LogLevel.INFO,
            )
        else:
            self.log_message('Cluster HTTP client already exists, skipping creation.', LogLevel.INFO)

    def log_message(self, message: str, log_level: LogLevel) -> None:
        log_message(logger, f'{self.log_prefix} {message}', log_level)

    async def send_request(self, request: QueryRequest) -> Response:
        """
        **INTERNAL**
        """
        if not hasattr(self, '_client'):
            raise RuntimeError('Client not created yet')

        url = URL(
            scheme=request.url.scheme,
            host=request.url.ip,
            port=request.url.port,
            path=request.url.path,
        )
        req = self._client.build_request(request.method, url, json=request.body, extensions=request.extensions)
        return await self._client.send(req, stream=True)

    def reset_client(self) -> None:
        """
        **INTERNAL**
        """
        if hasattr(self, '_client'):
            del self._client

    async def update_credential(self, new_credential: AnyCredential) -> None:
        current = self._conn_details.credential
        if type(current) is not type(new_credential):
            raise ValueError(
                f'Cannot switch credential type at runtime; current type is '
                f'{type(current).__name__}, new type is {type(new_credential).__name__}.'
            )
        self._conn_details.credential = new_credential

        # JWT/password rotation is free: DynamicCredentialAuth re-reads the credential
        # from _conn_details on every request. mTLS bakes the cert into the SSLContext
        # which is baked into the httpx AsyncClient, so the Client must be rebuilt.
        # Build the new Client first, swap, then close the old one — this keeps
        # _client populated throughout so concurrent send_request never sees it absent.
        # In-flight streams on the old Client are cancelled by httpx on aclose().
        if isinstance(new_credential, _SupportsClientCertChain):
            self._conn_details.validate_security_options()
            old_client = getattr(self, '_client', None)
            self._client = self._build_client()
            if old_client is not None:
                await old_client.aclose()

        self.log_message('Cluster HTTP credential updated', LogLevel.INFO)


logger = logging.getLogger(_AsyncClientAdapter.LOGGER_NAME)
