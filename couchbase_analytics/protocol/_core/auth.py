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

from typing import TYPE_CHECKING, Generator

from httpx import Auth, Request, Response

from couchbase_analytics.common.credential import _SupportsAuthHeader

if TYPE_CHECKING:
    from couchbase_analytics.protocol.connection import _ConnectionDetails


class DynamicCredentialAuth(Auth):
    """httpx ``Auth`` that reads the current credential from ``_ConnectionDetails`` at
    request time, so rotating a credential via ``Cluster.set_credential`` takes effect
    immediately without rebuilding the HTTP client.

    Cert credentials authenticate during the TLS handshake, so the auth_flow no-ops
    for them — the runtime ``_SupportsAuthHeader`` check picks out password/JWT.
    """

    def __init__(self, conn_details: _ConnectionDetails) -> None:
        self._conn_details = conn_details

    def auth_flow(self, request: Request) -> Generator[Request, Response, None]:
        cred = self._conn_details.credential
        if isinstance(cred, _SupportsAuthHeader):
            request.headers['Authorization'] = cred.http_authorization_header()
        yield request
