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

from typing import TYPE_CHECKING

from httpx import Auth, Request

if TYPE_CHECKING:
    from couchbase_analytics.protocol.connection import _ConnectionDetails


class DynamicCredentialAuth(Auth):
    """httpx ``Auth`` that reads the current credential from ``_ConnectionDetails`` at
    request time, so rotating a credential via ``Cluster.set_credential`` takes effect
    immediately without rebuilding the HTTP client.
    """

    def __init__(self, conn_details: _ConnectionDetails) -> None:
        self._conn_details = conn_details

    def auth_flow(self, request: Request):  # type: ignore[no-untyped-def]
        header = self._conn_details.credential.http_authorization_header()
        if header is not None:
            request.headers['Authorization'] = header
        # Client-certificate credentials authenticate during the TLS handshake, so no
        # Authorization header is set.
        yield request
