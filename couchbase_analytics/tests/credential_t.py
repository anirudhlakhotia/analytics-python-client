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

import pathlib
from base64 import b64encode
from typing import Tuple

import pytest
from httpx import Request

from couchbase_analytics.credential import (
    CertificateCredential,
    Credential,
    JwtCredential,
)
from couchbase_analytics.protocol._core.auth import DynamicCredentialAuth
from couchbase_analytics.protocol._core.client_adapter import _ClientAdapter

_SAMPLE_JWT = 'eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.payload.signature'

# Self-signed RSA cert valid 2025-2125, generated for tests only. Has no real-world value.
_TEST_CERT_PEM = """\
-----BEGIN CERTIFICATE-----
MIICzjCCAbagAwIBAgIUNe8AC/EhfT+KmoVlrOksVayaPUYwDQYJKoZIhvcNAQEL
BQAwIDEeMBwGA1UEAwwVYW5hbHl0aWNzLXRlc3QtY2xpZW50MCAXDTI1MDEwMTAw
MDAwMFoYDzIxMjUwMTAxMDAwMDAwWjAgMR4wHAYDVQQDDBVhbmFseXRpY3MtdGVz
dC1jbGllbnQwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDdFtCuZpSF
/l24Pr/PX1sQKqYnXwOaSiuzEuCF3rSRFVv+KevZu0M4w2y+crdJbP3y99Cup3Rw
ELJOhYN8SBg5moCLhJy5UdP5UWWNU5rPn5VKL0Y20/+i6gOpUsy4kixuNQDF+S+9
SwLgRWsGoJ9h2b4BE6nMAY/Clq7cRQRm4YNcL6eSI1iIokOv9TKBp1ppmYCZHDQ7
VVG6sMwJl83O3t1AkVd+1159t2VNRnUJRzUo3Ulwp1wmRakqF8uPuKw0ELEt/Zy5
qQLyol4NT6y+JlzSaP9tcugW5pOzvbh6WUU0u3Oqx/WVBZEbJE/VMFhLE4z6CUCU
eDJzWnkg/QPFAgMBAAEwDQYJKoZIhvcNAQELBQADggEBAIok45zWOuLocDLkrSto
llyB41MyrbREsoGFz/rt9dHuvYmRWmQad/UyWbXlfOxIO5lVpm6Y8xKDOG1fdXKL
jPNPQn6FNbk96BbA1+hLcPB6gVoVqOQGOr5+qM9hk2WISey/xEgGDsuR1rAtHbSH
QL/gxFurqLd+4UTU8UBCnuaMMNbW9ND99Dsbf/nF9wyx9aiHz/Ms77tBhVbEmGxy
IexZmTSlJkJwSK6EdZdEuPxp17QTzhqjy1OgIkxg9917hHi4sMjs550Q515yavi9
dmuMIjF019UgrsrhSP/9FVb/1UJfi2Dw2cLZWwT8m25wPecrsJqPu273aWJsXqMW
85A=
-----END CERTIFICATE-----
"""

_TEST_KEY_PEM = """\
-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEA3RbQrmaUhf5duD6/z19bECqmJ18DmkorsxLghd60kRVb/inr
2btDOMNsvnK3SWz98vfQrqd0cBCyToWDfEgYOZqAi4ScuVHT+VFljVOaz5+VSi9G
NtP/ouoDqVLMuJIsbjUAxfkvvUsC4EVrBqCfYdm+AROpzAGPwpau3EUEZuGDXC+n
kiNYiKJDr/UygadaaZmAmRw0O1VRurDMCZfNzt7dQJFXftdefbdlTUZ1CUc1KN1J
cKdcJkWpKhfLj7isNBCxLf2cuakC8qJeDU+sviZc0mj/bXLoFuaTs724ellFNLtz
qsf1lQWRGyRP1TBYSxOM+glAlHgyc1p5IP0DxQIDAQABAoIBABDiHHl/oo6WSCM5
F34HMssJ7A+hn9gjxdvc8IGzP2gSO34t8VwlLWhOSXrvA7Qlu0GB+dD8lKsM0LD9
B8zGgfhpe1uBev5j6KNnZdvkVd7OZEt6pLVXJx8SbnPQZjXKDn6JVE/J9wKmPHKn
78Oydw61NAnyWHXDFhlZVxfButOoTKaBOhqLHE7mrTYwEa6aglufAuKPun0kXpLY
HBLfS0fv5hF7jOzq32/bJPmEmxratU7Z3i1Lxboijwe+RbHav8VA4ELZdGsNOzvX
Qc7q3wSRphdXcGmTGtr6x6BeKnaxR+Y7JI+CxkL1u2uwRL6MjqE9C9xYZn2Rg89n
xvxjlsECgYEA9iIi0XmXOvMQBuEahvbXBt5KNAJvOnBPYYLmEkz63l59StTgYvUU
F4jcguDRLN6cYsS1ZkXNnUmNlYcUmpuazmrtLaVrK0faQcgih4maM6YJc8fyvUsM
n9HP26NzJszusjjYUyZ0SaE6vfyc/u7OF5eXBgZHdotr8sQOvI7GnikCgYEA5fOr
wJbvAB62EovQNSQ6BqN8Y7szfI/Y56FnRc9DyUAip4bseb+wBpqPAA7e9vbpJq24
hwimO+rJ0W4oHig8M6c1cSH5oz2vMjEXByJh7XonnleOLRN0I74q8b0g2r9Ds8fL
hbsYAXVYHzH7ekqcGMdZnoNpzHVJJtiLsOZhND0CgYEAjDWT6go+yPjvV0viBaIV
ibcVRB1i6UJTJfQgRaqOeiAPdZJgpF6B7IotO20AG3RQV79Aqpr27zOYMOa7KPud
KxskMw15SDVtMm3kpZsQOX3LAqaTM5vN/DjUFIU+soqpKuNQ78UHF259/P4rHNpC
kpPrFyZ6jSANBUUENAuNP0kCgYBmgfR7mw0Z8Zbat6buOaMAWJrX3pi6G2nnAAWI
kje2nDeWlMgQEgqHNxkuPnLYhwMycdjDoXBxX13uVXvezbLgl9Z0A2BEi/fwmP+Z
95LOCVll9cP0hiqM0HZWYyglO4QTvaoViGzQIZ5R8bcYMfBZ/2wNBKoCMfqVLY1A
I8MLRQKBgQDl7s+D92TP566VnM90di4/V3A1y7OzqAQI83RqVJwFhFCkN9jsm/7t
mD1dBmvzq/Gu7yxkEu6b5P5m0C/inOG7FRM7BvcoDpZreC1TRALo/6WoqTcfVJ+y
LrWlXyIGV+bPN8apXYgjVuudtir671ZPEyKCCjkkOxrlNgZmQmfBtQ==
-----END RSA PRIVATE KEY-----
"""


@pytest.fixture(scope='module')
def cert_paths(tmp_path_factory: pytest.TempPathFactory) -> Tuple[str, str]:
    # Module-scoped: the cert+key are static, so writing them once per module avoids
    # ~one PEM parse per cert test when an SSL context is built downstream.
    tmp_path = tmp_path_factory.mktemp('mtls_creds')
    cert = tmp_path / 'client.pem'
    key = tmp_path / 'client.key'
    cert.write_text(_TEST_CERT_PEM)
    key.write_text(_TEST_KEY_PEM)
    return str(cert), str(key)


class CredentialTestSuite:
    TEST_MANIFEST = [
        'test_password_credential_http_authorization_header',
        'test_password_credential_repr_redacts_password',
        'test_password_credential_rejects_non_string',
        'test_jwt_credential_creation',
        'test_jwt_credential_strips_token',
        'test_jwt_credential_rejects_non_string',
        'test_jwt_credential_rejects_empty',
        'test_jwt_credential_repr_redacts_token',
        'test_certificate_credential_creation',
        'test_certificate_credential_rejects_nonexistent_path',
        'test_certificate_credential_repr_redacts_key_path',
        'test_dynamic_auth_sets_header_from_current_credential',
        'test_dynamic_auth_picks_up_rotated_credential',
        'test_dynamic_auth_omits_header_for_certificate',
        'test_set_credential_same_type_updates_state',
        'test_set_credential_password_to_jwt_fails',
        'test_set_credential_jwt_to_password_fails',
        'test_set_credential_failure_does_not_change_state',
        'test_certificate_requires_https_endpoint',
        'test_set_credential_certificate_rotation_rebuilds_client',
        'test_set_credential_certificate_to_password_fails',
        'test_set_credential_password_to_certificate_fails',
    ]

    def test_password_credential_http_authorization_header(self) -> None:
        cred = Credential('Administrator', 'password')
        expected = 'Basic ' + b64encode(b'Administrator:password').decode('ascii')
        assert cred.http_authorization_header() == expected

    def test_password_credential_repr_redacts_password(self) -> None:
        cred = Credential('Administrator', 'super-secret')
        rendered = repr(cred)
        assert 'super-secret' not in rendered
        assert '****' in rendered
        assert 'Administrator' in rendered

    @pytest.mark.parametrize('bad_value', [12345, None, b'bytes', 1.5, ['a', 'b']])
    def test_password_credential_rejects_non_string(self, bad_value: object) -> None:
        with pytest.raises(ValueError):
            Credential(bad_value, 'password')  # type: ignore[arg-type]
        with pytest.raises(ValueError):
            Credential('user', bad_value)  # type: ignore[arg-type]

    def test_jwt_credential_creation(self) -> None:
        cred = JwtCredential(_SAMPLE_JWT)
        assert cred.http_authorization_header() == f'Bearer {_SAMPLE_JWT}'

    def test_jwt_credential_strips_token(self) -> None:
        cred = JwtCredential(f'  {_SAMPLE_JWT}\n')
        assert cred.http_authorization_header() == f'Bearer {_SAMPLE_JWT}'

    @pytest.mark.parametrize('bad_token', [12345, None, b'bytes.jwt.token', 1.5, ['a', 'b']])
    def test_jwt_credential_rejects_non_string(self, bad_token: object) -> None:
        with pytest.raises(ValueError):
            JwtCredential(bad_token)  # type: ignore[arg-type]

    @pytest.mark.parametrize('empty', ['', '   ', '\n\t'])
    def test_jwt_credential_rejects_empty(self, empty: str) -> None:
        with pytest.raises(ValueError, match='must not be empty'):
            JwtCredential(empty)

    def test_jwt_credential_repr_redacts_token(self) -> None:
        cred = JwtCredential(_SAMPLE_JWT)
        rendered = repr(cred)
        assert _SAMPLE_JWT not in rendered
        assert '****' in rendered

    def test_certificate_credential_creation(self, cert_paths: Tuple[str, str]) -> None:
        cert_path, key_path = cert_paths
        cred = CertificateCredential(cert_path, key_path)
        # Cert credentials don't expose an auth header — that method simply doesn't exist.
        assert not hasattr(cred, 'http_authorization_header')

    def test_certificate_credential_rejects_nonexistent_path(self, tmp_path: pathlib.Path) -> None:
        cert = tmp_path / 'real.pem'
        cert.write_text(_TEST_CERT_PEM)
        with pytest.raises(FileNotFoundError):
            CertificateCredential(str(cert), str(tmp_path / 'does-not-exist.key'))

    def test_certificate_credential_repr_redacts_key_path(self, cert_paths: Tuple[str, str]) -> None:
        cert_path, key_path = cert_paths
        cred = CertificateCredential(cert_path, key_path)
        rendered = repr(cred)
        assert key_path not in rendered
        assert '****' in rendered

    def test_dynamic_auth_sets_header_from_current_credential(self) -> None:
        cred = JwtCredential(_SAMPLE_JWT)
        client = _ClientAdapter('http://localhost', cred)
        auth = DynamicCredentialAuth(client.connection_details)

        req = Request('POST', 'http://localhost/api/v1/request')
        flow = auth.auth_flow(req)
        dispatched = next(flow)
        assert dispatched.headers['Authorization'] == f'Bearer {_SAMPLE_JWT}'

    def test_dynamic_auth_picks_up_rotated_credential(self) -> None:
        cred = JwtCredential(_SAMPLE_JWT)
        client = _ClientAdapter('http://localhost', cred)
        auth = DynamicCredentialAuth(client.connection_details)

        new_token = 'rotated.jwt.token'
        client.update_credential(JwtCredential(new_token))

        req = Request('POST', 'http://localhost/api/v1/request')
        flow = auth.auth_flow(req)
        dispatched = next(flow)
        assert dispatched.headers['Authorization'] == f'Bearer {new_token}'

    def test_dynamic_auth_omits_header_for_certificate(self, cert_paths: Tuple[str, str]) -> None:
        cert_path, key_path = cert_paths
        cred = CertificateCredential(cert_path, key_path)
        client = _ClientAdapter('https://localhost', cred)
        auth = DynamicCredentialAuth(client.connection_details)

        req = Request('POST', 'https://localhost/api/v1/request')
        dispatched = next(auth.auth_flow(req))
        assert 'Authorization' not in dispatched.headers

    def test_set_credential_same_type_updates_state(self) -> None:
        cred = JwtCredential(_SAMPLE_JWT)
        client = _ClientAdapter('http://localhost', cred)
        assert client.connection_details.credential.http_authorization_header() == f'Bearer {_SAMPLE_JWT}'

        new_token = 'fresh.jwt.token'
        client.update_credential(JwtCredential(new_token))

        assert isinstance(client.connection_details.credential, JwtCredential)
        assert client.connection_details.credential.http_authorization_header() == f'Bearer {new_token}'

    def test_set_credential_password_to_jwt_fails(self) -> None:
        cred = Credential('Administrator', 'password')
        client = _ClientAdapter('http://localhost', cred)
        with pytest.raises(ValueError):
            client.update_credential(JwtCredential(_SAMPLE_JWT))

    def test_set_credential_jwt_to_password_fails(self) -> None:
        cred = JwtCredential(_SAMPLE_JWT)
        client = _ClientAdapter('http://localhost', cred)
        with pytest.raises(ValueError):
            client.update_credential(Credential('Administrator', 'password'))

    def test_set_credential_failure_does_not_change_state(self) -> None:
        cred = Credential('Administrator', 'password')
        client = _ClientAdapter('http://localhost', cred)
        original_header = client.connection_details.credential.http_authorization_header()

        with pytest.raises(ValueError):
            client.update_credential(JwtCredential(_SAMPLE_JWT))

        assert isinstance(client.connection_details.credential, Credential)
        assert client.connection_details.credential.http_authorization_header() == original_header

    def test_certificate_requires_https_endpoint(self, cert_paths: Tuple[str, str]) -> None:
        cert_path, key_path = cert_paths
        cred = CertificateCredential(cert_path, key_path)
        with pytest.raises(ValueError, match='TLS'):
            _ClientAdapter('http://localhost', cred)

    def test_set_credential_certificate_rotation_rebuilds_client(
        self, cert_paths: Tuple[str, str]
    ) -> None:
        cert_path, key_path = cert_paths
        cred = CertificateCredential(cert_path, key_path)
        client = _ClientAdapter('https://localhost', cred)
        client.create_client()
        old_client = client._client
        closed = []
        old_client.close = lambda: closed.append(True)  # type: ignore[method-assign]

        client.update_credential(CertificateCredential(cert_path, key_path))

        assert client._client is not old_client
        assert closed == [True]

    def test_set_credential_certificate_to_password_fails(self, cert_paths: Tuple[str, str]) -> None:
        cert_path, key_path = cert_paths
        cred = CertificateCredential(cert_path, key_path)
        client = _ClientAdapter('https://localhost', cred)
        with pytest.raises(ValueError):
            client.update_credential(Credential('u', 'p'))

    def test_set_credential_password_to_certificate_fails(self, cert_paths: Tuple[str, str]) -> None:
        cert_path, key_path = cert_paths
        cred = Credential('u', 'p')
        client = _ClientAdapter('http://localhost', cred)
        with pytest.raises(ValueError):
            client.update_credential(CertificateCredential(cert_path, key_path))


class CredentialTests(CredentialTestSuite):
    @pytest.fixture(scope='class', autouse=True)
    def validate_test_manifest(self) -> None:
        def valid_test_method(meth: str) -> bool:
            attr = getattr(CredentialTests, meth)
            return callable(attr) and not meth.startswith('__') and meth.startswith('test')

        method_list = [meth for meth in dir(CredentialTests) if valid_test_method(meth)]
        test_list = set(CredentialTestSuite.TEST_MANIFEST).symmetric_difference(method_list)
        if test_list:
            pytest.fail(f'Test manifest invalid.  Missing/extra tests: {test_list}.')
