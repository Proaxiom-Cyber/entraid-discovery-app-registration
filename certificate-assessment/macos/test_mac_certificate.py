"""Native Keychain and offline cryptographic checks; no tenant connections."""

import base64
import json
import subprocess
import sys
import uuid
from datetime import timedelta

import mac_certificate as mc
import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding


def decode(part):
    return base64.urlsafe_b64decode(part + "=" * (-len(part) % 4))


@pytest.fixture(scope="module")
def native(tmp_path_factory):
    if sys.platform != "darwin":
        pytest.skip("Native login-Keychain test requires macOS")
    tag = "com.proaxiom.assessment.test.pytest-" + uuid.uuid4().hex
    output = tmp_path_factory.mktemp("public-certificate")
    helper = mc.build_helper()
    try:
        metadata = mc.prepare(output, tag)
        signer = mc.CertificateSigner(output / mc.PUBLIC_FILE, tag)
        yield output, tag, metadata, signer
    finally:
        mc._native(helper, "delete-test", tag)
        result = subprocess.run(
            [str(helper), "check", tag], capture_output=True, check=False
        )
        if result.returncode == 0:
            pytest.fail("The native test key was not removed")


def test_native_certificate_and_non_extractability(native):
    output, tag, metadata, signer = native
    facts = json.loads(mc._native(signer.helper_path, "check", tag))
    assert facts["extractable"] is False
    assert facts["bits"] == 2048
    assert facts["hardware_backed"] is False
    cert = x509.load_der_x509_certificate((output / mc.PUBLIC_FILE).read_bytes())
    signer.public_key().verify(
        cert.signature, cert.tbs_certificate_bytes, padding.PKCS1v15(), hashes.SHA256()
    )
    assert cert.not_valid_after_utc - cert.not_valid_before_utc == timedelta(days=60)
    assert metadata["private_key_extractable"] is False
    assert "helper_path" not in metadata
    assert str(signer.helper_path.parent) not in json.dumps(metadata)
    assert sorted(p.name for p in output.iterdir()) == [
        mc.METADATA_FILE,
        mc.PUBLIC_FILE,
    ]
    assert cert.public_key().public_numbers() == signer.public_key().public_numbers()


def test_native_rs256_and_ps256(native):
    signer = native[3]
    message = b"Offline Entra assessment signing verification; no tenant request."
    for algorithm, scheme in [
        ("rs256", padding.PKCS1v15()),
        ("ps256", padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=32)),
    ]:
        signature = signer.sign(message, algorithm)
        signer.public_key().verify(signature, message, scheme, hashes.SHA256())
    with pytest.raises(mc.CertificateError):
        signer.sign(message, "es256")


def test_assertion_is_correct_and_verifies(native):
    signer = native[3]
    tenant, client = str(uuid.uuid4()), str(uuid.uuid4())
    provider = mc.CertificateTokenProvider(tenant, client, signer)
    assertion = provider.client_assertion()
    parts = assertion.split(".")
    header, claims = json.loads(decode(parts[0])), json.loads(decode(parts[1]))
    assert header["alg"] == "PS256"
    assert header["x5t#S256"] == mc._b64url(
        signer.certificate.fingerprint(hashes.SHA256())
    )
    assert (
        claims["aud"] == f"https://login.microsoftonline.com/{tenant}/oauth2/v2.0/token"
    )
    assert claims["iss"] == claims["sub"] == client
    assert claims["exp"] - claims["nbf"] == 300
    assert claims["iat"] == claims["nbf"]
    uuid.UUID(claims["jti"])
    signer.public_key().verify(
        decode(parts[2]),
        ".".join(parts[:2]).encode("ascii"),
        padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=32),
        hashes.SHA256(),
    )


class Response:
    def __init__(self, status=200):
        self.status_code, self.closed = status, False

    def json(self):
        return {
            "access_token": "unit-test-placeholder",
            "expires_in": 3600,
            "token_type": "Bearer",
        }

    def close(self):
        self.closed = True


class Session:
    def __init__(self, status=200):
        self.calls, self.status = [], status

    def post(self, url, **kwargs):
        # Assert the transport contract without retaining the signed assertion.
        assert url.startswith("https://login.microsoftonline.com/")
        assert kwargs["allow_redirects"] is False
        assert kwargs["timeout"] == 30
        assert kwargs["data"]["scope"] == "https://graph.microsoft.com/.default"
        assert kwargs["data"]["grant_type"] == "client_credentials"
        assert "client_secret" not in kwargs["data"]
        self.calls.append(url)
        return Response(self.status)


def test_token_transport_and_refresh_are_in_memory(native):
    session = Session()
    provider = mc.CertificateTokenProvider(
        str(uuid.uuid4()), str(uuid.uuid4()), native[3], session
    )
    assert provider.access_token() == "unit-test-placeholder"
    assert provider.access_token() == "unit-test-placeholder"
    assert len(session.calls) == 1
    provider._expires = 0
    assert provider.access_token() == "unit-test-placeholder"
    assert len(session.calls) == 2
    assert session.trust_env is False


def test_redirect_and_bad_ids_are_rejected(native):
    session = Session(status=302)
    provider = mc.CertificateTokenProvider(
        str(uuid.uuid4()), str(uuid.uuid4()), native[3], session
    )
    with pytest.raises(mc.CertificateError, match="HTTP 302"):
        provider.access_token()
    with pytest.raises(mc.CertificateError, match="UUID"):
        mc.CertificateTokenProvider(
            "https://untrusted.example", str(uuid.uuid4()), native[3], session
        )


def test_existing_files_and_real_key_delete_are_refused(native, tmp_path):
    output, tag, _, signer = native
    with pytest.raises(mc.CertificateError, match="already exist"):
        mc.prepare(output, tag)
    result = subprocess.run(
        [
            str(signer.helper_path),
            "delete-test",
            "com.proaxiom.assessment.production-refusal",
        ],
        capture_output=True,
        check=False,
    )
    assert result.returncode != 0
    with pytest.raises(mc.CertificateError):
        mc.prepare(tmp_path / "long", "com.proaxiom.assessment.test.invalid", days=91)
    assert not (tmp_path / "long").exists()


def test_no_token_cli():
    with pytest.raises(SystemExit) as outcome:
        mc.main(["token"])
    assert outcome.value.code != 0


def test_invalid_inputs_fail_without_creating_output(tmp_path):
    for tag in (
        "invalid",
        "com.proaxiom.bad/name",
        "com.proaxiom.bad tag",
        "com.proaxiom.bad\n",
    ):
        with pytest.raises(mc.CertificateError, match="tag"):
            mc.prepare(tmp_path / "invalid", tag)
    for days in (0, 91, True):
        with pytest.raises(mc.CertificateError, match="duration"):
            mc.prepare(
                tmp_path / "invalid", "com.proaxiom.assessment.test.invalid", days=days
            )
    assert not (tmp_path / "invalid").exists()


def test_generic_tag_and_uuid_validation():
    assert mc._tag("com.proaxiom.assessment.any-customer.run-1")
    assert mc._tag("com.proaxiom.other-project.key-1")
    expected = str(uuid.uuid4())
    assert mc._uuid(expected.upper()) == expected
    with pytest.raises(mc.CertificateError):
        mc._uuid("common")


def test_existing_helper_without_metadata_is_refused(tmp_path, monkeypatch):
    helper = tmp_path / "keychain-signer"
    helper.write_bytes(b"not executed")
    helper.chmod(0o700)
    monkeypatch.setattr(mc.sys, "platform", "darwin")
    with pytest.raises(mc.CertificateError, match="metadata"):
        mc.build_helper(helper)
    assert helper.read_bytes() == b"not executed"


def test_changed_helper_source_is_not_silently_rebuilt(native, monkeypatch):
    signer = native[3]
    before = signer.helper_path.read_bytes()
    monkeypatch.setattr(mc, "_source_digest", lambda: "0" * 64)
    with pytest.raises(mc.CertificateError, match="source"):
        mc.build_helper(signer.helper_path)
    assert signer.helper_path.read_bytes() == before
