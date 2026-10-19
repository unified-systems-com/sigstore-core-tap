"""Tests for ``verify_dsse_bundle`` (req-sigstore-core-dsse) against REAL bundles.

Fixtures (``tests/fixtures/``) are two real Sigstore v0.3 DSSE bundles, the in-toto
CycloneDX SBOM attestations GitHub Actions published for the public
``unified-systems-com/tap`` repository (SOURCE: ``gh attestation verify ... --format
json``, ``attestation.bundle``, 2026-10-16), plus the Sigstore public-good
``trusted_root.json`` (SOURCE: ``sigstore.models.ClientTrustConfig.production()``
serialised 2026-10-19). With the trust root vendored, the unit tests run the REAL
sigstore-python verifier offline: no TUF fetch, no network. Verification time is
the Rekor ``integrated_time`` carried in the bundle, so the fixtures do not age out
of the Fulcio certificate's ten-minute window.

The one test that fetches the trust root live is gated behind
``SIGSTORE_CORE_LIVE=1`` and skipped by default.
"""

from __future__ import annotations

import base64
import gzip
import json
import os
from pathlib import Path
from typing import Any

import pytest
from sigstore.models import Bundle, TrustedRoot
from sigstore.verify import Verifier
from tap_plugin.sigstore_core import verify as verify_mod
from tap_plugin.sigstore_core.statement import extract_predicate
from tap_plugin.sigstore_core.verify import (
    IN_TOTO_PAYLOAD_TYPE,
    DsseVerificationResult,
    GitHubWorkflowPolicy,
    verify_dsse_bundle,
)

FIXTURES = Path(__file__).parent / "fixtures"
ISSUER = "https://token.actions.githubusercontent.com"
REPO = "unified-systems-com/tap"
CYCLONEDX = "https://cyclonedx.org/bom"

# Fixture A: sbom-vulnerability-evidence.yml (reusable workflow, SAN pinned by commit).
A_FILE = "dsse_sbom_vuln_evidence.bundle.json.gz"
A_SAN = f"https://github.com/{REPO}/.github/workflows/sbom-vulnerability-evidence.yml@5736329dff506c952b5567260dd82c51adab5d74"
A_REF = "refs/heads/main"
A_SHA = "8c0488ad12947a343b7ffabe06332726e98c96b5"
# Build Signer Digest of fixture A: the commit of the reusable workflow file, the SAN's @<sha>. It is NOT A_SHA.
A_SIGNER_DIGEST = "5736329dff506c952b5567260dd82c51adab5d74"
A_SUBJECT = "a9149a88a6239fc7a5351d9854fbff42448d2ed28cc71951a4c2aa2f4aca7750"
# Fixture B: publish-images.yml (a different signer workflow, SAN pinned by ref).
B_FILE = "dsse_sbom_publish_images.bundle.json.gz"
B_SAN = f"https://github.com/{REPO}/.github/workflows/publish-images.yml@refs/heads/main"
B_SHA = "42a563b8b21cf6866f21549ece70faf1dd6dab9e"
B_SUBJECT = "48e30963aa6e9786bba6cbea65c391f830f435fe15360fd87f0bd80f47eb56a4"


def _load(name: str) -> dict[str, Any]:
    return json.loads(gzip.decompress((FIXTURES / name).read_bytes()))


def _dump(bundle: dict[str, Any]) -> bytes:
    return json.dumps(bundle).encode()


def _policy_a(**overrides: Any) -> GitHubWorkflowPolicy:
    fields: dict[str, Any] = {
        "oidc_issuer": ISSUER,
        "github_repository": REPO,
        "workflow_identity_uri": A_SAN,
        "workflow_ref": A_REF,
        "workflow_sha": A_SHA,
        "build_signer_digest": A_SIGNER_DIGEST,
    }
    fields.update(overrides)
    return GitHubWorkflowPolicy(**fields)


def _policy_b(**overrides: Any) -> GitHubWorkflowPolicy:
    fields: dict[str, Any] = {
        "oidc_issuer": ISSUER,
        "github_repository": REPO,
        "workflow_identity_uri": B_SAN,
        "workflow_ref": "refs/heads/main",
        "workflow_sha": B_SHA,
    }
    fields.update(overrides)
    return GitHubWorkflowPolicy(**fields)


@pytest.fixture
def real_offline_verifier(monkeypatch: pytest.MonkeyPatch) -> Verifier:
    """The real sigstore-python Verifier built from the vendored trust root (no network)."""
    verifier = Verifier(trusted_root=TrustedRoot.from_file(str(FIXTURES / "public_good_trusted_root.json")))
    monkeypatch.setattr(verify_mod, "_get_verifier", lambda: verifier)
    return verifier


class _FakeVerifier:
    """Stands in for the cached Verifier where a test needs to control verify_dsse's outcome."""

    def __init__(self, *, returns: tuple[str, bytes] | None = None, raises: Exception | None = None) -> None:
        self.returns = returns
        self.raises = raises
        self.calls = 0

    def verify_dsse(self, bundle: Bundle, policy: Any) -> tuple[str, bytes]:
        self.calls += 1
        if self.raises is not None:
            raise self.raises
        assert self.returns is not None
        return self.returns


class TestHappyPath:
    """Spec: req-sigstore-core-dsse-1 (canonical function), -2 (result shape),
    req-sigstore-core-dsse-8 (log metadata from a real bundle)."""

    def test_reusable_workflow_bundle_verifies(self, real_offline_verifier: Verifier) -> None:
        result = verify_dsse_bundle(_dump(_load(A_FILE)), policy=_policy_a())
        assert isinstance(result, DsseVerificationResult)
        assert result.signature_verified is True, result.failure_detail
        assert result.failure_code == ""
        assert result.payload_type == IN_TOTO_PAYLOAD_TYPE
        assert result.signed_by == A_SAN
        assert result.signing_issuer == ISSUER
        assert result.build_signer_digest == A_SIGNER_DIGEST
        assert result.parsed_bundle is not None
        assert result.verified_at.endswith("Z")

    def test_other_signer_workflow_bundle_verifies(self, real_offline_verifier: Verifier) -> None:
        result = verify_dsse_bundle(_dump(_load(B_FILE)), policy=_policy_b())
        assert result.signature_verified is True, result.failure_detail
        assert result.signed_by == B_SAN

    def test_required_fields_only_policy_verifies(self, real_offline_verifier: Verifier) -> None:
        policy = GitHubWorkflowPolicy(oidc_issuer=ISSUER, github_repository=REPO)
        assert verify_dsse_bundle(_dump(_load(A_FILE)), policy=policy).signature_verified is True

    def test_payload_is_the_signed_statement(self, real_offline_verifier: Verifier) -> None:
        result = verify_dsse_bundle(_dump(_load(A_FILE)), policy=_policy_a())
        envelope_payload = base64.b64decode(_load(A_FILE)["dsseEnvelope"]["payload"])
        assert result.payload == envelope_payload
        statement = json.loads(result.payload)
        assert statement["predicateType"] == CYCLONEDX
        assert statement["subject"][0]["digest"]["sha256"] == A_SUBJECT

    def test_log_metadata_populated(self, real_offline_verifier: Verifier) -> None:
        """Mock-based tests cannot catch upstream shape drift in the log entry; a real bundle does."""
        result = verify_dsse_bundle(_dump(_load(A_FILE)), policy=_policy_a())
        assert result.rekor_log_index.isdigit()
        assert len(result.log_key_id) == 64  # hex sha256 of the Rekor key
        assert result.integrated_time.endswith("Z")
        assert result.entry_kind in {"dsse", "hashedrekord"}
        assert result.rekor_log_url == "https://rekor.sigstore.dev"


class TestPolicyMismatch:
    """Spec: req-sigstore-core-dsse-6 (policy parity with verify_bundle),
    req-sigstore-core-dsse-3 (never raises)."""

    @pytest.mark.parametrize(
        "overrides",
        [
            {"github_repository": "someone-else/tap"},
            {"workflow_ref": "refs/heads/not-main"},
            {"workflow_sha": "0" * 40},
            {"build_signer_digest": "0" * 40},
            # A_SHA is the triggering commit, not the signing workflow's: must not pass as the signer digest.
            {"build_signer_digest": A_SHA},
            {"oidc_issuer": "https://accounts.google.com"},
            {"workflow_identity_uri": B_SAN},
        ],
        ids=[
            "repository",
            "workflow_ref",
            "workflow_sha",
            "signer_digest",
            "signer_digest_is_not_workflow_sha",
            "issuer",
            "identity_uri",
        ],
    )
    def test_wrong_policy_field_fails_closed(self, real_offline_verifier: Verifier, overrides: dict[str, Any]) -> None:
        result = verify_dsse_bundle(_dump(_load(A_FILE)), policy=_policy_a(**overrides))
        assert result.signature_verified is False
        assert result.failure_code == "policy_mismatch"
        assert result.failure_detail != ""
        # The payload is never handed over on a failed verdict ...
        assert result.payload == b""
        assert result.payload_type == ""
        # ... but the failed identity stays visible.
        assert result.signed_by == A_SAN

    def test_policy_mismatch_does_not_reach_the_verifier(self, monkeypatch: pytest.MonkeyPatch) -> None:
        fake = _FakeVerifier(returns=(IN_TOTO_PAYLOAD_TYPE, b"{}"))
        monkeypatch.setattr(verify_mod, "_get_verifier", lambda: fake)
        result = verify_dsse_bundle(_dump(_load(A_FILE)), policy=_policy_a(github_repository="x/y"))
        assert result.failure_code == "policy_mismatch"
        assert fake.calls == 0


class TestTamper:
    """Spec: req-sigstore-core-dsse-3, -4: tampering is a verdict, not an exception."""

    def test_tampered_payload_fails(self, real_offline_verifier: Verifier) -> None:
        bundle = _load(A_FILE)
        payload = bytearray(base64.b64decode(bundle["dsseEnvelope"]["payload"]))
        payload[-3] ^= 0x01  # still base64-able bytes; the DSSE signature no longer matches
        bundle["dsseEnvelope"]["payload"] = base64.b64encode(bytes(payload)).decode()
        result = verify_dsse_bundle(_dump(bundle), policy=_policy_a())
        assert result.signature_verified is False
        assert result.failure_code == "signature"
        assert result.payload == b""

    def test_tampered_payload_type_fails(self, real_offline_verifier: Verifier) -> None:
        """payloadType is inside the signed PAE, so rewriting it breaks the signature."""
        bundle = _load(A_FILE)
        bundle["dsseEnvelope"]["payloadType"] = "text/plain"
        result = verify_dsse_bundle(_dump(bundle), policy=_policy_a(), expected_payload_type=None)
        assert result.signature_verified is False
        assert result.failure_code == "signature"

    def test_signature_of_a_different_attestation_fails(self, real_offline_verifier: Verifier) -> None:
        bundle = _load(A_FILE)
        bundle["dsseEnvelope"]["signatures"] = _load(B_FILE)["dsseEnvelope"]["signatures"]
        result = verify_dsse_bundle(_dump(bundle), policy=_policy_a())
        assert result.signature_verified is False
        assert result.failure_code == "signature"


class TestPayloadType:
    """Spec: req-sigstore-core-dsse-7 (payloadType checked, default in-toto)."""

    def test_unexpected_payload_type_is_a_failure_after_crypto(self, real_offline_verifier: Verifier) -> None:
        result = verify_dsse_bundle(
            _dump(_load(A_FILE)),
            policy=_policy_a(),
            expected_payload_type="application/vnd.example+json",
        )
        assert result.signature_verified is False
        assert result.failure_code == "payload_type_mismatch"
        assert IN_TOTO_PAYLOAD_TYPE in result.failure_detail
        assert result.payload == b""

    def test_none_disables_the_check(self, real_offline_verifier: Verifier) -> None:
        result = verify_dsse_bundle(_dump(_load(A_FILE)), policy=_policy_a(), expected_payload_type=None)
        assert result.signature_verified is True
        assert result.payload_type == IN_TOTO_PAYLOAD_TYPE

    def test_default_rejects_a_non_in_toto_envelope(self, monkeypatch: pytest.MonkeyPatch) -> None:
        fake = _FakeVerifier(returns=("text/plain", b"hello"))
        monkeypatch.setattr(verify_mod, "_get_verifier", lambda: fake)
        result = verify_dsse_bundle(_dump(_load(A_FILE)), policy=_policy_a())
        assert fake.calls == 1
        assert result.signature_verified is False
        assert result.failure_code == "payload_type_mismatch"


class TestFences:
    """Spec: req-sigstore-core-dsse-5 (Rekor-backed only), req-sigstore-core-dsse-2
    (three-state result), -3, -4."""

    def test_no_rekor_proof_fails_before_the_verifier(self, monkeypatch: pytest.MonkeyPatch) -> None:
        fake = _FakeVerifier(returns=(IN_TOTO_PAYLOAD_TYPE, b"{}"))
        monkeypatch.setattr(verify_mod, "_get_verifier", lambda: fake)
        monkeypatch.setattr(verify_mod, "_has_rekor_proof", lambda bundle: False)
        result = verify_dsse_bundle(_dump(_load(A_FILE)), policy=_policy_a())
        assert result.signature_verified is False
        assert result.failure_code == "no_rekor_proof"
        assert fake.calls == 0

    def test_bundle_without_tlog_entries_never_verifies(self, real_offline_verifier: Verifier) -> None:
        bundle = _load(A_FILE)
        bundle["verificationMaterial"]["tlogEntries"] = []
        result = verify_dsse_bundle(_dump(bundle), policy=_policy_a())
        assert result.signature_verified is not True
        assert result.failure_code in {"bundle_parse", "no_rekor_proof"}
        assert result.payload == b""

    def test_message_signature_bundle_is_not_a_dsse_bundle(self, monkeypatch: pytest.MonkeyPatch) -> None:
        fake = _FakeVerifier(returns=(IN_TOTO_PAYLOAD_TYPE, b"{}"))
        monkeypatch.setattr(verify_mod, "_get_verifier", lambda: fake)
        # A parsed bundle that has no DSSE envelope (a plain message-signature bundle).
        monkeypatch.setattr(Bundle, "_dsse_envelope", property(lambda self: None))
        result = verify_dsse_bundle(_dump(_load(A_FILE)), policy=_policy_a())
        assert result.signature_verified is False
        assert result.failure_code == "no_dsse_envelope"
        assert fake.calls == 0

    def test_garbage_bytes_are_bundle_parse(self) -> None:
        result = verify_dsse_bundle(b"not a bundle", policy=_policy_a())
        assert result.signature_verified is None
        assert result.failure_code == "bundle_parse"
        assert result.parsed_bundle is None
        assert result.payload == b""
        assert result.verified_at.endswith("Z")

    def test_empty_and_wrong_shape_json_are_bundle_parse(self) -> None:
        assert verify_dsse_bundle(b"", policy=_policy_a()).failure_code == "bundle_parse"
        assert verify_dsse_bundle(b'{"a": 1}', policy=_policy_a()).signature_verified is None

    def test_unexpected_verifier_exception_is_a_verdict(self, monkeypatch: pytest.MonkeyPatch) -> None:
        fake = _FakeVerifier(raises=RuntimeError("boom"))
        monkeypatch.setattr(verify_mod, "_get_verifier", lambda: fake)
        result = verify_dsse_bundle(_dump(_load(A_FILE)), policy=_policy_a())
        assert result.signature_verified is False
        assert result.failure_code == "unexpected"
        assert result.failure_detail == "boom"


class TestVerifiedPayloadFeedsStatementCheck:
    """Spec: req-sigstore-core-statement-1 (exact predicate bytes) on a real payload."""

    def test_real_predicate_bytes_are_a_slice_of_the_signed_payload(self, real_offline_verifier: Verifier) -> None:
        result = verify_dsse_bundle(_dump(_load(A_FILE)), policy=_policy_a())
        assert result.signature_verified is True
        found = extract_predicate(result.payload, expected_subject_sha256=A_SUBJECT, expected_predicate_type=CYCLONEDX)
        assert found.ok, found.failure_detail
        # The predicate is the last key in the payload: its bytes end right before the closing brace.
        assert result.payload.endswith(found.predicate + b"}")
        assert result.payload.count(found.predicate) == 1
        assert json.loads(found.predicate) == json.loads(result.payload)["predicate"]
        assert found.predicate_sha256 and len(found.predicate_sha256) == 64

    def test_other_bundle_subject_does_not_match(self, real_offline_verifier: Verifier) -> None:
        result = verify_dsse_bundle(_dump(_load(A_FILE)), policy=_policy_a())
        found = extract_predicate(result.payload, expected_subject_sha256=B_SUBJECT, expected_predicate_type=CYCLONEDX)
        assert not found.ok
        assert found.failure_code == "subject_mismatch"


@pytest.mark.skipif(
    os.environ.get("SIGSTORE_CORE_LIVE") != "1",
    reason="live integration test: fetches the Sigstore public-good TUF trust root (network); set SIGSTORE_CORE_LIVE=1",
)
class TestLiveIntegration:
    """Network. Run by hand: SIGSTORE_CORE_LIVE=1 pytest -k Live. Uses the production Verifier
    (TUF refresh) through the module's own cache, exactly as a consumer would."""

    def test_real_bundles_verify_against_live_trust_root(self) -> None:
        verify_mod._get_verifier.cache_clear()
        for name, policy, subject in ((A_FILE, _policy_a(), A_SUBJECT), (B_FILE, _policy_b(), B_SUBJECT)):
            result = verify_dsse_bundle(_dump(_load(name)), policy=policy)
            assert result.signature_verified is True, result.failure_detail
            found = extract_predicate(
                result.payload, expected_subject_sha256=subject, expected_predicate_type=CYCLONEDX
            )
            assert found.ok, found.failure_detail
        bad = verify_dsse_bundle(_dump(_load(A_FILE)), policy=_policy_a(github_repository="x/y"))
        assert bad.failure_code == "policy_mismatch"
