"""Hermetic tests for ``tap_plugin.sigstore_core.statement`` (req-sigstore-core-statement).

Pure functions over bytes; no sigstore import, no network. The point under test is
that the returned predicate is a byte-for-byte slice of the payload, not a
re-serialisation.
"""

from __future__ import annotations

import hashlib

import pytest
from tap_plugin.sigstore_core.statement import extract_predicate

SHA = "a" * 64
PT = "https://cyclonedx.org/bom"
STATEMENT = "https://in-toto.io/Statement/v0.1"


def _extract(payload: bytes, sha: str = SHA, pt: str = PT):  # noqa: ANN202
    return extract_predicate(payload, expected_subject_sha256=sha, expected_predicate_type=pt)


def _payload(predicate: str = '{"k":1}', *, tail: str = "") -> bytes:
    return (
        f'{{"_type":"{STATEMENT}","subject":[{{"name":"x","digest":{{"sha256":"{SHA}"}}}}],'
        f'"predicateType":"{PT}","predicate":{predicate}{tail}}}'
    ).encode()


class TestExactBytes:
    """Spec: req-sigstore-core-statement-1 (exact predicate bytes, no re-serialisation)."""

    def test_returns_the_predicate_span_verbatim(self) -> None:
        predicate = '{"b":1,   "a":[1 , 2.50, 1e3],"s":"\\u00e9\\/"}'
        found = _extract(_payload(predicate))
        assert found.ok
        assert found.predicate == predicate.encode()
        assert found.predicate_sha256 == hashlib.sha256(predicate.encode()).hexdigest()

    def test_whitespace_and_key_order_around_the_predicate_are_irrelevant(self) -> None:
        predicate = '{\n  "z": 1,\n  "a": 2\n}'
        payload = (
            f'  {{\n "predicate" :  {predicate} ,\n"predicateType":"{PT}","subject":'
            f'[{{"digest":{{"sha256":"{SHA}"}}}}], "_type" : "{STATEMENT}" }}\n'
        ).encode()
        found = _extract(payload)
        assert found.ok
        assert found.predicate == predicate.encode()

    def test_non_ascii_bytes_survive_unchanged(self) -> None:
        predicate = '{"name":"café ☃"}'
        found = _extract(_payload(predicate))
        assert found.predicate == predicate.encode("utf-8")

    def test_non_object_predicates_are_sliced_too(self) -> None:
        for predicate in ('"text"', "[1, 2]", "null", "  12.0"):
            found = _extract(_payload(predicate.strip()))
            assert found.ok
            assert found.predicate == predicate.strip().encode()

    def test_keys_inside_the_predicate_do_not_confuse_the_walk(self) -> None:
        predicate = f'{{"predicate":"inner","predicateType":"other","subject":[],"_type":"{STATEMENT}"}}'
        found = _extract(_payload(predicate))
        assert found.ok
        assert found.predicate == predicate.encode()

    def test_v1_statement_type_accepted(self) -> None:
        payload = _payload().replace(STATEMENT.encode(), b"https://in-toto.io/Statement/v1")
        assert _extract(payload).ok


class TestSubjectAndPredicateType:
    """Spec: req-sigstore-core-statement-2 (subject digest), -3 (predicateType)."""

    def test_any_matching_subject_suffices(self) -> None:
        payload = (
            f'{{"_type":"{STATEMENT}","subject":[{{"digest":{{"sha256":"{"b" * 64}"}}}},'
            f'{{"digest":{{"sha256":"{SHA}"}}}}],"predicateType":"{PT}","predicate":{{}}}}'
        ).encode()
        found = _extract(payload)
        assert found.ok
        assert found.subject_sha256 == ("b" * 64, SHA)

    def test_digest_comparison_ignores_case_and_sha256_prefix(self) -> None:
        assert _extract(_payload(), sha=SHA.upper()).ok
        assert _extract(_payload(), sha=f"sha256:{SHA}").ok

    def test_wrong_subject_digest(self) -> None:
        found = _extract(_payload(), sha="c" * 64)
        assert not found.ok
        assert found.failure_code == "subject_mismatch"
        assert found.predicate == b""
        assert SHA in found.failure_detail

    def test_wrong_predicate_type(self) -> None:
        found = _extract(_payload(), pt="https://slsa.dev/provenance/v1")
        assert not found.ok
        assert found.failure_code == "predicate_type_mismatch"
        assert found.predicate_type == PT
        assert found.predicate == b""

    def test_subject_without_sha256_does_not_match(self) -> None:
        payload = _payload().replace(b'"sha256"', b'"sha512"')
        assert _extract(payload).failure_code == "subject_mismatch"


class TestMalformed:
    """Spec: req-sigstore-core-statement-4 (never raises; failure codes)."""

    @pytest.mark.parametrize(
        "payload",
        [b"", b"not json", b"[]", b'"x"', b"{", b'{"a":1,}', b'{"a":1} trailing', b"\xff\xfe{}", b'{"a" 1}'],
    )
    def test_not_a_json_object_is_statement_parse(self, payload: bytes) -> None:
        found = _extract(payload)
        assert not found.ok
        assert found.failure_code == "statement_parse"

    def test_duplicate_top_level_key_is_refused(self) -> None:
        payload = _payload(tail=',"predicate":{"other":true}')
        found = _extract(payload)
        assert found.failure_code == "statement_parse"
        assert "duplicate" in found.failure_detail

    def test_wrong_statement_type(self) -> None:
        payload = _payload().replace(STATEMENT.encode(), b"https://example.com/NotStatement")
        assert _extract(payload).failure_code == "statement_type"

    def test_missing_type_is_statement_type(self) -> None:
        payload = b'{"subject":[],"predicateType":"x","predicate":{}}'
        assert _extract(payload).failure_code == "statement_type"

    def test_missing_subject_or_predicate_type_is_statement_parse(self) -> None:
        no_subject = f'{{"_type":"{STATEMENT}","predicateType":"{PT}","predicate":{{}}}}'.encode()
        assert _extract(no_subject).failure_code == "statement_parse"
        no_pt = f'{{"_type":"{STATEMENT}","subject":[],"predicate":{{}}}}'.encode()
        assert _extract(no_pt).failure_code == "statement_parse"

    def test_missing_predicate(self) -> None:
        payload = (
            f'{{"_type":"{STATEMENT}","subject":[{{"digest":{{"sha256":"{SHA}"}}}}],"predicateType":"{PT}"}}'
        ).encode()
        found = _extract(payload)
        assert found.failure_code == "predicate_missing"
        assert found.predicate == b""


class TestPurity:
    """Spec: req-sigstore-core-statement-5 (no sigstore import, no I/O)."""

    def test_module_imports_nothing_from_sigstore_or_network_libs(self) -> None:
        import ast
        from pathlib import Path

        import tap_plugin.sigstore_core.statement as mod

        tree = ast.parse(Path(mod.__file__).read_text())
        imported = {
            (node.module if isinstance(node, ast.ImportFrom) else alias.name).split(".")[0]
            for node in ast.walk(tree)
            if isinstance(node, ast.Import | ast.ImportFrom)
            for alias in (node.names if isinstance(node, ast.Import) else [node])
            if (isinstance(node, ast.Import) or node.module)
        }
        assert imported <= {"__future__", "hashlib", "json", "dataclasses"}
