"""Read an in-toto Statement out of a verified DSSE payload.

``verify.verify_dsse_bundle`` returns the signed payload bytes; this module takes
those bytes and answers two questions a consumer must settle before trusting the
attestation's content: is it about the subject I expect (``subject[].digest.sha256``)
and is it the predicate kind I expect (``predicateType``)? On success it returns
the EXACT bytes of the ``predicate`` value as they sit inside the signed payload.

Why exact bytes: a consumer that binds content by digest (sha256 over the
predicate) must hash what the signer signed. Parsing the predicate and
re-serialising it changes whitespace, key order and number/escape spelling, so
the digest would not match what any other verifier computes. The scanner below
walks only the Statement's top-level keys and slices the predicate's span out of
the payload; it never re-serialises anything.

Pure functions, no network, no graph access, no ``sigstore.*`` import.

Spec: plugins/sigstore_core/specs/spec-sigstore-core-v0.md (req-sigstore-core-statement).
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass

# Statement ``_type`` values for the two published in-toto Statement versions.
IN_TOTO_STATEMENT_TYPES = (
    "https://in-toto.io/Statement/v0.1",
    "https://in-toto.io/Statement/v1",
)

_DECODER = json.JSONDecoder()
_WS = " \t\n\r"


@dataclass(frozen=True)
class StatementPredicate:
    """Outcome of ``extract_predicate``.

    ``ok`` is ``True`` only when the payload parsed as an in-toto Statement, a
    subject carried the expected sha256, and ``predicateType`` matched. Then
    ``predicate`` holds the exact predicate bytes and ``predicate_sha256`` their
    lowercase hex digest. Otherwise ``failure_code`` is one of
    ``statement_parse``, ``statement_type``, ``subject_mismatch``,
    ``predicate_type_mismatch``, ``predicate_missing``; ``predicate`` is empty.
    ``predicate_type`` and ``subject_sha256`` report what the statement claimed,
    for diagnostics, whenever they could be read.
    """

    ok: bool
    predicate: bytes = b""
    predicate_sha256: str = ""
    predicate_type: str = ""
    subject_sha256: tuple[str, ...] = ()
    failure_code: str = ""
    failure_detail: str = ""


def _skip_ws(text: str, idx: int) -> int:
    while idx < len(text) and text[idx] in _WS:
        idx += 1
    return idx


def _top_level_spans(text: str) -> dict[str, tuple[int, int]]:
    """Map each top-level key of a JSON object to its value's (start, end) span.

    ``text`` must be exactly one JSON object (surrounding whitespace allowed).
    Raises ``ValueError`` on anything else, including duplicate top-level keys
    (ambiguous which one a verifier meant, so refused).
    """
    idx = _skip_ws(text, 0)
    if idx >= len(text) or text[idx] != "{":
        raise ValueError("payload is not a JSON object")
    idx = _skip_ws(text, idx + 1)
    spans: dict[str, tuple[int, int]] = {}
    if idx < len(text) and text[idx] == "}":
        idx += 1
    else:
        while True:
            key, idx = _DECODER.raw_decode(text, idx)  # raises JSONDecodeError (a ValueError)
            if not isinstance(key, str):
                raise ValueError("object key is not a string")
            idx = _skip_ws(text, idx)
            if idx >= len(text) or text[idx] != ":":
                raise ValueError("expected ':' after object key")
            start = _skip_ws(text, idx + 1)
            _, end = _DECODER.raw_decode(text, start)
            if key in spans:
                raise ValueError(f"duplicate top-level key {key!r}")
            spans[key] = (start, end)
            idx = _skip_ws(text, end)
            if idx < len(text) and text[idx] == ",":
                idx = _skip_ws(text, idx + 1)
                continue
            if idx < len(text) and text[idx] == "}":
                idx += 1
                break
            raise ValueError("expected ',' or '}' in object")
    if _skip_ws(text, idx) != len(text):
        raise ValueError("trailing data after JSON object")
    return spans


def extract_predicate(
    payload: bytes,
    *,
    expected_subject_sha256: str,
    expected_predicate_type: str,
) -> StatementPredicate:
    """Check a verified in-toto payload and return the exact predicate bytes.

    Spec: req-sigstore-core-statement-1 .. -5.

    The payload MUST already be the output of a successful
    ``verify_dsse_bundle``; this function does no signature work. It never raises.

    Args:
        payload: The verified DSSE payload bytes (an in-toto Statement, JSON).
        expected_subject_sha256: Hex sha256 the statement must name in
            ``subject[].digest.sha256`` (any one subject suffices; compared
            case-insensitively, with an optional ``sha256:`` prefix tolerated).
        expected_predicate_type: The ``predicateType`` URI the statement must carry.
    """

    def fail(code: str, detail: str, **seen: object) -> StatementPredicate:
        return StatementPredicate(ok=False, failure_code=code, failure_detail=detail, **seen)  # type: ignore[arg-type]

    try:
        text = payload.decode("utf-8")
    except UnicodeDecodeError as exc:
        return fail("statement_parse", f"payload is not UTF-8: {exc}")

    try:
        spans = _top_level_spans(text)
    except ValueError as exc:
        return fail("statement_parse", str(exc))

    def value(key: str) -> object:
        start, end = spans[key]
        return json.loads(text[start:end])

    statement_type = value("_type") if "_type" in spans else None
    if statement_type not in IN_TOTO_STATEMENT_TYPES:
        return fail("statement_type", f"_type {statement_type!r} is not an in-toto Statement")

    predicate_type = value("predicateType") if "predicateType" in spans else None
    if not isinstance(predicate_type, str):
        return fail("statement_parse", "predicateType missing or not a string")

    subjects = value("subject") if "subject" in spans else None
    if not isinstance(subjects, list):
        return fail("statement_parse", "subject missing or not a list", predicate_type=predicate_type)
    digests: list[str] = []
    for subject in subjects:
        digest = subject.get("digest") if isinstance(subject, dict) else None
        sha = digest.get("sha256") if isinstance(digest, dict) else None
        if isinstance(sha, str):
            digests.append(sha.lower())
    seen = {"predicate_type": predicate_type, "subject_sha256": tuple(digests)}

    expected = expected_subject_sha256.lower().removeprefix("sha256:")
    if expected not in digests:
        return fail(
            "subject_mismatch",
            f"no subject carries sha256 {expected}; statement names {', '.join(digests) or 'none'}",
            **seen,
        )
    if predicate_type != expected_predicate_type:
        return fail(
            "predicate_type_mismatch",
            f"predicateType {predicate_type!r} is not the expected {expected_predicate_type!r}",
            **seen,
        )
    if "predicate" not in spans:
        return fail("predicate_missing", "statement has no predicate", **seen)

    start, end = spans["predicate"]
    raw = text[start:end].encode("utf-8")
    return StatementPredicate(
        ok=True,
        predicate=raw,
        predicate_sha256=hashlib.sha256(raw).hexdigest(),
        predicate_type=predicate_type,
        subject_sha256=tuple(digests),
    )
