"""Stage 1 -- canonicalization.

Deliberately conservative. Security text carries meaning in case and
punctuation: `CVE-2021-44228`, `../../`, `${jndi:ldap://}`, `O_CREAT|O_EXCL`.
Lowercasing, stripping punctuation, or removing stopwords would destroy exactly
the signal this corpus exists for, so none of that happens here.

What does happen: Unicode NFC, line-ending normalization, control-character
removal, and whitespace collapsing. Each transformation is counted separately so
the report can say which ones actually touched the corpus -- "canonicalization
altered 60% of CVE descriptions" is a finding about the data, while "records were
canonicalized" is not.
"""

from __future__ import annotations

import re
import unicodedata

# C0/C1 controls except tab and newline, plus zero-width and BOM characters that
# survive copy-paste into vulnerability descriptions.
_CONTROL = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f-\x9f]")
_ZERO_WIDTH = re.compile(r"[​-‏  ﻿­]")
_CRLF = re.compile(r"\r\n?")
_TRAILING_WS = re.compile(r"[ \t]+$", re.M)
_MANY_BLANK = re.compile(r"\n{3,}")
_MANY_SPACE = re.compile(r"[ \t]{2,}")
# Non-breaking and exotic spaces -> plain space. NOT applied to \n.
_NBSP = re.compile(r"[   -   　]")

TRANSFORMS = (
    "nfc",
    "crlf_to_lf",
    "control_chars_removed",
    "zero_width_removed",
    "nbsp_normalized",
    "trailing_ws_stripped",
    "blank_lines_collapsed",
    "inner_spaces_collapsed",
    "edges_trimmed",
)


def canonicalize(text: str) -> tuple[str, list[str]]:
    """Return (canonical_text, [names of transforms that actually changed it])."""
    if not text:
        return "", []
    applied: list[str] = []

    out = unicodedata.normalize("NFC", text)
    if out != text:
        applied.append("nfc")

    prev = out
    out = _CRLF.sub("\n", out)
    if out != prev:
        applied.append("crlf_to_lf")

    prev = out
    out = _CONTROL.sub("", out)
    if out != prev:
        applied.append("control_chars_removed")

    prev = out
    out = _ZERO_WIDTH.sub("", out)
    if out != prev:
        applied.append("zero_width_removed")

    prev = out
    out = _NBSP.sub(" ", out)
    if out != prev:
        applied.append("nbsp_normalized")

    prev = out
    out = _TRAILING_WS.sub("", out)
    if out != prev:
        applied.append("trailing_ws_stripped")

    prev = out
    out = _MANY_BLANK.sub("\n\n", out)
    if out != prev:
        applied.append("blank_lines_collapsed")

    prev = out
    out = _MANY_SPACE.sub(" ", out)
    if out != prev:
        applied.append("inner_spaces_collapsed")

    prev = out
    out = out.strip()
    if out != prev:
        applied.append("edges_trimmed")

    return out, applied
