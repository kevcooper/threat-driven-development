"""Threat Composer's canonical file format.

The Threat Composer editor (AWS Toolkit for VS Code) loads a ``.tc.json`` by:

1. running ``sanitize-html`` with no allowed tags over every string value,
2. parsing the result with strict zod schemas (unknown keys reject the file;
   output objects are rebuilt in schema-declaration key order),
3. rebuilding the top-level object in a fixed order, filling in missing
   sections, and dropping ``workspace`` and an empty ``brainstorm``.

The Threats, Mitigations and Assumptions list views then sort the in-memory
arrays *in place* (threats by ``numericId`` descending, the others by
``displayOrder`` descending), so merely browsing those views reorders them.

Every second the webview serializes the current state with
``JSON.stringify(data, null, 2)`` and compares it to the file text. If they
differ and the parsed JSON is not deep-equal, the Toolkit rewrites the whole
file, which shows up as reordered keys and stripped ``<tags>``.

This module reproduces steps 1 to 3, the list-view sorts and the serializer, so
files written by ``tdd`` are already in the form the editor would write and
opening them changes nothing.

Sources (read, not vendored): awslabs/threat-composer
``packages/threat-composer/src/{hooks/useExportImport,utils/sanitizeHtml,customTypes,
components/*/…List}`` and aws/aws-toolkit-vscode
``packages/core/resources/js/vsCodeExtensionInterface.js``.
"""

from __future__ import annotations

import html
import html.entities
import json
import math
import re
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional, Tuple

# ---- limits and enums (packages/threat-composer/src/configs) ---------------------

TAG_MAX = 30
SMALL_MAX = 50
FIELD_MAX = 200
FREE_TEXT_SMALL_MAX = 1000
FREE_TEXT_MAX = 100000
IMAGE_URL_MAX = 2048
IMAGE_BASE64_MAX = 1000000
ID_MAX = 36

THREAT_STATUSES = ("threatIdentified", "threatResolved", "threatResolvedNotUseful")
MITIGATION_STATUSES = (
    "mitigationIdentified",
    "mitigationInProgress",
    "mitigationResolved",
    "mitigationResolvedWillNotAction",
)
STRIDE = ("S", "T", "R", "I", "D", "E")
PRIORITIES = ("High", "Medium", "Low")
CUSTOM_PREFIX = "custom:"

TOP_LEVEL_ORDER = (
    "schema",
    "applicationInfo",
    "architecture",
    "dataflow",
    "assumptions",
    "mitigations",
    "assumptionLinks",
    "mitigationLinks",
    "threats",
)
BRAINSTORM_KEYS = (
    "assumptions",
    "threatSources",
    "threatPrerequisites",
    "threatActions",
    "threatImpacts",
    "assets",
    "mitigations",
)


# ---- sanitize-html (allowedTags: []) -----------------------------------------------

# htmlparser2 treats these as raw-text / special; sanitize-html drops or re-escapes
# their content in ways that are not worth reproducing. Strings containing them are
# reported as "uncertain" instead of guessed at.
_SPECIAL_TAGS = {
    "script", "style", "textarea", "option", "xmp", "title", "iframe",
    "noembed", "noframes", "plaintext", "noscript",
}
_ENTITY_RE = re.compile(r"&(#[0-9]+;|#[xX][0-9a-fA-F]+;|[A-Za-z][A-Za-z0-9]*;)")
_TAG_RE = re.compile(r"</?([A-Za-z][A-Za-z0-9-]*)[^>]*>")


class Uncertain(ValueError):
    """The string contains markup whose exact sanitize-html output is not reproduced."""


def _escape(text: str) -> str:
    return text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def sanitize_string(value: str) -> str:
    """What Threat Composer stores for ``value`` after ``sanitizeHtml``.

    Tags are removed, entities are decoded, and ``&``, ``<``, ``>`` in the
    remaining text are escaped. Raises ``Uncertain`` for constructs outside the
    subset reproduced here (comments, ``<!``/``<?``, quotes inside tags, raw-text
    tags, unterminated tags, non-standard entities).
    """
    if "<" not in value and "&" not in value and ">" not in value:
        return value
    out: List[str] = []
    i, n = 0, len(value)
    while i < n:
        c = value[i]
        if c == "&":
            m = _ENTITY_RE.match(value, i)
            if m:
                body = m.group(1)
                if body.startswith("#") or body in html.entities.html5:
                    out.append(html.unescape(m.group(0)))
                    i = m.end()
                    continue
                raise Uncertain(f"non-standard entity {m.group(0)!r}")
            nxt = value[i + 1] if i + 1 < n else ""
            if nxt.isalnum() or nxt == "#":
                raise Uncertain("'&' followed by a letter, digit or '#' (legacy entity rules)")
            out.append("&")
            i += 1
        elif c == "<":
            nxt = value[i + 1] if i + 1 < n else ""
            nxt2 = value[i + 2] if i + 2 < n else ""
            if nxt.isascii() and nxt.isalpha() or (nxt == "/" and nxt2.isascii() and nxt2.isalpha()):
                m = _TAG_RE.match(value, i)
                if not m:
                    raise Uncertain("unterminated tag")
                if '"' in m.group(0) or "'" in m.group(0) or "<" in m.group(0)[1:]:
                    raise Uncertain("tag containing quotes or '<'")
                if m.group(1).lower() in _SPECIAL_TAGS:
                    raise Uncertain(f"<{m.group(1)}> is a raw-text tag")
                i = m.end()  # tag dropped, its text content (if any) is kept
            elif nxt in ("!", "?") or nxt == "/":
                raise Uncertain("comment, declaration or processing instruction")
            else:
                out.append("<")
                i += 1
        else:
            out.append(c)
            i += 1
    return _escape("".join(out))


# ---- JSON.stringify(data, null, 2) --------------------------------------------------


def _js_number(x: Any) -> str:
    if isinstance(x, bool):
        return "true" if x else "false"
    if isinstance(x, int):
        return str(x)
    if math.isnan(x) or math.isinf(x):
        return "null"
    if x == int(x) and abs(x) < 1e21:
        return str(int(x))
    r = repr(x)  # shortest round-trip, same digits as JS
    if "e" not in r:
        mant, exp = r, 0
    else:
        mant, e = r.split("e")
        exp = int(e)
    neg = mant.startswith("-")
    mant = mant.lstrip("-")
    if "." in mant:
        ip, fp = mant.split(".")
    else:
        ip, fp = mant, ""
    digits = (ip + fp).lstrip("0") or "0"
    point = len(ip) + exp - (len(ip + fp) - len((ip + fp).lstrip("0")))
    k = len(digits.rstrip("0")) or 1
    digits = digits[:k]
    if -6 < point <= 21:
        if point <= 0:
            s = "0." + "0" * (-point) + digits
        elif point >= k:
            s = digits + "0" * (point - k)
        else:
            s = digits[:point] + "." + digits[point:]
    else:
        e = point - 1
        s = digits[0] + ("." + digits[1:] if k > 1 else "") + "e" + ("+" if e > 0 else "-") + str(abs(e))
    return ("-" if neg else "") + s


def _js_string(s: str) -> str:
    out = ['"']
    for ch in s:
        o = ord(ch)
        if ch == '"':
            out.append('\\"')
        elif ch == "\\":
            out.append("\\\\")
        elif ch == "\n":
            out.append("\\n")
        elif ch == "\r":
            out.append("\\r")
        elif ch == "\t":
            out.append("\\t")
        elif ch == "\b":
            out.append("\\b")
        elif ch == "\f":
            out.append("\\f")
        elif o < 0x20 or 0xD800 <= o <= 0xDFFF:
            out.append("\\u%04x" % o)
        else:
            out.append(ch)
    out.append('"')
    return "".join(out)


def js_stringify(value: Any, indent: str = "  ", _level: int = 0) -> str:
    """``JSON.stringify(value, null, 2)``: no trailing newline, non-ASCII kept as is."""
    pad, inner = indent * _level, indent * (_level + 1)
    if value is None:
        return "null"
    if isinstance(value, (bool, int, float)):
        return _js_number(value)
    if isinstance(value, str):
        return _js_string(value)
    if isinstance(value, list):
        if not value:
            return "[]"
        items = [js_stringify(v, indent, _level + 1) for v in value]
        return "[\n" + ",\n".join(inner + i for i in items) + "\n" + pad + "]"
    if isinstance(value, dict):
        if not value:
            return "{}"
        items = [_js_string(str(k)) + ": " + js_stringify(v, indent, _level + 1) for k, v in value.items()]
        return "{\n" + ",\n".join(inner + i for i in items) + "\n" + pad + "}"
    raise TypeError(f"cannot serialize {type(value).__name__}")


# ---- strict schema (packages/threat-composer/src/customTypes) ------------------------


def _u16len(s: str) -> int:
    """JavaScript string length (UTF-16 code units)."""
    return len(s.encode("utf-16-le")) // 2


# Rendered as Markdown, so an escaped entity (a blockquote's '>' becoming '&gt;') still
# displays correctly. Rewrites here are just formatting. Every other string is shown as
# plain text, where Threat Composer's escaping is visible ('&' displays as '&amp;').
MARKDOWN_PATHS = {"$.applicationInfo.description", "$.architecture.description", "$.dataflow.description"}


@dataclass
class Report:
    errors: List[str] = field(default_factory=list)  # Threat Composer would refuse the file
    changes: List[str] = field(default_factory=list)  # plain text Threat Composer would visibly rewrite
    uncertain: List[str] = field(default_factory=list)  # text whose rewrite is not reproduced
    markdown_changes: List[str] = field(default_factory=list)  # harmless entity escaping in Markdown

    @property
    def ok(self) -> bool:
        return not self.errors and not self.uncertain


Check = Callable[[Any, str, Report], Any]


def _str(max_len: Optional[int] = None, *, nonempty=False, exact: Optional[int] = None,
         enum: Optional[Tuple[str, ...]] = None, prefix: Optional[str] = None) -> Check:
    def check(v: Any, path: str, r: Report) -> Any:
        if not isinstance(v, str):
            r.errors.append(f"{path}: expected a string")
            return v
        n = _u16len(v)
        if exact is not None and n != exact:
            r.errors.append(f"{path}: must be exactly {exact} characters")
        if max_len is not None and n > max_len:
            r.errors.append(f"{path}: longer than {max_len} characters")
        if nonempty and not v:
            r.errors.append(f"{path}: must not be empty")
        if enum is not None and v not in enum:
            r.errors.append(f"{path}: must be one of {', '.join(enum)}")
        if prefix is not None and not v.startswith(prefix):
            r.errors.append(f"{path}: must start with {prefix!r}")
        return v
    return check


def _num(max_value: Optional[float] = None) -> Check:
    def check(v: Any, path: str, r: Report) -> Any:
        if isinstance(v, bool) or not isinstance(v, (int, float)):
            r.errors.append(f"{path}: expected a number")
        elif max_value is not None and v > max_value:
            r.errors.append(f"{path}: must be at most {max_value:g}")
        return v
    return check


def _array(item: Check) -> Check:
    def check(v: Any, path: str, r: Report) -> Any:
        if not isinstance(v, list):
            r.errors.append(f"{path}: expected an array")
            return v
        return [item(x, f"{path}[{i}]", r) for i, x in enumerate(v)]
    return check


def _obj(fields: List[Tuple[str, Check, bool]], strict: bool = True) -> Check:
    """Fields are (name, check, required) in schema-declaration order, which is output order."""
    names = {f[0] for f in fields}

    def check(v: Any, path: str, r: Report) -> Any:
        if not isinstance(v, dict):
            r.errors.append(f"{path}: expected an object")
            return v
        if strict:
            for key in v:
                if key not in names:
                    r.errors.append(f"{path}: unrecognized key '{key}'")
        out: Dict[str, Any] = {}
        for name, sub, required in fields:
            if name in v:
                out[name] = sub(v[name], f"{path}.{name}", r)
            elif required:
                r.errors.append(f"{path}.{name}: required")
        return out
    return check


def _image(v: Any, path: str, r: Report) -> Any:
    if not isinstance(v, str):
        r.errors.append(f"{path}: expected a string")
    elif v:
        is_url = re.match(r"^https?://", v, re.I) and _u16len(v) <= IMAGE_URL_MAX
        is_b64 = re.match(r"^data:image/[a-z+]{3,};base64,[A-Za-z0-9+/]*={0,2}$", v, re.I) and _u16len(v) <= IMAGE_BASE64_MAX
        if not (is_url or is_b64):
            r.errors.append(f"{path}: invalid image (URL up to {IMAGE_URL_MAX} chars or base64 data URI)")
    return v


def _metadata(allowed: Dict[str, Check]) -> Check:
    def check(v: Any, path: str, r: Report) -> Any:
        if not isinstance(v, dict):
            r.errors.append(f"{path}: expected an object")
            return v
        extra = [k for k in v if k not in ("key", "value")]
        if extra or "key" not in v or "value" not in v:
            r.errors.append(f"{path}: metadata entries must have exactly 'key' and 'value'")
            return v
        key = v["key"]
        if isinstance(key, str) and key.startswith(CUSTOM_PREFIX):
            _str(SMALL_MAX)(key, f"{path}.key", r)
            val = v["value"]
            ok = isinstance(val, str) or (isinstance(val, list) and all(isinstance(x, str) for x in val))
            if not ok:
                r.errors.append(f"{path}.value: custom metadata value must be a string or array of strings")
            return {"key": key, "value": val}
        if key not in allowed:
            r.errors.append(
                f"{path}.key: '{key}' is not allowed here (allowed: {', '.join(allowed)}, or a 'custom:' key)"
            )
            return v
        return {"key": key, "value": allowed[key](v["value"], f"{path}.value", r)}
    return check


_COMMENTS = {"Comments": _str(FREE_TEXT_SMALL_MAX)}
_THREAT_META = {
    **_COMMENTS,
    "source": _str(enum=("threatPack",)),
    "STRIDE": _array(_str(enum=STRIDE)),
    "Priority": _str(enum=PRIORITIES),
    "threatPackId": _str(TAG_MAX, nonempty=True),
    "threatPackThreatId": _str(ID_MAX),
    "threatPackMitigationCandidateId": _str(ID_MAX),
}
_MITIGATION_META = {
    **_COMMENTS,
    "source": _str(enum=("mitigationPack",)),
    "mitigationPackId": _str(TAG_MAX, nonempty=True),
    "mitigationPackMitigationId": _str(ID_MAX),
}


def _entity_base(meta: Dict[str, Check]) -> List[Tuple[str, Check, bool]]:
    return [
        ("id", _str(ID_MAX), True),
        ("numericId", _num(), True),
        ("displayOrder", _num(), False),
        ("metadata", _array(_metadata(meta)), False),
        ("tags", _array(_str(TAG_MAX, nonempty=True)), False),
    ]


_DISPLAY_TOKEN = _obj([
    ("type", _str(enum=("b", "span")), False),
    ("tooltip", _str(30), False),
    ("content", _str(FIELD_MAX), True),
])


def _display_item(v: Any, path: str, r: Report) -> Any:
    return v if isinstance(v, str) else _DISPLAY_TOKEN(v, path, r)


ASSUMPTION = _obj(_entity_base(_COMMENTS) + [("content", _str(FREE_TEXT_SMALL_MAX), True)])
MITIGATION = _obj(_entity_base(_MITIGATION_META) + [
    ("content", _str(FREE_TEXT_SMALL_MAX), True),
    ("status", _str(enum=MITIGATION_STATUSES), False),
])
THREAT = _obj(_entity_base(_THREAT_META) + [
    ("threatSource", _str(FIELD_MAX), False),
    ("prerequisites", _str(FIELD_MAX), False),
    ("threatAction", _str(FIELD_MAX), False),
    ("threatImpact", _str(FIELD_MAX), False),
    ("impactedGoal", _array(_str(FIELD_MAX)), False),
    ("impactedAssets", _array(_str(FIELD_MAX)), False),
    ("statement", _str(FIELD_MAX * 7), False),
    ("customTemplate", _str(FIELD_MAX), False),
    ("displayedStatement", _array(_display_item), False),
    ("status", _str(enum=THREAT_STATUSES), False),
])
ASSUMPTION_LINK = _obj([
    ("type", _str(enum=("Mitigation", "Threat")), True),
    ("assumptionId", _str(exact=36), True),
    ("linkedId", _str(exact=36), True),
])
MITIGATION_LINK = _obj([
    ("mitigationId", _str(exact=36), True),
    ("linkedId", _str(exact=36), True),
])
APPLICATION_INFO = _obj([("name", _str(FIELD_MAX), False), ("description", _str(FREE_TEXT_MAX), False)])
IMAGE_INFO = _obj([("description", _str(FREE_TEXT_MAX), False), ("image", _image, False)])


def _datetime(v: Any, path: str, r: Report) -> Any:
    if not isinstance(v, str) or not re.match(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}(:\d{2}(\.\d+)?)?Z$", v):
        r.errors.append(f"{path}: expected an ISO 8601 UTC timestamp ending in Z")
    return v


_BRAINSTORM_ITEM = _obj([
    ("id", _str(ID_MAX), True),
    ("content", _str(FIELD_MAX), True),
    ("createdAt", _datetime, True),
    ("createdBy", _str(SMALL_MAX), False),
    ("groupId", _str(ID_MAX), False),
])
BRAINSTORM = _obj([(k, _array(_BRAINSTORM_ITEM), False) for k in BRAINSTORM_KEYS])
WORKSPACE = _obj([
    ("id", _str(exact=36), True),
    ("name", _str(SMALL_MAX), True),
    ("storageType", _str(), False),
    ("metadata", lambda v, p, r: v, False),
], strict=False)

DATA_EXCHANGE = _obj([
    ("schema", _num(1), True),
    ("workspace", WORKSPACE, False),
    ("applicationInfo", APPLICATION_INFO, False),
    ("architecture", IMAGE_INFO, False),
    ("dataflow", IMAGE_INFO, False),
    ("assumptions", _array(ASSUMPTION), False),
    ("mitigations", _array(MITIGATION), False),
    ("assumptionLinks", _array(ASSUMPTION_LINK), False),
    ("mitigationLinks", _array(MITIGATION_LINK), False),
    ("threats", _array(THREAT), False),
    ("brainstorm", BRAINSTORM, False),
])


# ---- the full load → export cycle ----------------------------------------------------


def _excerpt(before: str, after: str, width: int = 30) -> str:
    """Show where two strings first differ."""
    i = 0
    while i < min(len(before), len(after)) and before[i] == after[i]:
        i += 1
    lo = max(0, i - width)
    return f"{before[lo:i + width]!r} -> {after[lo:i + width]!r}"


def _sanitize(value: Any, path: str, r: Report) -> Any:
    if isinstance(value, str):
        if not value:
            return value
        try:
            out = sanitize_string(value)
        except Uncertain as exc:
            r.uncertain.append(f"{path}: {exc}: {value[:80]!r}")
            return value
        if out != value:
            note = f"{path}: {_excerpt(value, out)}"
            (r.markdown_changes if path in MARKDOWN_PATHS else r.changes).append(note)
        return out
    if isinstance(value, list):
        return [_sanitize(v, f"{path}[{i}]", r) for i, v in enumerate(value)]
    if isinstance(value, dict):
        return {k: _sanitize(v, f"{path}.{k}", r) for k, v in value.items()}
    return value


def _view_sort_key(field_name: str):
    # (b.x || Number.MAX_VALUE) - (a.x || Number.MAX_VALUE), stable: descending,
    # with missing or 0 treated as the largest value.
    def key(item: Dict[str, Any]) -> float:
        v = item.get(field_name)
        if isinstance(v, bool) or not isinstance(v, (int, float)) or not v:
            return -math.inf
        return -v
    return key


def canonicalize(data: Any) -> Tuple[Optional[Dict[str, Any]], Report]:
    """Return what Threat Composer would write back for ``data``, and a report.

    The result is None when Threat Composer would refuse to open the data.
    """
    r = Report()
    if isinstance(data, list):
        r.errors.append("$: legacy array format is not supported")
        return None, r
    clean = _sanitize(data, "$", r)
    parsed = DATA_EXCHANGE(clean, "$", r)
    if not r.errors and parsed.get("schema") != 1:
        r.errors.append("$.schema: must be 1")
    if r.errors:
        return None, r

    out: Dict[str, Any] = {
        "schema": 1,
        "applicationInfo": parsed.get("applicationInfo", {}),
        "architecture": parsed.get("architecture", {}),
        "dataflow": parsed.get("dataflow", {}),
        "assumptions": sorted(parsed.get("assumptions", []), key=_view_sort_key("displayOrder")),
        "mitigations": sorted(parsed.get("mitigations", []), key=_view_sort_key("displayOrder")),
        "assumptionLinks": parsed.get("assumptionLinks", []),
        "mitigationLinks": parsed.get("mitigationLinks", []),
        "threats": [
            {k: v for k, v in t.items() if k != "displayedStatement"}
            for t in sorted(parsed.get("threats", []), key=_view_sort_key("numericId"))
        ],
    }
    brainstorm = parsed.get("brainstorm")
    if brainstorm and any(brainstorm.get(k) for k in BRAINSTORM_KEYS):
        out["brainstorm"] = brainstorm
    return out, r


def dumps(data: Dict[str, Any]) -> str:
    """Canonical file text for already-canonical data."""
    return js_stringify(data)


@dataclass
class FormatResult:
    text: Optional[str]  # canonical text, None if the file cannot be formatted
    report: Report
    changed: bool = False


def format_text(text: str) -> FormatResult:
    try:
        data = json.loads(text)
    except json.JSONDecodeError as exc:
        return FormatResult(None, Report(errors=[f"invalid JSON: {exc}"]))
    canon, report = canonicalize(data)
    if canon is None:
        return FormatResult(None, report)
    out = dumps(canon)
    return FormatResult(out, report, out != text)


# ---- threat statement rendering (utils/renderThreatStatement) -------------------------

_FIELDS = [  # token, key, fieldId, displayField
    ("threat_source", "threatSource", 1, "threat source"),
    ("prerequisites", "prerequisites", 2, "prerequisites"),
    ("threat_action", "threatAction", 4, "threat action"),
    ("threat_impact", "threatImpact", 8, "threat impact"),
    ("impacted_goal", "impactedGoal", 16, "impacted goal"),
    ("impacted_assets", "impactedAssets", 32, "impacted assets"),
]
_BY_TOKEN = {f[0]: f for f in _FIELDS}
_FORMATS = {
    7: "A [threat_source] [prerequisites] can [threat_action]",
    15: "A [threat_source] [prerequisites] can [threat_action], which leads to [threat_impact]",
    23: "A [threat_source] [prerequisites] can [threat_action], resulting in reduced [impacted_goal]",
    31: "A [threat_source] [prerequisites] can [threat_action], which leads to [threat_impact], resulting in reduced [impacted_goal]",
    39: "A [threat_source] [prerequisites] can [threat_action], negatively impacting [impacted_assets]",
    47: "A [threat_source] [prerequisites] can [threat_action], which leads to [threat_impact], negatively impacting [impacted_assets]",
    55: "A [threat_source] [prerequisites] can [threat_action], resulting in reduced [impacted_goal] of [impacted_assets]",
    63: "A [threat_source] [prerequisites] can [threat_action], which leads to [threat_impact], resulting in reduced [impacted_goal] of [impacted_assets]",
}
_PLACEHOLDER = "<placeholder>"

# npm 'indefinite' 2.5.2, which Threat Composer uses for a/an.
_IRREGULAR = set("""
eunuch eucalyptus eugenics eulogy euphemism euphony euphoria eureka euro european euphemistic
euphonic euphoric euphemistically euphonically euphorically heir heiress herb homage honesty honor
honour honoree hour honest honorous honorific honorable honourable honestly hourly one ouija once
ubiquity udometer ufo uke ukelele ululate unicorn unicycle uniform unify union unison unit unity
universe university upas ural uranium urea ureter urethra urine urologist urology urus usage use user
usual usurp usurper usury utensil uterus utility utopia utricle uvarovite uvea uvula utah utahn
ubiquitous ugandan ukrainian unanimous unicameral unified unique unisex universal urinal urological
useful useless usurious utilitarian utopic ubiquitously unanimously unicamerally uniquely universally
urologically usefully uselessly usuriously yttria yggdrasil ylem yperite ytterbia ytterbium yttrium
ytterbous ytterbic yttric f h l m n r s u x
""".split())


def _is_irregular(word: str) -> bool:
    for ending in (None, "s", "es", "ed"):
        w = word
        if ending:
            if w.endswith(ending):
                w = w[: -len(ending)]
            if len(w) <= 1:
                continue
        if w in _IRREGULAR:
            return True
    return False


def indefinite_article(word: str, capitalize: bool = False) -> str:
    starts_vowel = bool(re.match(r"^[aeiouAEIOU]", word))
    m = re.match(r"^([0-9,]+)", word)
    if m:
        number = m.group(1).replace(",", "")
        article = "a"
        if re.match(r"^(11|8|18)", number):
            eleven = bool(re.match(r"^(11|18)", number))
            if eleven and len(number) == 4:
                article = "a"
            elif eleven and (len(number) - 2) % 3 == 0:
                article = "an"
            else:
                article = "an" if number.startswith("8") else "a"
    elif re.match(r"^[A-Z]+$", word.split(" ")[0]):
        irregular = bool(re.match(r"^[UFHLMNRSX]", word[:1]))
        article = "a" if starts_vowel == irregular else "an"
    else:
        first = re.split(r"[\s'-]", word)[0].lower()
        article = "an" if starts_vowel != _is_irregular(first) else "a"
    return article[0].upper() + article[1:] if capitalize else article


_ARTICLE_RE = re.compile(r"\b(a|an) ([\s(\"'“‘-]?\w*)\b", re.IGNORECASE | re.MULTILINE | re.ASCII)


def correct_articles(text: str) -> str:
    def repl(m: "re.Match[str]") -> str:
        article, following = m.group(1), m.group(2)
        word = re.sub(r"^[\s(\"'“‘-]+|\s+$", "", following)
        return indefinite_article(word, capitalize=article.startswith("A")) + " " + following
    return _ARTICLE_RE.sub(repl, text)


def _filled(v: Any) -> bool:
    return (isinstance(v, str) and v != "") or (isinstance(v, list) and len(v) > 0)


def _field_content(token: str, t: Dict[str, Any]) -> str:
    _, key, _, display = _BY_TOKEN.get(token, (token, token, 0, ""))
    v = t.get(key)
    if isinstance(v, str) and v:
        return v
    if isinstance(v, list) and v:
        if len(v) == 1:
            return v[0]
        return ", ".join(v[:-1]) + (" and/or " if token == "impacted_goal" else " and ") + v[-1]
    return display


def render_statement(t: Dict[str, Any]) -> str:
    """Threat Composer's ``renderThreatStatement(t).statement``."""
    filled = [f for f in _FIELDS if _filled(t.get(f[1]))]
    if not filled:
        return ""
    if len(filled) == 1:
        token = filled[0][0]
        position = [f[0] for f in _FIELDS].index(token) + 1
        prefix, suffix = "...", "..."
        if position == 1:
            prefix = ""
        elif position == len(_FIELDS):
            suffix = ""
        return prefix + _field_content(token, t) + suffix

    u = dict(t)
    u["threatSource"] = t.get("threatSource") or "threat source"
    u["prerequisites"] = t.get("prerequisites") or _PLACEHOLDER
    u["threatAction"] = t.get("threatAction") or "perform a threat action"
    combo = sum(f[2] for f in _FIELDS if _filled(u.get(f[1])))
    template = t.get("customTemplate") or _FORMATS.get(combo, "")

    parts: List[str] = []
    while True:
        start = template.find("[")
        if start < 0:
            break
        end = template.find("]")
        if end < 0:
            break
        before = template[:start]
        token = template[start + 1:end]
        content = correct_articles(_field_content(token, u))
        if before == "A ":
            before = before.replace("A", indefinite_article(content, capitalize=True), 1)
        before = correct_articles(before)
        if token == "prerequisites" and content == _PLACEHOLDER:
            content = ""
        parts += [before, content]
        template = template[end + 1:]
    return re.sub(r"\s\s+", " ", " ".join(parts)).replace(" ,", ",")
