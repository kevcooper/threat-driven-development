"""A small JSON Schema (2020-12) validator, standard library only.

It covers the keywords the vendored Threat Composer schema uses plus a few common
neighbours. An unsupported validation keyword raises instead of being skipped, so a
schema update that needs more is noticed (tests/test_schema.py loads the real schema).
``format`` is treated as an annotation, the 2020-12 default.
"""

from __future__ import annotations

import json
import os
import re
from functools import lru_cache
from typing import Any, Dict, List

SCHEMA_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "schemas")
THREAT_COMPOSER_SCHEMA = os.path.join(SCHEMA_DIR, "threat-composer-v1.schema.json")

ANNOTATIONS = {
    "$schema", "$id", "$comment", "$defs", "definitions", "title", "description", "default",
    "examples", "deprecated", "readOnly", "writeOnly", "format",
}
VALIDATORS = {
    "type", "properties", "required", "additionalProperties", "items", "anyOf", "oneOf", "allOf",
    "not", "const", "enum", "maxLength", "minLength", "maximum", "minimum", "exclusiveMaximum",
    "exclusiveMinimum", "pattern", "minItems", "maxItems", "uniqueItems", "$ref",
}


class UnsupportedSchema(ValueError):
    pass


@lru_cache(maxsize=4)
def load(path: str = THREAT_COMPOSER_SCHEMA) -> Dict[str, Any]:
    with open(path, encoding="utf-8") as fh:
        schema = json.load(fh)
    check_supported(schema)
    return schema


def check_supported(schema: Any) -> None:
    def walk(node: Any) -> None:
        if isinstance(node, dict):
            for key, value in node.items():
                if key not in ANNOTATIONS and key not in VALIDATORS:
                    raise UnsupportedSchema(f"unsupported JSON Schema keyword '{key}'")
                if key in ("properties", "$defs", "definitions"):
                    for sub in value.values():
                        walk(sub)
                elif key in ("items", "additionalProperties", "not"):
                    walk(value)
                elif key in ("anyOf", "oneOf", "allOf"):
                    for sub in value:
                        walk(sub)
    walk(schema)


def _type_ok(value: Any, t: str) -> bool:
    if t == "object":
        return isinstance(value, dict)
    if t == "array":
        return isinstance(value, list)
    if t == "string":
        return isinstance(value, str)
    if t == "boolean":
        return isinstance(value, bool)
    if t == "null":
        return value is None
    if t == "number":
        return isinstance(value, (int, float)) and not isinstance(value, bool)
    if t == "integer":
        return isinstance(value, (int, float)) and not isinstance(value, bool) and float(value).is_integer()
    return False


def _resolve(root: Dict[str, Any], ref: str) -> Dict[str, Any]:
    if not ref.startswith("#"):
        raise UnsupportedSchema(f"only local $ref is supported: {ref}")
    node: Any = root
    for part in ref.lstrip("#/").split("/") if ref != "#" else []:
        node = node[part.replace("~1", "/").replace("~0", "~")]
    return node


def validate(instance: Any, schema: Dict[str, Any], path: str = "$", root: Dict[str, Any] = None) -> List[str]:
    """Return a list of 'path: problem' strings; empty means valid."""
    root = root if root is not None else schema
    errs: List[str] = []
    if schema is True or schema == {}:
        return errs
    if schema is False:
        return [f"{path}: not allowed"]
    if "$ref" in schema:
        errs += validate(instance, _resolve(root, schema["$ref"]), path, root)

    if "type" in schema:
        types = schema["type"] if isinstance(schema["type"], list) else [schema["type"]]
        if not any(_type_ok(instance, t) for t in types):
            return errs + [f"{path}: expected {' or '.join(types)}"]
    if "const" in schema and instance != schema["const"]:
        errs.append(f"{path}: must be {json.dumps(schema['const'])}")
    if "enum" in schema and instance not in schema["enum"]:
        errs.append(f"{path}: must be one of {', '.join(json.dumps(e) for e in schema['enum'])}")

    if isinstance(instance, str):
        if "maxLength" in schema and len(instance) > schema["maxLength"]:
            errs.append(f"{path}: longer than {schema['maxLength']} characters")
        if "minLength" in schema and len(instance) < schema["minLength"]:
            errs.append(f"{path}: shorter than {schema['minLength']} characters")
        if "pattern" in schema and not re.search(schema["pattern"], instance):
            errs.append(f"{path}: does not match pattern {schema['pattern'][:60]}")
    if isinstance(instance, (int, float)) and not isinstance(instance, bool):
        if "maximum" in schema and instance > schema["maximum"]:
            errs.append(f"{path}: must be at most {schema['maximum']}")
        if "minimum" in schema and instance < schema["minimum"]:
            errs.append(f"{path}: must be at least {schema['minimum']}")
        if "exclusiveMaximum" in schema and instance >= schema["exclusiveMaximum"]:
            errs.append(f"{path}: must be less than {schema['exclusiveMaximum']}")
        if "exclusiveMinimum" in schema and instance <= schema["exclusiveMinimum"]:
            errs.append(f"{path}: must be greater than {schema['exclusiveMinimum']}")

    if isinstance(instance, dict):
        props = schema.get("properties", {})
        for key in schema.get("required", []):
            if key not in instance:
                errs.append(f"{path}.{key}: required")
        for key, value in instance.items():
            if key in props:
                errs += validate(value, props[key], f"{path}.{key}", root)
            elif "additionalProperties" in schema:
                extra = schema["additionalProperties"]
                if extra is False:
                    errs.append(f"{path}: unrecognized key '{key}'")
                elif isinstance(extra, dict):
                    errs += validate(value, extra, f"{path}.{key}", root)

    if isinstance(instance, list):
        if "items" in schema:
            for i, item in enumerate(instance):
                errs += validate(item, schema["items"], f"{path}[{i}]", root)
        if "minItems" in schema and len(instance) < schema["minItems"]:
            errs.append(f"{path}: needs at least {schema['minItems']} items")
        if "maxItems" in schema and len(instance) > schema["maxItems"]:
            errs.append(f"{path}: allows at most {schema['maxItems']} items")
        if schema.get("uniqueItems"):
            seen = [json.dumps(x, sort_keys=True) for x in instance]
            if len(seen) != len(set(seen)):
                errs.append(f"{path}: items must be unique")

    if "allOf" in schema:
        for sub in schema["allOf"]:
            errs += validate(instance, sub, path, root)
    if "anyOf" in schema or "oneOf" in schema:
        branches = schema.get("anyOf") or schema.get("oneOf")
        results = [validate(instance, sub, path, root) for sub in branches]
        passing = [r for r in results if not r]
        if not passing:
            best = min(results, key=len)
            errs.append(f"{path}: matches none of the {len(branches)} allowed forms"
                        + (f" (closest: {best[0]})" if best else ""))
        elif "oneOf" in schema and len(passing) > 1:
            errs.append(f"{path}: matches more than one of the allowed forms")
    if "not" in schema and not validate(instance, schema["not"], path, root):
        errs.append(f"{path}: matches a form that is not allowed")
    return errs


def validate_threat_composer(data: Any) -> List[str]:
    return validate(data, load())
