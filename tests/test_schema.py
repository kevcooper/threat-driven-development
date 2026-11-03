"""The vendored official Threat Composer schema, the validator, and `tdd lint`."""

import json
import unittest
import uuid

from tests.helpers import RepoTestCase
from threat_tdd import canonical, jsonschema_lite
from threat_tdd.lint import RULES

U = lambda: str(uuid.uuid4())  # noqa: E731


def _fields(check):
    """Field names, in order, of a canonical._obj check (read from its closure)."""
    for cell in check.__closure__ or ():
        v = cell.cell_contents
        if isinstance(v, list) and v and isinstance(v[0], tuple):
            return [f[0] for f in v]
    raise AssertionError("not an object check")


class VendoredSchemaTests(unittest.TestCase):
    def setUp(self):
        self.schema = jsonschema_lite.load()  # also asserts every keyword is supported

    def props(self, *path):
        node = self.schema
        for p in path:
            node = node["properties"][p] if p != "[]" else node["items"]
        return node

    def test_key_order_matches_canonical(self):
        # The official schema is generated from the same zod shapes the editor parses
        # with, so its property order is the editor's output key order.
        top = [k for k in self.schema["properties"]]
        self.assertEqual(top[: len(canonical.TOP_LEVEL_ORDER)], list(canonical.TOP_LEVEL_ORDER))
        cases = {
            ("threats", "[]"): canonical.THREAT,
            ("mitigations", "[]"): canonical.MITIGATION,
            ("assumptions", "[]"): canonical.ASSUMPTION,
            ("assumptionLinks", "[]"): canonical.ASSUMPTION_LINK,
            ("mitigationLinks", "[]"): canonical.MITIGATION_LINK,
            ("applicationInfo",): canonical.APPLICATION_INFO,
            ("architecture",): canonical.IMAGE_INFO,
        }
        internal = {"displayedStatement"}  # excluded from the published schema
        for path, check in cases.items():
            ours = [f for f in _fields(check) if f not in internal]
            self.assertEqual(list(self.props(*path)["properties"]), ours, path)

    def test_limits_match_canonical(self):
        t = self.props("threats", "[]")["properties"]
        self.assertEqual(t["threatAction"]["maxLength"], canonical.FIELD_MAX)
        self.assertEqual(t["statement"]["maxLength"], canonical.FIELD_MAX * 7)
        self.assertEqual(t["tags"]["items"]["maxLength"], canonical.TAG_MAX)
        self.assertEqual(sorted(t["status"]["enum"]), sorted(canonical.THREAT_STATUSES))
        m = self.props("mitigations", "[]")["properties"]
        self.assertEqual(m["content"]["maxLength"], canonical.FREE_TEXT_SMALL_MAX)
        self.assertEqual(sorted(m["status"]["enum"]), sorted(canonical.MITIGATION_STATUSES))

    def test_validator(self):
        good = {"schema": 1, "threats": [{"id": U(), "numericId": 1, "statement": "s",
                                          "metadata": [{"key": "STRIDE", "value": ["S"]}]}]}
        self.assertEqual(jsonschema_lite.validate_threat_composer(good), [])
        bad = {"schema": 1, "extra": 1, "threats": [{"id": U(), "numericId": "1",
                                                     "metadata": [{"key": "Bogus", "value": 1}]}]}
        errs = "\n".join(jsonschema_lite.validate_threat_composer(bad))
        self.assertIn("unrecognized key 'extra'", errs)
        self.assertIn("numericId: expected number", errs)
        self.assertIn("matches none of", errs)

    def test_unsupported_keyword_is_loud(self):
        with self.assertRaises(jsonschema_lite.UnsupportedSchema):
            jsonschema_lite.check_supported({"type": "object", "dependentRequired": {}})


class LintCommandTests(RepoTestCase):
    def test_rules_listed(self):
        self.assertEqual(self.tdd("lint", "--rules"), 0)
        for code in RULES:
            self.assertIn(code, self.last_out)

    def test_quality_warnings_and_strict(self):
        self.tdd("add-threat", "--source", "user", "--action", "read logs")
        self.tdd("add-mitigation", "--content", "Unlinked control")
        self.assertEqual(self.tdd("lint"), 0)  # warnings only
        for code in ("TDD130", "TDD131", "TDD132", "TDD120"):
            self.assertIn(code, self.last_out)
        self.assertEqual(self.tdd("lint", "--strict"), 1)
        self.assertEqual(self.tdd("lint", "--disable", "TDD130,TDD131,TDD132,TDD120"), 0)
        self.assertNotIn("TDD130", self.last_out)

    def test_config_disable(self):
        self.tdd("add-threat", "--source", "user", "--action", "read logs")
        cfg = self.read_json(".tdd/config.json")
        cfg["lint"] = {"disable": ["TDD130"]}
        self.write_json(".tdd/config.json", cfg)
        self.tdd("lint")
        self.assertNotIn("TDD130", self.last_out)
        self.assertIn("TDD131", self.last_out)

    def test_schema_only(self):
        path = "threats/demo.tc.json"
        data = self.read_json(path)
        data["threats"] = [{"id": U(), "numericId": 1, "statement": "s", "status": "threatResolved"}]
        self.write(path, json.dumps(data))
        self.assertEqual(self.tdd("lint"), 1)
        self.assertIn("TDD110", self.last_out)  # resolved without a strategy
        self.assertEqual(self.tdd("lint", "--schema-only"), 0)  # schema-valid, just unformatted
        self.assertIn("TC003", self.last_out)
        self.assertNotIn("TDD110", self.last_out)

    def test_official_schema_errors(self):
        path = "threats/demo.tc.json"
        data = self.read_json(path)
        data["workspace"] = {"id": U(), "name": "x"}  # the editor accepts it; the schema doesn't
        self.write_json(path, data)
        self.assertEqual(self.tdd("lint", "--schema-only"), 1)
        self.assertIn("TC001", self.last_out)

    def test_editor_refusal_stops_further_rules(self):
        self.write("threats/demo.tc.json", '{"schema": 1, "threats": [{"id": "x"}]}')
        self.assertEqual(self.tdd("lint"), 1)
        self.assertIn("TC002", self.last_out)
        self.assertNotIn("TDD1", self.last_out)

    def test_statement_drift_and_strategy_reason(self):
        self.tdd("add-threat", "--source", "user", "--action", "read logs")
        path = "threats/demo.tc.json"
        data = self.read_json(path)
        data["threats"][0]["statement"] = "something else"
        data["threats"][0]["tags"] = ["risk:accept"]
        self.write_json(path, data)
        self.tdd("lint")
        self.assertIn("TDD104", self.last_out)
        self.assertIn("TDD112", self.last_out)

    def test_schema_command(self):
        self.assertEqual(self.tdd("schema"), 0)
        self.assertIn("threat-composer-v1.schema.json", self.last_out)
        self.assertEqual(self.tdd("schema", "--print"), 0)
        self.assertEqual(json.loads(self.last_out)["$schema"], "https://json-schema.org/draft/2020-12/schema")


if __name__ == "__main__":
    unittest.main()
