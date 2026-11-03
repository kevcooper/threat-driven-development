"""Threat Composer canonical form: what the VS Code extension would write back.

Expected values are derived from reading Threat Composer's source (sanitize-html with
allowedTags: [], strict zod schemas, useExportImport, the list views' in-place sorts,
renderThreatStatement) and the AWS Toolkit's vsCodeExtensionInterface.js.
"""

import json
import os
import unittest
import uuid

from tests.helpers import RepoTestCase
from threat_tdd import canonical
from threat_tdd.canonical import Uncertain, canonicalize, dumps, format_text, render_statement, sanitize_string

U = lambda: str(uuid.uuid4())  # noqa: E731


class SanitizeTests(unittest.TestCase):
    def test_plain_text_untouched(self):
        for s in ["", "plain text", 'quotes "ok" and it\'s fine', "unicode ✓ ünïcödé", "a = b; c: d"]:
            self.assertEqual(sanitize_string(s), s)

    def test_tags_stripped_content_kept(self):
        self.assertEqual(sanitize_string("check:<name> tags"), "check: tags")
        self.assertEqual(sanitize_string("x <b>bold</b> y"), "x bold y")
        self.assertEqual(sanitize_string("<br/>line"), "line")

    def test_entities_and_escaping(self):
        self.assertEqual(sanitize_string("a & b"), "a &amp; b")
        self.assertEqual(sanitize_string("1 < 2"), "1 &lt; 2")
        self.assertEqual(sanitize_string("> quote"), "&gt; quote")
        self.assertEqual(sanitize_string("&amp; &lt;b&gt;"), "&amp; &lt;b&gt;")
        self.assertEqual(sanitize_string("&copy; &#65; &#x42;"), "© A B")

    def test_idempotent(self):
        for s in ["a & b", "x <y> z", "> q", "&lt;tag&gt;", "1 < 2 > 0"]:
            once = sanitize_string(s)
            self.assertEqual(sanitize_string(once), once, s)

    def test_uncertain_constructs_are_not_guessed(self):
        for s in ["<script>x</script>", "<!-- c -->", "<a href='x'>y</a>", "<unclosed", "&bogus;", "AT&T"]:
            with self.assertRaises(Uncertain, msg=s):
                sanitize_string(s)


class StringifyTests(unittest.TestCase):
    def test_matches_json_stringify_layout(self):
        data = {"a": 1, "b": [], "c": {}, "d": [1, {"e": "✓\n\"x\""}], "f": 1.5, "g": True, "h": None}
        self.assertEqual(
            dumps(data),
            '{\n  "a": 1,\n  "b": [],\n  "c": {},\n  "d": [\n    1,\n    {\n      "e": "✓\\n\\"x\\""\n'
            '    }\n  ],\n  "f": 1.5,\n  "g": true,\n  "h": null\n}',
        )

    def test_js_numbers(self):
        cases = {1.0: "1", 0.5: "0.5", 1e-7: "1e-7", 0.000001: "0.000001", 1e21: "1e+21", 123456.789: "123456.789"}
        for value, text in cases.items():
            self.assertEqual(canonical._js_number(value), text)

    def test_control_chars(self):
        self.assertEqual(canonical._js_string("\x01\t"), '"\\u0001\\t"')


def _threat(n, **kw):
    return {"id": U(), "numericId": n, "statement": f"threat {n}", **kw}


class CanonicalizeTests(unittest.TestCase):
    def test_top_level_order_and_defaults(self):
        canon, r = canonicalize({"threats": [], "schema": 1, "workspace": {"id": U(), "name": "x"}})
        self.assertEqual(r.errors, [])
        self.assertEqual(list(canon), list(canonical.TOP_LEVEL_ORDER))
        self.assertEqual(canon["applicationInfo"], {})

    def test_entity_key_order_follows_schema(self):
        t = {"status": "threatIdentified", "statement": "s", "tags": [], "metadata": [], "numericId": 1, "id": U()}
        m = {"content": "c", "status": "mitigationIdentified", "id": U(), "numericId": 1}
        canon, _ = canonicalize({"schema": 1, "threats": [t], "mitigations": [m],
                                 "architecture": {"image": "", "description": "d"}})
        self.assertEqual(list(canon["threats"][0]), ["id", "numericId", "metadata", "tags", "statement", "status"])
        self.assertEqual(list(canon["mitigations"][0]), ["id", "numericId", "content", "status"])
        self.assertEqual(list(canon["architecture"]), ["description", "image"])

    def test_list_view_sorts(self):
        threats = [_threat(1), _threat(3), _threat(2)]
        mits = [{"id": U(), "numericId": i, "displayOrder": d, "content": str(i)}
                for i, d in [(1, 1), (2, None), (3, 3), (4, 0), (5, 2)]]
        for m in mits:
            if m["displayOrder"] is None:
                del m["displayOrder"]
        canon, _ = canonicalize({"schema": 1, "threats": threats, "mitigations": mits})
        self.assertEqual([t["numericId"] for t in canon["threats"]], [3, 2, 1])
        # missing / 0 displayOrder sort first (|| Number.MAX_VALUE), ties keep their order
        self.assertEqual([m["numericId"] for m in canon["mitigations"]], [2, 4, 3, 5, 1])

    def test_dropped_fields(self):
        t = _threat(1, displayedStatement=["x"])
        canon, _ = canonicalize({"schema": 1, "threats": [t], "brainstorm": {"assumptions": []}})
        self.assertNotIn("displayedStatement", canon["threats"][0])
        self.assertNotIn("brainstorm", canon)

    def test_refused_files(self):
        bad = [
            {"schema": 2},
            {"schema": 1, "extra": 1},
            {"schema": 1, "threats": [_threat(1, priority="High")]},
            {"schema": 1, "mitigations": [{"id": U(), "numericId": 1, "content": "c",
                                           "metadata": [{"key": "Priority", "value": "High"}]}]},
            {"schema": 1, "mitigations": [{"id": U(), "numericId": 1, "content": "c",
                                           "tags": ["check:" + "x" * 25]}]},
            {"schema": 1, "threats": [_threat(1, status="done")]},
            [],
        ]
        for data in bad:
            canon, r = canonicalize(data)
            self.assertIsNone(canon, data)
            self.assertTrue(r.errors)

    def test_custom_metadata_allowed(self):
        t = _threat(1, metadata=[{"key": "custom:owner", "value": "appsec"}, {"key": "STRIDE", "value": ["S"]}])
        canon, r = canonicalize({"schema": 1, "threats": [t]})
        self.assertEqual(r.errors, [])

    def test_markdown_vs_plain_text_rewrites(self):
        data = {"schema": 1, "applicationInfo": {"description": "> note"},
                "threats": [_threat(1, threatAction="read & write")]}
        canon, r = canonicalize(data)
        self.assertEqual(canon["applicationInfo"]["description"], "&gt; note")
        self.assertEqual(len(r.markdown_changes), 1)
        self.assertEqual(len(r.changes), 1)

    def test_fixed_point(self):
        data = {"mitigations": [{"content": "x", "numericId": 1, "id": U()}], "schema": 1,
                "threats": [_threat(2), _threat(5)]}
        first = format_text(json.dumps(data))
        second = format_text(first.text)
        self.assertTrue(first.changed)
        self.assertFalse(second.changed)
        self.assertFalse(first.text.endswith("\n"))


class RenderStatementTests(unittest.TestCase):
    def test_full_statement(self):
        t = {"threatSource": "external actor", "prerequisites": "with a token", "threatAction": "read data",
             "threatImpact": "disclosure", "impactedGoal": ["confidentiality", "integrity"],
             "impactedAssets": ["db", "logs"]}
        self.assertEqual(
            render_statement(t),
            "An external actor with a token can read data, which leads to disclosure, resulting in reduced "
            "confidentiality and/or integrity of db and logs",
        )

    def test_articles(self):
        for source, expected in [("user", "A user"), ("hour", "An hour"), ("SQL injector", "An SQL injector"),
                                 ("UFO", "A UFO"), ("8-bit actor", "An 8-bit actor"), ("insider", "An insider")]:
            self.assertTrue(render_statement({"threatSource": source, "threatAction": "act"}).startswith(expected),
                            source)

    def test_partial_statements(self):
        self.assertEqual(render_statement({}), "")
        self.assertEqual(render_statement({"threatAction": "do x"}), "...do x...")
        self.assertEqual(render_statement({"threatSource": "bot"}), "bot...")
        self.assertEqual(render_statement({"impactedAssets": ["db"]}), "...db")
        self.assertEqual(render_statement({"threatAction": "do x", "threatImpact": "y"}),
                         "A threat source can do x, which leads to y")

    def test_inline_article_correction(self):
        self.assertEqual(render_statement({"threatSource": "actor", "threatAction": "steal a API key"}),
                         "An actor can steal an API key")


class FmtCommandTests(RepoTestCase):
    def test_init_writes_canonical(self):
        self.assertEqual(self.tdd("fmt", "--check"), 0, self.last_out)

    def test_cli_edits_stay_canonical(self):
        self.add_green_threat()
        self.tdd("add-threat", "--source", "insider", "--action", "copy data")
        self.assertEqual(self.tdd("fmt", "--check"), 0, self.last_out)
        text = open(os.path.join(self.root, "threats/demo.tc.json"), encoding="utf-8").read()
        self.assertFalse(text.endswith("\n"))
        data = json.loads(text)
        self.assertEqual([t["numericId"] for t in data["threats"]], [2, 1])

    def test_fmt_rewrites_and_check_fails(self):
        path = "threats/demo.tc.json"
        data = self.read_json(path)
        self.write(path, json.dumps(data, indent=4, sort_keys=True) + "\n")
        self.assertEqual(self.tdd("fmt", "--check"), 1)
        self.assertEqual(self.tdd("fmt"), 0)
        self.assertIn("formatted", self.last_out)
        self.assertEqual(self.tdd("fmt", "--check"), 0)

    def test_fmt_refuses_invalid(self):
        self.write("threats/demo.tc.json", '{"schema": 1, "bogus": true}')
        self.assertEqual(self.tdd("fmt"), 1)
        self.assertIn("refuse", self.last_out)

    def test_cli_rejects_text_threat_composer_would_rewrite(self):
        self.assertEqual(self.tdd("add-threat", "--source", "user", "--action", "read & write"), 1)
        self.assertIn("&amp;", self.last_err)
        self.assertEqual(self.tdd("add-threat", "--source", "<role>", "--action", "x"), 1)
        self.assertEqual(self.tdd("add-threat", "--source", "user", "--action", "x"), 0)
        self.assertEqual(self.tdd("add-mitigation", "--threat", "T-1", "--content", "m",
                              "--check", "a-check-name-that-is-too-long"), 1)
        self.assertIn("at most 24", self.last_err)

    def test_ci_blocks_unformatted_model(self):
        self.add_green_threat()
        self.write("app.py", "changed\n")
        path = "threats/demo.tc.json"
        self.write(path, json.dumps(self.read_json(path), indent=4))
        self.git("add", "-A")
        self.git("commit", "-qm", "x")
        self.assertEqual(self.tdd("ci", "--base", "main", "--summary", "/dev/null"), 1)
        self.assertIn("canonical", self.last_out)
        self.tdd("fmt")
        self.git("commit", "-qam", "fmt")
        self.assertEqual(self.tdd("ci", "--base", "main", "--summary", "/dev/null"), 0, self.last_out)


if __name__ == "__main__":
    unittest.main()
