"""The bundled CWE dictionary, CWE tags on threats, and derived CWE tags on mitigations."""

import json
import unittest

from tests.helpers import RepoTestCase
from threat_tdd import cwe

PATH = "threats/demo.tc.json"


class DictionaryTests(unittest.TestCase):
    def test_loads_with_version_and_notice(self):
        self.assertRegex(cwe.version(), r"^CWE \d+\.\d+ \(\d{4}-\d{2}-\d{2}\)$")
        self.assertIn("MITRE", cwe._data()["notice"])
        self.assertGreater(len(cwe.entries()), 1000)

    def test_lookup(self):
        e = cwe.get(639)
        self.assertEqual(e["name"], "Authorization Bypass Through User-Controlled Key")
        self.assertEqual(e["usage"], "Allowed")
        self.assertIn(863, e["parents"])
        self.assertIn(566, cwe.children(639))
        self.assertEqual(cwe.url(639), "https://cwe.mitre.org/data/definitions/639.html")

    def test_parse_ref(self):
        for ref in ("CWE-639", "cwe-639", "639", " CWE639 "):
            self.assertEqual(cwe.parse_ref(ref), 639)
        with self.assertRaises(ValueError):
            cwe.parse_ref("IDOR")

    def test_problems(self):
        self.assertIsNone(cwe.problem(639))
        self.assertEqual(cwe.problem(99999)[0], "unknown")
        self.assertEqual(cwe.problem(1187)[0], "deprecated")
        self.assertIn("CWE-908", cwe.problem(1187)[1])
        self.assertEqual(cwe.problem(20)[0], "mapping")  # Class, Discouraged
        self.assertIn("more specific", cwe.problem(20)[1])
        self.assertEqual(cwe.problem(284)[0], "mapping")  # Pillar
        self.assertEqual(cwe.problem(1000)[0], "mapping")  # a view

    def test_search(self):
        cases = {
            "idor": 639,
            "cross site scripting": 79,
            "os command injection": 78,
            "sql injection": 89,
            "hardcoded password": 259,
            "missing authentication": 306,
            "CWE-352": 352,
        }
        for query, expected in cases.items():
            ids = [i for i, _ in cwe.search(query, 3)]
            self.assertIn(expected, ids, query)
        # broad and deprecated entries are left out by default
        self.assertNotIn(20, [i for i, _ in cwe.search("improper input validation", 20)])
        self.assertIn(20, [i for i, _ in cwe.search("improper input validation", 20, include_all=True)])

    def test_tag_ids(self):
        self.assertEqual(cwe.tag_ids({"tags": ["risk:mitigate", "CWE-79", "cwe-89", "CWE79", "check:x"]}), [79, 89])


class CweCommandTests(RepoTestCase):
    def threat(self, n=1):
        return [t for t in self.read_json(PATH)["threats"] if t["numericId"] == n][0]

    def mit(self, n=1):
        return [m for m in self.read_json(PATH)["mitigations"] if m["numericId"] == n][0]

    def setUp(self):
        super().setUp()
        self.tdd("add-threat", "--source", "tenant user", "--action", "read another tenant's invoices",
                 "--priority", "High", "--cwe", "639")
        self.tdd("add-threat", "--source", "visitor", "--action", "inject script into comments",
                 "--priority", "Low", "--cwe", "CWE-79")

    def test_add_threat_with_cwe(self):
        self.assertIn("CWE-639", self.threat(1)["tags"])
        self.assertEqual(self.tdd("add-threat", "--source", "x", "--action", "y", "--cwe", "99999"), 1)
        self.assertIn("not in CWE", self.last_err)

    def test_add_and_remove(self):
        self.assertEqual(self.tdd("cwe", "add", "--threat", "T-1", "CWE-566"), 0)
        self.assertEqual([t for t in self.threat(1)["tags"] if t.startswith("CWE-")], ["CWE-639", "CWE-566"])
        self.assertEqual(self.tdd("cwe", "add", "--threat", "T-1", "639"), 0)  # no duplicate
        self.assertEqual(self.threat(1)["tags"].count("CWE-639"), 1)
        self.tdd("cwe", "remove", "--threat", "T-1", "566")
        self.assertNotIn("CWE-566", self.threat(1)["tags"])

    def test_add_refuses_unsuitable_without_force(self):
        self.assertEqual(self.tdd("cwe", "add", "--threat", "T-1", "20"), 1)
        self.assertIn("Discouraged", self.last_err)
        self.assertEqual(self.tdd("cwe", "add", "--threat", "T-1", "1187"), 1)
        self.assertIn("deprecated", self.last_err)
        self.assertEqual(self.tdd("cwe", "add", "--threat", "T-1", "20", "--force"), 0)
        self.tdd("lint")
        self.assertIn("TDD162", self.last_out)

    def test_mitigations_derive_cwe_tags(self):
        self.tdd("add-mitigation", "--threat", "T-1", "--threat", "T-2", "--content", "Authorization middleware")
        self.assertEqual(self.mit()["tags"], ["CWE-79", "CWE-639", "priority:high"])
        self.tdd("cwe", "remove", "--threat", "T-2", "79")
        self.assertEqual(self.mit()["tags"], ["CWE-639", "priority:high"])
        self.assertEqual(self.tdd("lint"), 0, self.last_out)

    def test_stale_mitigation_cwe_is_an_error_and_sync_fixes_it(self):
        self.tdd("add-mitigation", "--threat", "T-1", "--content", "Authorization middleware")
        data = self.read_json(PATH)
        t1 = [t for t in data["threats"] if t["numericId"] == 1][0]
        t1["tags"].append("CWE-566")  # edited in the Threat Composer UI
        self.write_json(PATH, data)
        self.tdd("fmt")
        self.assertEqual(self.tdd("lint"), 1)
        self.assertIn("TDD151", self.last_out)
        self.tdd("sync", "--no-checks")
        self.assertIn("CWE tags CWE-639 -> CWE-566, CWE-639", self.last_out)
        self.assertEqual(self.tdd("lint"), 0, self.last_out)

    def test_lint_unknown_cwe_and_missing_cwe(self):
        self.tdd("add-threat", "--source", "bot", "--action", "scrape pages")
        data = self.read_json(PATH)
        [t for t in data["threats"] if t["numericId"] == 2][0]["tags"].append("CWE-99999")
        self.write_json(PATH, data)
        self.tdd("fmt")
        self.assertEqual(self.tdd("lint"), 1)
        self.assertIn("TDD160", self.last_out)
        self.assertIn("T-3 warning TDD163", self.last_out)

    def test_search_and_show_commands(self):
        self.assertEqual(self.tdd("cwe", "search", "idor"), 0)
        self.assertIn("CWE-639", self.last_out)
        self.assertEqual(self.tdd("cwe", "search", "zzzzqqq"), 1)
        self.assertEqual(self.tdd("cwe", "show", "639"), 0)
        self.assertIn("IDOR", self.last_out)
        self.assertEqual(self.tdd("cwe", "show", "99999"), 1)
        self.assertEqual(json.loads(self.tdd_out("cwe", "show", "639", "--json"))["id"], 639)

    def tdd_out(self, *args):
        self.tdd(*args)
        return self.last_out

    def test_git_tag_message_lists_weaknesses(self):
        from threat_tdd import tagging
        from threat_tdd.model import load_file
        self.tdd("add-mitigation", "--threat", "T-1", "--content", "Authorization middleware")
        model = load_file(self.root, PATH)
        msg = tagging.tag_message(model, model.mitigations[0])
        self.assertIn("Weaknesses: CWE-639: Authorization Bypass Through User-Controlled Key", msg)

    def test_status_shows_cwes(self):
        self.tdd("status")
        self.assertIn("[CWE-639]", self.last_out)
