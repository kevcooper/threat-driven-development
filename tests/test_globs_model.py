import unittest

from threat_tdd import globs
from threat_tdd.model import Model, compose_statement, empty_model, validate


class GlobTests(unittest.TestCase):
    def test_double_star(self):
        self.assertTrue(globs.match("threats/a.tc.json", "threats/**/*.tc.json"))
        self.assertTrue(globs.match("threats/x/y/a.tc.json", "threats/**/*.tc.json"))
        self.assertFalse(globs.match("other/a.tc.json", "threats/**/*.tc.json"))

    def test_basename_pattern_matches_any_depth(self):
        self.assertTrue(globs.match("README.md", "*.md"))
        self.assertTrue(globs.match("a/b/NOTES.md", "**/*.md"))
        self.assertFalse(globs.match("a/b/notes.py", "**/*.md"))

    def test_directory_pattern(self):
        self.assertTrue(globs.match("docs/x/y.png", "docs/**"))
        self.assertTrue(globs.match("docs/x.png", "docs/"))
        self.assertFalse(globs.match("src/docs.py", "docs/**"))


class ModelTests(unittest.TestCase):
    def test_statement_grammar(self):
        s = compose_statement("external actor", "with a stolen token", "call the admin API",
                              "privilege escalation", ["confidentiality", "integrity"], ["tenant data"])
        self.assertEqual(
            s,
            "An external actor with a stolen token can call the admin API, which leads to privilege "
            "escalation, resulting in reduced confidentiality and integrity of tenant data",
        )

    def test_add_and_link(self):
        m = Model("t.tc.json", empty_model("x"))
        t = m.add_threat("user", "", "do a thing", "", [], [])
        mit = m.add_mitigation("stop it", checks=["c1"])
        self.assertTrue(m.link(mit["id"], t["id"]))
        self.assertFalse(m.link(mit["id"], t["id"]))
        self.assertEqual(m.mitigations_for(t["id"]), [mit])
        self.assertIs(m.find_threat("T-1"), t)
        self.assertIs(m.find_threat("1"), t)
        self.assertIs(m.find_mitigation(mit["id"][:6]), mit)
        self.assertEqual(validate(m, ["c1"]), [])

    def test_validation_errors(self):
        m = Model("t.tc.json", {
            "threats": [{"id": "a", "statement": "s", "status": "threatResolvedNotUseful"},
                        {"id": "a", "statement": ""}],
            "mitigations": [{"id": "m", "content": "c", "tags": ["check:nope"]}],
            "mitigationLinks": [{"mitigationId": "m", "linkedId": "zzz"}],
        })
        msgs = [str(i) for i in validate(m, ["other"])]
        joined = "\n".join(msgs)
        self.assertIn("duplicate threat id a", joined)
        self.assertIn("no statement", joined)
        self.assertIn("no Comments", joined)
        self.assertIn("unknown threat zzz", joined)
        self.assertIn("references check 'nope'", joined)


if __name__ == "__main__":
    unittest.main()
