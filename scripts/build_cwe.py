#!/usr/bin/env python3
"""Build threat_tdd/data/cwe.json from MITRE's CWE XML (maintainer tool).

    curl -sSLo /tmp/cwe.zip https://cwe.mitre.org/data/xml/cwec_latest.xml.zip
    unzip -d /tmp/cwe /tmp/cwe.zip
    python3 -I scripts/build_cwe.py /tmp/cwe/cwec_v*.xml threat_tdd/data/cwe.json

Keeps what tdd needs to validate and look up CWE references: id, name, kind,
abstraction, status, MITRE's mapping usage (Allowed / Allowed-with-Review /
Discouraged / Prohibited), a short description, alternate terms, parents in the
Research Concepts view (CWE-1000), and for deprecated entries the CWEs their
description points to.
"""

import json
import re
import sys
import xml.etree.ElementTree as ET

RESEARCH_VIEW = "1000"
DESC_MAX = 400
NOTICE = (
    "Copyright (c) The MITRE Corporation. CWE is a trademark of The MITRE Corporation. "
    "CWE is free to use by any organization or individual for any research, development, "
    "and/or commercial purposes, per the CWE Terms of Use "
    "(https://cwe.mitre.org/about/termsofuse.html). The MITRE Corporation grants a "
    "non-exclusive, royalty-free license to use CWE for research, development, and "
    "commercial purposes. Any copy made for such purposes is authorized on the condition "
    "that MITRE's copyright designation and this license are reproduced in any such copy."
)


def text(el):
    return " ".join("".join(el.itertext()).split()) if el is not None else ""


def short(s, limit=DESC_MAX):
    return s if len(s) <= limit else s[: limit - 1].rsplit(" ", 1)[0] + "…"


def main(src, dst):
    root = ET.parse(src).getroot()
    ns = root.tag.split("}")[0] + "}"

    def find(el, path):
        return el.find("/".join(ns + p for p in path.split("/")))

    def usage(el):
        u = find(el, "Mapping_Notes/Usage")
        return u.text.strip() if u is not None and u.text else None

    entries = {}
    for w in root.find(ns + "Weaknesses"):
        desc = text(find(w, "Description"))
        parents = sorted({int(r.get("CWE_ID")) for r in w.iter(ns + "Related_Weakness")
                          if r.get("Nature") == "ChildOf" and r.get("View_ID") == RESEARCH_VIEW})
        alt = [text(find(a, "Term")) for a in w.iter(ns + "Alternate_Term")]
        entry = {
            "name": w.get("Name"),
            "kind": "weakness",
            "abstraction": w.get("Abstraction"),
            "status": w.get("Status"),
            "usage": usage(w),
            "description": short(desc),
        }
        if parents:
            entry["parents"] = parents
        if alt:
            entry["alternate_terms"] = [a for a in alt if a][:8]
        if w.get("Status") == "Deprecated":
            refs = sorted({int(x) for x in re.findall(r"CWE-(\d+)", desc + " " + w.get("Name", ""))}
                          - {int(w.get("ID"))})
            if refs:
                entry["see"] = refs
        entries[int(w.get("ID"))] = entry
    for kind, section in (("grouping", "Groupings"), ("view", "Views")):
        node = root.find(ns + section)
        for g in node if node is not None else []:
            entries[int(g.get("ID"))] = {
                "name": g.get("Name"),
                "kind": kind,
                "status": g.get("Status"),
                "usage": usage(g) or "Prohibited",
            }

    out = {
        "source": "https://cwe.mitre.org/data/xml/cwec_latest.xml.zip",
        "version": root.get("Version"),
        "date": root.get("Date"),
        "notice": NOTICE,
        "entries": {str(k): entries[k] for k in sorted(entries)},
    }
    with open(dst, "w", encoding="utf-8") as fh:
        json.dump(out, fh, ensure_ascii=False, separators=(",", ":"), sort_keys=False)
        fh.write("\n")
    print(f"wrote {dst}: CWE {out['version']} ({out['date']}), {len(entries)} entries")


if __name__ == "__main__":
    if len(sys.argv) != 3:
        sys.exit(__doc__)
    main(sys.argv[1], sys.argv[2])
