# CWE data

`cwe.json` is derived from the Common Weakness Enumeration (CWE™) list, version 5.0
(2026-10-28), downloaded from https://cwe.mitre.org/data/xml/cwec_latest.xml.zip and
trimmed by `scripts/build_cwe.py` to the fields tdd uses: id, name, kind, abstraction,
status, mapping usage, a shortened description, alternate terms, parents in the Research
Concepts view (CWE-1000), and replacement references for deprecated entries.

Copyright © The MITRE Corporation. CWE is a trademark of The MITRE Corporation.

## CWE Terms of Use

CWE™ is free to use by any organization or individual for any research, development,
and/or commercial purposes, per these CWE Terms of Use. Accordingly, The MITRE
Corporation hereby grants you a non-exclusive, royalty-free license to use CWE for
research, development, and commercial purposes. Any copy you make for such purposes is
authorized on the condition that you reproduce MITRE's copyright designation and this
license in any such copy.

Source: https://cwe.mitre.org/about/termsofuse.html

## Updating

```
curl -sSLo /tmp/cwe.zip https://cwe.mitre.org/data/xml/cwec_latest.xml.zip
unzip -d /tmp/cwe /tmp/cwe.zip
python3 -I scripts/build_cwe.py /tmp/cwe/cwec_v*.xml threat_tdd/data/cwe.json
```

Then update the version above and run the tests.
