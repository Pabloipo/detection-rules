# detection-rules

[![tests](https://github.com/Pabloipo/detection-rules/actions/workflows/tests.yml/badge.svg)](https://github.com/Pabloipo/detection-rules/actions/workflows/tests.yml)
[![Python](https://img.shields.io/badge/python-3.9%2B-blue)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/license-MIT-green)](LICENSE)

Detection rules in [Sigma](https://github.com/SigmaHQ/sigma) mapped to [MITRE ATT&CK](https://attack.mitre.org/), each one shipping log samples and a test that proves it detects what it should (and nothing else).

This is not a dump of copied rules: every rule comes with the evidence that it works. The goal is to show detection reasoning, not just YAML.

## Structure

```
rules/
  <platform>/<category>/<name>.yml   # the Sigma rule
tests/
  samples/<name>/match.json          # log(s) it SHOULD detect
  samples/<name>/nomatch.json        # benign log(s) it should NOT detect (guards against false positives)
  test_rules.py                      # validates and tests every rule
```

`<name>` is shared by the rule and its samples folder, so they pair up automatically.

## Rule format

Every rule does four things:

1. **Sigma logic** in a `.yml` with the standard fields: `title`, `id` (UUID), `status`, `description`, `author`, `date`, `logsource`, `detection` (with `condition`) and `level`.
2. **ATT&CK mapping** in `tags`, with tactic and technique. Example: `attack.execution`, `attack.t1059.001`.
3. **Log samples**: a `match.json` with events that must trigger the rule and a `nomatch.json` with similar but benign events.
4. **Test**: `tests/test_rules.py` parses the rule, checks it detects every event in `match.json` and none in `nomatch.json`.

Minimal rule example:

```yaml
title: Whoami executed by a web server process
id: 00000000-0000-0000-0000-000000000000
status: experimental
description: whoami.exe spawned by w3wp/httpd, typical reconnaissance after a webshell.
author: Pablo Iglesias Pose
date: 2026/10/28
logsource:
  product: windows
  category: process_creation
detection:
  selection:
    Image|endswith: '\whoami.exe'
    ParentImage|endswith: '\w3wp.exe'
  condition: selection
level: high
tags:
  - attack.discovery
  - attack.t1033
```

## How to validate

```bash
pip install -r requirements.txt   # just PyYAML
python tests/test_rules.py
```

No network or API keys needed. The harness ships a small self-contained Sigma matcher (offline) that parses each rule, runs it against `match.json` and `nomatch.json`, and fails if a rule stops detecting what it should or fires on a benign event.

Sigma subset supported by the matcher: `contains`/`startswith`/`endswith`/`re`/`all` modifiers, `*` and `?` wildcards, lists as OR (or AND with `|all`), and conditions with `and`/`or`/`not`, parentheses and `x of` (`1 of sel_*`, `all of them`, …).

## MITRE ATT&CK

Every rule is tagged with its tactic (e.g. `attack.execution`) and its technique or sub-technique (e.g. `attack.t1059.001`), so you can see at a glance what the repo covers and where the gaps are against the ATT&CK matrix.

## License

MIT
