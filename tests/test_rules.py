"""Valida las reglas Sigma del repo y las prueba contra sus muestras.

Uso: python tests/test_rules.py   (sin red ni claves)

- self_check(): prueba el motor de matching con casos inline.
- check_rules(): por cada rules/**/*.yml valida los campos obligatorios y
  comprueba que detecta TODOS los eventos de tests/samples/<nombre>/match.json
  y NINGUNO de nomatch.json.

Alcance del matcher (subconjunto de Sigma, suficiente para estas reglas):
modificadores contains/startswith/endswith/re/all, comodines * y ?, listas
como OR (o AND con |all), y condiciones con and/or/not, paréntesis y `x of`.
"""
import json
import re
import sys
from pathlib import Path

try:
    import yaml
except ImportError:
    sys.exit("Falta PyYAML: pip install -r requirements.txt")

ROOT = Path(__file__).resolve().parent.parent
RULES_DIR = ROOT / "rules"
SAMPLES_DIR = ROOT / "tests" / "samples"
REQUIRED = ["title", "id", "status", "description", "logsource", "detection", "level", "tags"]


def _wild(pattern):
    """Patrón Sigma con comodines * ? -> regex (sin distinguir mayúsculas)."""
    out = []
    for ch in pattern:
        out.append(".*" if ch == "*" else "." if ch == "?" else re.escape(ch))
    return re.compile("^" + "".join(out) + "$", re.IGNORECASE | re.DOTALL)


def _match_value(mods, pattern, actual):
    a, p = str(actual), str(pattern)
    if "re" in mods:
        return re.search(p, a, re.IGNORECASE) is not None
    if "contains" in mods:
        return p.lower() in a.lower()
    if "startswith" in mods:
        return a.lower().startswith(p.lower())
    if "endswith" in mods:
        return a.lower().endswith(p.lower())
    if "*" in p or "?" in p:
        return _wild(p).match(a) is not None
    return a.lower() == p.lower()


def _match_field(field_spec, value, event):
    name, *mods = field_spec.split("|")
    if name not in event:
        return False
    values = value if isinstance(value, list) else [value]
    reducer = all if "all" in mods else any          # |all exige todos; si no, cualquiera
    mods = [m for m in mods if m != "all"]
    return reducer(_match_value(mods, v, event[name]) for v in values)


def _match_search(spec, event):
    if isinstance(spec, list):
        if all(isinstance(x, dict) for x in spec):   # lista de mapas = OR
            return any(_match_search(m, event) for m in spec)
        blob = " ".join(str(v) for v in event.values()).lower()  # keywords
        return any(str(k).lower() in blob for k in spec)
    return all(_match_field(f, v, event) for f, v in spec.items())  # dict = AND


def _eval_condition(condition, results):
    def resolve_xof(m):
        quant, pat = m.group(1), m.group(2)
        rx = re.compile("^" + pat.replace("*", ".*") + "$")
        names = list(results) if pat == "them" else [n for n in results if rx.match(n)]
        vals = [results[n] for n in names]
        if quant == "all":
            ok = bool(vals) and all(vals)
        elif quant == "any":
            ok = any(vals)
        else:
            ok = sum(1 for v in vals if v) >= int(quant)
        return "True" if ok else "False"

    expr = re.sub(r"\b(all|any|\d+) of ([A-Za-z0-9_]+\*?)", resolve_xof, condition)
    if re.search(r"\bof\b", expr):                   # algún `x of` no reconocido
        raise ValueError(f"condición no soportada: {condition!r}")
    expr = re.sub(r"[A-Za-z_][A-Za-z0-9_]*",
                  lambda m: m.group(0) if m.group(0) in ("and", "or", "not", "True", "False")
                  else ("True" if results.get(m.group(0)) else "False"), expr)
    tokens = re.findall(r"\w+|[()]", expr)
    if not all(t in {"and", "or", "not", "True", "False", "(", ")"} for t in tokens):
        raise ValueError(f"condición no soportada: {condition!r}")
    return bool(eval(expr, {"__builtins__": {}}, {}))  # expr ya validada: solo bools y operadores


def matches(rule, event):
    det = rule["detection"]
    results = {k: _match_search(v, event) for k, v in det.items() if k != "condition"}
    return _eval_condition(det["condition"], results)


def self_check():
    r = {"detection": {
        "selection": {"Image|endswith": r"\whoami.exe", "ParentImage|endswith": r"\w3wp.exe"},
        "filter": {"User": "SYSTEM"},
        "condition": "selection and not filter"}}
    assert matches(r, {"Image": r"C:\Windows\System32\whoami.exe",
                       "ParentImage": r"C:\inetpub\w3wp.exe", "User": "web"})
    assert not matches(r, {"Image": r"...\whoami.exe", "ParentImage": r"...\w3wp.exe",
                           "User": "SYSTEM"})                      # lo filtra
    assert not matches(r, {"Image": r"...\cmd.exe", "ParentImage": r"...\explorer.exe",
                           "User": "web"})
    # lista = OR ; contains|all = AND
    r2 = {"detection": {"sel": {"CommandLine|contains|all": ["-enc", "-nop"]}, "condition": "sel"}}
    assert matches(r2, {"CommandLine": "powershell -nop -enc AAAA"})
    assert not matches(r2, {"CommandLine": "powershell -enc AAAA"})
    # x of  (con prefijo y comodín)
    r3 = {"detection": {"sel_a": {"EventID": 4625}, "sel_b": {"EventID": 4740},
                        "condition": "1 of sel_*"}}
    assert matches(r3, {"EventID": 4740})
    assert not matches(r3, {"EventID": 1})
    # comodín en el valor
    r4 = {"detection": {"sel": {"Image": r"*\powershell.exe"}, "condition": "sel"}}
    assert matches(r4, {"Image": r"C:\x\powershell.exe"})
    assert not matches(r4, {"Image": r"C:\x\pwsh.exe"})
    print("self-check OK")


def _load(path):
    if not path.exists():
        return None
    data = json.loads(path.read_text(encoding="utf-8"))
    return data if isinstance(data, list) else [data]


def check_rules():
    rules = sorted(RULES_DIR.rglob("*.yml"))
    if not rules:
        print("No hay reglas todavía (0).")
        return 0
    for path in rules:
        rule = yaml.safe_load(path.read_text(encoding="utf-8"))
        name = path.stem
        missing = [f for f in REQUIRED if f not in rule]
        assert not missing, f"{name}: faltan campos {missing}"
        assert "condition" in rule["detection"], f"{name}: detection sin condition"
        assert any(str(t).startswith("attack.") for t in (rule.get("tags") or [])), \
            f"{name}: sin tag attack.*"
        match = _load(SAMPLES_DIR / name / "match.json")
        nomatch = _load(SAMPLES_DIR / name / "nomatch.json")
        assert match, f"{name}: falta tests/samples/{name}/match.json con eventos"
        assert nomatch is not None, f"{name}: falta tests/samples/{name}/nomatch.json"
        for ev in match:
            assert matches(rule, ev), f"{name}: debería detectar {ev}"
        for ev in nomatch:
            assert not matches(rule, ev), f"{name}: falso positivo con {ev}"
        print(f"OK {name}  ({len(match)} match / {len(nomatch)} nomatch)")
    print(f"\n{len(rules)} regla(s) validada(s).")
    return len(rules)


if __name__ == "__main__":
    self_check()
    check_rules()
    print("OK")
