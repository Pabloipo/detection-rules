# detection-rules

[![tests](https://github.com/Pabloipo/detection-rules/actions/workflows/tests.yml/badge.svg)](https://github.com/Pabloipo/detection-rules/actions/workflows/tests.yml)
[![Python](https://img.shields.io/badge/python-3.9%2B-blue)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/license-MIT-green)](LICENSE)

Reglas de detección [Sigma](https://github.com/SigmaHQ/sigma) mapeadas a [MITRE ATT&CK](https://attack.mitre.org/), cada una con muestras de log y un test que comprueba que detecta lo que debe (y solo eso).

No es una colección de reglas copiadas: cada regla trae la evidencia de que funciona. La idea es enseñar el razonamiento de detección, no solo el YAML.

## Estructura

```
rules/
  <plataforma>/<categoría>/<nombre>.yml   # la regla Sigma
tests/
  samples/<nombre>/match.json             # log(s) que SÍ debe detectar
  samples/<nombre>/nomatch.json           # log(s) que NO debe detectar (evita falsos positivos)
  test_rules.py                           # valida y prueba todas las reglas
```

`<nombre>` es el mismo para la regla y su carpeta de muestras, así se emparejan solos.

## Formato de una regla

Cada regla cumple cuatro cosas:

1. **Lógica Sigma** en un `.yml` con los campos estándar: `title`, `id` (UUID), `status`, `description`, `author`, `date`, `logsource`, `detection` (con `condition`) y `level`.
2. **Mapeo ATT&CK** en `tags`, con la táctica y la técnica. Ejemplo: `attack.execution`, `attack.t1059.001`.
3. **Muestras de log**: un `match.json` con eventos que deben disparar la regla y un `nomatch.json` con eventos parecidos pero benignos.
4. **Test**: `tests/test_rules.py` parsea la regla, comprueba que detecta cada evento de `match.json` y que no detecta ninguno de `nomatch.json`.

Ejemplo mínimo de regla:

```yaml
title: Whoami ejecutado por un proceso web
id: 00000000-0000-0000-0000-000000000000
status: experimental
description: whoami.exe lanzado por w3wp/httpd, típico de reconocimiento tras un webshell.
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

## Cómo validar

```bash
pip install -r requirements.txt   # solo PyYAML
python tests/test_rules.py
```

No necesita red ni claves. El harness lleva un pequeño matcher Sigma propio (offline) que parsea cada regla, la ejecuta contra `match.json` y `nomatch.json`, y falla si deja de detectar algo que debía o si salta con un evento benigno.

Subconjunto de Sigma que soporta el matcher: modificadores `contains`/`startswith`/`endswith`/`re`/`all`, comodines `*` y `?`, listas como OR (o AND con `|all`), y condiciones con `and`/`or`/`not`, paréntesis y `x of` (`1 of sel_*`, `all of them`, …).

## MITRE ATT&CK

Cada regla se etiqueta con su táctica (p. ej. `attack.execution`) y su técnica o subtécnica (p. ej. `attack.t1059.001`). Así se ve de un vistazo qué cubre el repo y dónde quedan huecos frente a la matriz ATT&CK.

## Licencia

MIT
