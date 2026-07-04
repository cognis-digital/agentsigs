# Signature format

A signature is one entry in a category file under [`agentsigs/signatures/`](../agentsigs/signatures).
Each file is plain JSON — no YAML, no dependencies — so anyone can add a detection with a text editor.

## File shape

```json
{
  "category": "prompt_injection",
  "description": "One line on what this category covers.",
  "atlas": "AML.T0051",
  "owasp": "LLM01",
  "signatures": [
    {
      "id": "PI001",
      "severity": "high",
      "name": "Ignore previous instructions",
      "pattern": "(?i)\\b(ignore|disregard)\\b[^.\\n]{0,40}\\b(previous|prior)\\b[^.\\n]{0,20}\\binstructions?\\b"
    }
  ]
}
```

The category-level `atlas` / `owasp` are inherited by every signature in the file; a signature may
override them with its own `atlas` / `owasp` fields.

## Fields

| Field | Required | Notes |
|---|:---:|---|
| `id` | ✅ | Stable, unique, prefixed per category (`PI###`, `JB###`, `TP###`, `EX###`, `OB###`). |
| `severity` | ✅ | `critical` / `high` / `medium` / `low` / `info`. |
| `name` | ✅ | Short human label shown in output. |
| `pattern` | ✅ | A Python `re` regex. Use `(?i)` for case-insensitive. Bound your quantifiers (`{0,40}`) to avoid catastrophic backtracking. |
| `atlas` | — | A real [MITRE ATLAS](https://atlas.mitre.org) technique ID. Inherited if omitted. |
| `owasp` | — | An [OWASP LLM Top 10](https://genai.owasp.org) category. Inherited if omitted. |

## Quality bar

1. **Real, named threat.** Every signature must map to a genuine, explainable attack pattern — no filler.
2. **Low false-positive.** Test against benign text; a well-formed tool description or normal prompt
   must not trip a critical/high signature. The suite enforces this (`test_no_false_positive_on_benign`).
3. **Bounded regex.** No unbounded `.*` across newlines; keep patterns fast on large inputs.
4. **Mapped.** Provide (or inherit) an ATLAS technique and an OWASP category.

## Add one

1. Add the object to the right category file (or create a new category file with the shape above).
2. Run `agentsigs stats` (it loads) and `agentsigs list -c <category>` (it shows).
3. Add a detection test in `tests/` proving it fires on a malicious sample and not on a benign one.
4. `pytest -q`, then open a PR. New categories are welcome — the engine loads any `*.json` in the dir.
