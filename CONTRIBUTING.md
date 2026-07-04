# Contributing to agentsigs

agentsigs is only as good as its coverage, and coverage is a community effort. The most valuable
contribution is **a new signature** — a real, named AI-agent attack pattern.

## Add a signature
See [docs/signature-format.md](docs/signature-format.md). In short: add a JSON object to the right
category file under `agentsigs/signatures/`, give it a unique id, a bounded regex, a severity, and a
MITRE ATLAS + OWASP LLM mapping. Then add a test proving it fires on a malicious sample and stays
quiet on a benign one.

## Ground rules
- **Real threats only.** Every signature maps to a genuine, explainable attack. No filler.
- **Low false-positive.** The suite enforces that benign text doesn't trip critical/high signatures.
- **Bounded regex.** No unbounded `.*` across newlines.
- **Deterministic + stdlib.** No dependencies, no network.

## Run it
```bash
pip install -e ".[dev]"
pytest -q
agentsigs stats
```

Seen a new attack in the wild? Bring it to [Discussions](https://github.com/cognis-digital/agentsigs/discussions) — good ones ship with your credit.
