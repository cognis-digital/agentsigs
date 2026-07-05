# agentsigs has moved into shrike

The AI-threat signature library (prompt injection, jailbreaks, tool poisoning, exfiltration,
obfuscation — mapped to MITRE ATLAS + OWASP LLM Top 10) now ships **inside
[shrike](https://github.com/cognis-digital/shrike)**, the autonomous security agent for your AI stack.

```bash
pip install shrike-sec
shrike sigs ./prompts        # scan text/files against the signature library
shrike sigs --list           # every signature + its ATLAS/OWASP mapping
```

shrike also runs these signatures automatically over your MCP tool descriptions during `shrike audit`.

This repository is **archived (read-only)**. All development continues in
[shrike](https://github.com/cognis-digital/shrike) — nothing was lost; the signatures live in
[`shrike/signatures/`](https://github.com/cognis-digital/shrike/tree/main/shrike/signatures).
