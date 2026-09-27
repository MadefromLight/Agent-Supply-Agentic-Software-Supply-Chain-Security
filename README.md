# Agent Supply

An agentic software supply-chain security scanner.

AI agents are compositions of code, packages, MCP servers, tools, skills, prompts, credentials and external services. Traditional dependency scanning does not describe the whole agent attack surface.

This MVP scans a local agent manifest for declared risk signals and emits structured findings.

## Checks
- wildcard permissions
- suspicious scripts
- credential-like strings
- loose dependency versions
- unpinned external tools

## Quick start
npm install
npm test
npm run build
npm run scan -- examples/demo-agent.json

This is a static risk scanner, not a malware detector. Findings are signals for review, not proof that a component is malicious or safe.

License: MIT
