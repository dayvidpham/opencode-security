# opencode-security

Security filter for OpenCode AI agent tool execution. Intercepts tool calls and blocks access to sensitive files using specificity-based pattern matching.

## Components

### opencode-security-filter (Python)

CLI tool that checks file paths against security patterns.

```bash
cd opencode-security-filter
uv pip install -e .
opencode-security-filter --check "/path/to/file"
```

### opencode-plugin (TypeScript)

OpenCode plugin that intercepts tool execution, extracts file paths from bash AST, and checks them against the security filter.

```bash
cd opencode-plugin
npm install
npm test
```

## Development

```bash
# Python tests
cd opencode-security-filter
uv run pytest

# TypeScript tests
cd opencode-plugin
npm test
```
