# adapter

Vulnera LSP Server for IDE extensions.

## Overview

This adapter hosts a Language Server Protocol (LSP) implementation that calls
`/api/v1/dependencies/analyze` and surfaces:

- diagnostics for vulnerable dependencies
- code actions for version recommendations (nearest safe, latest safe, next safe minor)

The server defaults to `detail_level=standard` while allowing the client to
override it via initialization options.

## Architecture

Key modules:

- `config`: resolves configuration from environment + LSP initialization options
- `api`: typed client for `/api/v1/dependencies/analyze`
- `diagnostics`: maps vulnerabilities to LSP diagnostics
- `code_actions`: maps recommendations to LSP code actions
- `state`: document tracking, debounce, and analysis cache
- `lsp`: `tower-lsp` server implementation

## Configuration

Environment variables (optional):

- `VULNERA_API_URL` (default: `http://localhost:3000`)
- `VULNERA_API_KEY` (X-API-Key header)
- `VULNERA_DETAIL_LEVEL` (`minimal|standard|full`)
- `VULNERA_COMPACT_MODE` (`true|false`)
- `VULNERA_ENABLE_CACHE` (`true|false`)
- `VULNERA_DEBOUNCE_MS` (default: `500`)

LSP initialization options (preferred for IDEs):

```json
{
 "vulnera": {
  "apiUrl": "http://localhost:3000",
  "apiKey": "...",
  "detailLevel": "standard",
  "compactMode": false,
  "enableCache": true,
  "debounceMs": 500
 }
}
```

## Integration Notes

- The adapter is designed to be launched by IDE extensions over stdio.
- Code actions emit edits when the dependency version can be located; otherwise,
 they emit a `vulnera.applyRecommendation` command with recommendation data.
