# Vulnera Adapter (LSP)

The adapter is a stdio-based Language Server Protocol implementation that connects IDEs to Vulnera dependency analysis APIs.

It is designed for extension hosts (VS Code, JetBrains bridge layers, etc.) and provides:

- dependency vulnerability diagnostics
- quick-fix code actions based on safe version recommendations
- debounced workspace-batch analysis for low request overhead
- correlated request/response mapping with per-file IDs

## What it does

For supported dependency files, the adapter:

1. Tracks text document lifecycle events (`open`, `change`, `save`, `close`)
2. Applies incremental text changes in-memory
3. Debounces analysis by workspace
4. Sends one batch request to `/api/v1/dependencies/analyze`
5. Maps results back to files via `file_id` correlation
6. Publishes diagnostics and code actions

For unknown ecosystems, it avoids noisy false positives by skipping analysis and clearing stale diagnostics.

## Runtime behavior

### Synchronization mode

- `TextDocumentSyncKind::INCREMENTAL`
- Save includes full text (`save.include_text = true`)

This keeps editor traffic lower than full-document sync and prevents repeated full-buffer pushes.

### Batch + debounce

- Files are grouped by workspace key
- A single debounced task analyzes all dirty files in that workspace
- Per-file mapping uses `file_id` (`uri.to_string()`)

### Error surfacing

- Transport/server failures emit status notification (`show_message`)
- Transport/server failures emit in-file failure diagnostics when file context exists

## Configuration

You can configure the adapter using env vars and/or LSP initialize options.

### Environment variables

- `VULNERA_API_URL` (default: `http://localhost:3000`)
- `VULNERA_API_KEY` (sent as `X-API-Key`)
- `VULNERA_DETAIL_LEVEL` (`minimal|standard|full`)
- `VULNERA_COMPACT_MODE` (`true|false`)
- `VULNERA_ENABLE_CACHE` (`true|false`)
- `VULNERA_DEBOUNCE_MS` (default: `500`)

### Initialize options

Preferred for extension-hosted use:

```json
{
    "vulnera": {
        "apiUrl": "http://localhost:3000",
        "apiKey": "...",
        "detailLevel": "standard",
        "compactMode": false,
        "enableCache": true,
        "debounceMs": 500,
        "userAgent": "my-extension/1.0.0"
    }
}
```

## Module map

- `src/lsp.rs` — LSP server implementation and sync handling
- `src/state.rs` — document state, debounce scheduler, batch analysis pipeline
- `src/api.rs` — HTTP client + DTOs for dependency analysis endpoint
- `src/diagnostics.rs` — vulnerability/result to LSP diagnostics mapping
- `src/code_actions.rs` — quick-fix generation from version recommendations
- `src/package_locator.rs` — dependency version location helpers (regex cached via `once_cell`)
- `src/config.rs` — env + initialize options parsing

## Performance notes

- Dependency locator regexes are statically initialized (`once_cell::sync::Lazy`) to avoid per-request regex compilation overhead.
- Batch response mapping uses request correlation (`file_id`) to remain stable even with async completion reordering on the server.

## Development

From this directory:

- `cargo check`
- `cargo test`

From workspace root (cross-module validation):

- `cargo test --manifest-path adapter/Cargo.toml`

## Release model

Tag-based release is handled by GitHub Actions in `.github/workflows/release.yml`.

On tag push (`adapter-v*` or `v*`), pipeline runs:

1. `cargo test`
2. `cargo package --allow-dirty --no-verify`
3. checksum generation
4. GitHub Release publication with packaged `.crate` artifact

## Compatibility contract (current)

- Optional API auth uses `X-API-Key`
- Batch request supports `files[].file_id`
- Batch response includes `results[].file_id`
- Batch response includes `metadata.request_id`
