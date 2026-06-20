# Changelog

## 1.2.0 — 2026-06-20

### Changed

- **`check`** now reports `update` for a build the WP Registry has flagged
  **outdated** — a newer version exists — and this verdict overrides your site's
  own update check, which is exactly the data that can be stale. So a build that
  was uploaded for audit but is already superseded shows as `update` (update it)
  instead of lingering as `in queue` or `unaudited`.
- **`upload`** skips builds the registry already knows are outdated, so a stale
  local update check can't re-queue a dead build.

## 1.1.0 — 2026-06-20

### Added

- **`wp registry upload [<target>]`** — upload a not-yet-audited build to the
  registry's audit queue. Only components that are unaudited, not already queued,
  and on the **latest installed version** are accepted; an out-of-date build is
  skipped (update it first rather than queueing a build that's about to change).
  Pass `type/slug` (e.g. `plugin/akismet`) or a bare slug to upload a single
  component, or omit the target to upload everything eligible. `--dry-run`
  previews without uploading. The upload is re-hashed and validated server-side,
  so only genuine plugin/theme builds are accepted.
- **`check` reports two more states:**
  - `update` — the installed build isn't audited and WordPress reports a newer
    version is available (so update it rather than upload it).
  - `in queue` — this exact build has already been uploaded and is awaiting
    audit.
- `update` and `in queue` now sort above plain `unaudited` in the results.

### Changed

- **`check` no longer downloads the full hash manifests.** It now looks up only
  the hashes your site actually has, via prefix-sharded, edge-cached lookups
  (`/hashes/<prefix>.json`) — far less bandwidth, always fresh, and audit + queue
  state come from a single read so they can never disagree.
- A build that gets audited automatically leaves the `in queue` state on your
  next `check` — no stale "awaiting audit" labels.

## 1.0.0 — 2026-05-12

### Added

- Initial release.
- **`wp registry check`** — hashes every installed plugin, theme, and loose PHP
  file and reports each against the registry as `clean`, `low`, `medium`,
  `high`, `critical`, `malware`, or `unaudited`. Supports `--type`, `--details`,
  and `--format=json`.
- **`wp registry show <slug>`** — full recorded findings for a single component
  (severity, vulnerability type, file location, code snippet, recommendation).
- **`wp registry update`** — installs patched versions for vulnerable components
  that have a patch published in the registry. Supports `--dry-run`.
- Hash-based identity (SHA-256 of on-disk files) so modified code is flagged
  `unaudited` instead of being falsely marked clean, and identical builds are
  deduplicated across sites.
- Self-update from GitHub releases.
