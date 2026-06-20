# WP Registry

A WP-CLI plugin that checks your WordPress site against [WP Registry](https://wpregistry.io), a public database of hashed WordPress plugins, themes, and files.

Every component in the registry has been reviewed for vulnerabilities, malware, and maintenance status. Each entry is identified by a SHA-256 hash of its contents, so two sites running the same code share the same verdict.

## How it works

1. The plugin hashes your installed plugins, themes, and loose PHP files locally.
2. It looks up only those hashes against the registry and reports each one: `clean`, `low`, `medium`, `high`, `critical`, `malware`, `update`, `in queue`, or `unaudited`.
3. If your copy has been modified, the hash will not match a known build and the component is reported as `unaudited` rather than falsely marked clean.
4. Anything still `unaudited` can be uploaded for review with `wp registry upload`.

Only content hashes leave your site for a check — sent as short, shared prefixes (see [Privacy](#privacy)). No file contents, site URL, or user data. Uploading a build sends that one build's code for review.

## Install

```bash
wp plugin install https://github.com/WPRegistry/wp-registry/releases/latest/download/wp-registry.zip --force --activate
```

## Usage

### Survey this site

```bash
wp registry check
```

```
Plugins (12)
  Name                Hash          Audit
⚠ flavor-jenga       a1b2c3d4e5f6  critical
⚠ jenga-toolkit      f6e5d4c3b2a1  high
✓ akismet            1234567890ab  clean
✓ contact-form-7     ba0987654321  clean
↑ jenga-pro          9a8b7c6d5e4f  update
… jenga-blocks       1f2e3d4c5b6a  in queue
? jenga-starter      0f0e0d0c0b0a  unaudited

Scanned 12 components in 3s: 2 vulnerable, 7 clean, 1 update, 1 in queue, 1 unaudited
WP Registry: 75% coverage (9/12 audited)
```

### Filter by type

```bash
wp registry check --type=plugins
wp registry check --type=themes
wp registry check --type=files
```

### Append each component's key issue

```bash
wp registry check --details
```

### Machine-readable output

```bash
wp registry check --format=json
```

### Inspect one component

Show every recorded finding (severity, vulnerability type, file location, code snippet, recommendation) for a single installed plugin or theme.

```bash
wp registry show elementor-pro
wp registry show twentytwentyfive --type=theme
wp registry show elementor-pro --format=json
```

### Apply security patches

If a vulnerable component has a patched version available in the registry, `update` installs it.

```bash
wp registry update              # apply available patches
wp registry update --dry-run    # preview without changes
```

### Upload unaudited components for review

If `check` shows components as `unaudited`, you can upload them to the registry's
audit queue. Only builds that are unaudited, not already queued, and on their
latest installed version are sent — an out-of-date build is skipped (update it
first). The upload is re-hashed and validated server-side, so only genuine
plugin/theme builds are accepted.

```bash
wp registry upload                       # upload every unaudited, latest-version build
wp registry upload plugin/jenga-starter  # upload one component (type/slug, or a bare slug)
wp registry upload --dry-run             # preview what would be uploaded
```

An uploaded build shows as `in queue` until it's audited, after which `check`
reports its real verdict.

## Statuses

| Status      | Meaning                                              |
|-------------|------------------------------------------------------|
| `clean`     | Audited, no issues found                             |
| `low`       | Minor issues, informational                          |
| `medium`    | Meaningful issues (e.g. abandoned, weak practices)   |
| `high`      | Significant vulnerability                            |
| `critical`  | Immediately exploitable or actively dangerous        |
| `malware`   | Confirmed malicious code                             |
| `update`    | Not audited at this build, and a newer version is available — update rather than upload |
| `in queue`  | Uploaded and awaiting audit                          |
| `unaudited` | Not in the registry, on the latest version — upload it for review |

## Why hash-based?

The plugin computes a SHA-256 of the actual files on disk. The version string in a plugin header can be forged or out-of-date; the hash cannot.

- **Modified code is flagged.** If malware was injected into a plugin on your server, the hash will not match any known-clean build. The component is reported `unaudited` rather than falsely marked clean.
- **Identical code is deduplicated.** A plugin audited on one site automatically covers every other site running the same build.
- **Premium plugins work too.** Plugins not on WordPress.org can still be checked, as long as the same build has been audited somewhere.

## Public API

Everything the plugin talks to is public at `https://wpregistry.io`, so you can build your own tooling on the same endpoints.

| Endpoint | Used by | Description |
|---|---|---|
| `/hashes/<prefix>.json` | `check` | Every audited (and queued) hash starting with a 1–6 hex-char prefix. The plugin groups its hashes by prefix and fetches only the shards it needs, so each lookup stays small and edge-cacheable. |
| `/upload?slug=&version=&type=&hash=` | `upload` | `POST` a plugin/theme `.zip` to the audit queue (re-hashed and validated server-side). |
| `/manifest.json` | `update` | Available patches for vulnerable components. |

A prefix shard is shaped:

```json
{
  "prefix": "a1b",
  "generated": "2026-06-20T01:10:10+00:00",
  "count": 12,
  "hashes": {
    "a1b2c3d4...": {
      "audited": true,
      "status": "critical",
      "malware": false,
      "slug": "flavor-jenga",
      "version": "2.1.0",
      "key_issue": "Unauthenticated file upload via AJAX handler"
    },
    "a1bf00d...": { "audited": false, "in_queue": true }
  }
}
```

The full per-type manifests (`/plugins-hashes.json`, `/themes-hashes.json`, `/mu-plugins-hashes.json`, `/files-hashes.json`) are still published if you'd rather pull everything at once.

## Privacy

A `check` sends only short **prefixes** of your content hashes. The registry returns every audited hash sharing each prefix and the match happens on your machine, so the registry never learns your exact hashes — and never sees your site URL, file contents, user data, or any other identifying information.

`upload` is the deliberate exception: it sends the build's `.zip` (a plugin or theme you chose to upload for review) along with its slug, version, and hash. `update` only downloads the public patch manifest.

Hashes are one-way; your code cannot be reconstructed from them.

## License

MIT
