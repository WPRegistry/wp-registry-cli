# WP Registry

A WP-CLI plugin that checks your WordPress site against [WP Registry](https://wpregistry.io), a public database of hashed WordPress plugins, themes, and files.

Every component in the registry has been reviewed for vulnerabilities, malware, and maintenance status. Each entry is identified by a SHA-256 hash of its contents, so two sites running the same code share the same verdict.

## How it works

1. The plugin hashes your installed plugins, themes, and loose PHP files locally.
2. Each hash is checked against the registry: `clean`, `low`, `medium`, `high`, `critical`, `malware`, or `unaudited`.
3. If your copy has been modified, the hash will not match a known build and the component is reported as `unaudited` rather than falsely marked clean.

No file contents, site URL, or user data leaves your site. Only hashes, slugs, and versions.

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
? jenga-starter      0f0e0d0c0b0a  unaudited

Scanned 12 components in 3s: 1 critical, 1 high, 8 clean, 2 unaudited
WP Registry: 83% coverage (10/12 audited)
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

## Statuses

| Status      | Meaning                                              |
|-------------|------------------------------------------------------|
| `clean`     | Audited, no issues found                             |
| `low`       | Minor issues, informational                          |
| `medium`    | Meaningful issues (e.g. abandoned, weak practices)   |
| `high`      | Significant vulnerability                            |
| `critical`  | Immediately exploitable or actively dangerous        |
| `malware`   | Confirmed malicious code                             |
| `unaudited` | Not yet in the registry                              |

## Why hash-based?

The plugin computes a SHA-256 of the actual files on disk. The version string in a plugin header can be forged or out-of-date; the hash cannot.

- **Modified code is flagged.** If malware was injected into a plugin on your server, the hash will not match any known-clean build. The component is reported `unaudited` rather than falsely marked clean.
- **Identical code is deduplicated.** A plugin audited on one site automatically covers every other site running the same build.
- **Premium plugins work too.** Plugins not on WordPress.org can still be checked, as long as the same build has been audited somewhere.

## Public API

The plugin reads from a small set of public JSON endpoints at `https://wpregistry.io`. You can hit them directly for your own tooling.

| Endpoint                       | Description                                         |
|--------------------------------|-----------------------------------------------------|
| `/manifest.json`               | Available patches for vulnerable components        |
| `/plugins-hashes.json`         | All audited plugin hashes                          |
| `/themes-hashes.json`          | All audited theme hashes                           |
| `/mu-plugins-hashes.json`      | All audited mu-plugin hashes                       |
| `/files-hashes.json`           | All audited loose-file hashes                      |

Each manifest is shaped:

```json
{
  "generated": "2026-05-09T01:10:10+00:00",
  "type": "plugins",
  "count": 5032,
  "hashes": {
    "a1b2c3d4...": {
      "slug": "flavor-jenga",
      "version": "2.1.0",
      "status": "critical",
      "key_issue": "Unauthenticated file upload via AJAX handler",
      "findings": 3
    }
  }
}
```

## Privacy

The plugin sends component slugs, versions, and content hashes to the registry. It does not send your site URL, file contents, user data, or any other identifying information. Hashes are one-way; your code cannot be reconstructed from them.

## License

MIT
