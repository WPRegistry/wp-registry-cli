<?php

namespace WPRegistry;

class Command {

	private const API_BASE = 'https://wpregistry.io';

	// Prefix length for the sharded hash lookup. 3 hex chars over the ~48k-hash
	// registry is ~12 hashes/bucket — light bandwidth with meaningful k-anonymity.
	// Raise toward 5 for less bandwidth (≈per-hash, ~no anonymity); lower for more.
	private const SHARD_PREFIX_LEN = 3;

	private const SEVERITY_ORDER = [
		'malware'   => 6,
		'critical'  => 5,
		'high'      => 4,
		'medium'    => 3,
		'low'       => 2,
		'clean'     => 1,
		'update'    => -1,
		'in queue'  => -2,
		'unaudited' => -3,
	];

	/**
	 * Check your site against the WP Registry.
	 *
	 * Hashes all plugins, themes, and loose files locally, then compares
	 * against the public audit database. No data leaves your site.
	 *
	 * Default output is a clean table of every component. Use --details to
	 * include each component's key issue inline.
	 *
	 * ## OPTIONS
	 *
	 * [--type=<type>]
	 * : Check a specific component type. Accepts: plugins, themes, files, all.
	 * ---
	 * default: all
	 * ---
	 *
	 * [--details]
	 * : Append each component's key_issue summary alongside the audit verdict.
	 *
	 * [--format=<format>]
	 * : Output format. Accepts: table, json.
	 * ---
	 * default: table
	 * ---
	 *
	 * ## EXAMPLES
	 *
	 *     wp registry check
	 *     wp registry check --details
	 *     wp registry check --type=plugins
	 *     wp registry check --format=json
	 *
	 * @when after_wp_load
	 */
	public function check( $args, $assoc_args ) {
		$type    = $assoc_args['type'] ?? 'all';
		$format  = $assoc_args['format'] ?? 'table';
		$details = isset( $assoc_args['details'] );
		$start  = microtime( true );

		// Hash the site locally, then do ONE batch lookup against the registry
		// instead of downloading the full *-hashes.json manifests. Audit status and
		// queue state come back together from a single read, so they can't disagree
		// (no "in queue" flicker), and only the site's own hashes leave — never URLs
		// or file contents. The "update" label still comes from WordPress's own
		// local update transient.
		$scan = [];
		if ( $type === 'all' || $type === 'plugins' ) {
			\WP_CLI::log( 'Scanning plugins...' );
			$scan['plugin'] = Hasher::hash_plugins();
		}
		if ( $type === 'all' || $type === 'themes' ) {
			\WP_CLI::log( 'Scanning themes...' );
			$scan['theme'] = Hasher::hash_themes();
		}
		if ( $type === 'all' || $type === 'files' ) {
			\WP_CLI::log( 'Scanning loose files...' );
			$scan['file'] = Hasher::hash_loose_files();
		}

		$all_hashes = [];
		foreach ( $scan as $map ) {
			foreach ( $map as $hash ) {
				$all_hashes[] = $hash;
			}
		}
		$lookup = self::lookup_hashes( $all_hashes );

		self::refresh_update_data();
		$updates = [
			'plugin' => self::slugs_with_updates( 'plugin' ),
			'theme'  => self::slugs_with_updates( 'theme' ),
		];

		$results = [];
		foreach ( $scan as $ctype => $map ) {
			foreach ( $map as $slug => $hash ) {
				$results[] = self::resolve_component( $ctype, $slug, $hash, $lookup, $updates[ $ctype ] ?? [] );
			}
		}

		// Sort: malware first, then by severity desc, then alphabetical
		usort( $results, function ( $a, $b ) {
			$sa = ! empty( $a['malware'] ) ? 'malware' : $a['status'];
			$sb = ! empty( $b['malware'] ) ? 'malware' : $b['status'];
			$diff = ( self::SEVERITY_ORDER[ $sb ] ?? 0 ) - ( self::SEVERITY_ORDER[ $sa ] ?? 0 );
			return $diff !== 0 ? $diff : strcmp( $a['slug'], $b['slug'] );
		} );

		// Count summary. "unaudited" now means specifically uploadable (latest
		// version, not already queued); "update" and "queued" split off from it.
		$summary = [ 'clean' => 0, 'vulnerable' => 0, 'malware' => 0, 'unaudited' => 0, 'update' => 0, 'queued' => 0 ];
		foreach ( $results as $r ) {
			if ( ! empty( $r['malware'] ) ) {
				$summary['malware']++;
			} elseif ( $r['status'] === 'unaudited' ) {
				$summary['unaudited']++;
			} elseif ( $r['status'] === 'update' ) {
				$summary['update']++;
			} elseif ( $r['status'] === 'in queue' ) {
				$summary['queued']++;
			} elseif ( $r['status'] === 'clean' ) {
				$summary['clean']++;
			} else {
				$summary['vulnerable']++;
			}
		}

		if ( $format === 'json' ) {
			$audited_count  = $summary['clean'] + $summary['vulnerable'] + $summary['malware'];
			$total_count    = count( $results );
			$coverage_pct   = $total_count > 0 ? round( $audited_count / $total_count * 100 ) : 100;
			$summary['coverage'] = $coverage_pct;
			echo json_encode( [ 'results' => $results, 'summary' => $summary ], JSON_PRETTY_PRINT ) . "\n";
			return;
		}

		\WP_CLI::log( '' );
		if ( $details ) {
			self::render_details( $results );
		} else {
			self::render_table( $results );
		}

		// Summary
		$elapsed = round( microtime( true ) - $start, 1 );
		$total   = count( $results );
		\WP_CLI::log( '' );

		$parts = [];
		if ( $summary['malware'] > 0 )     $parts[] = \WP_CLI::colorize( "%1 {$summary['malware']} malware %n" );
		if ( $summary['vulnerable'] > 0 )  $parts[] = \WP_CLI::colorize( "%r{$summary['vulnerable']} vulnerable%n" );
		if ( $summary['clean'] > 0 )       $parts[] = \WP_CLI::colorize( "%g{$summary['clean']} clean%n" );
		if ( $summary['update'] > 0 )      $parts[] = \WP_CLI::colorize( "%y{$summary['update']} update%n" );
		if ( $summary['queued'] > 0 )      $parts[] = \WP_CLI::colorize( "%c{$summary['queued']} in queue%n" );
		if ( $summary['unaudited'] > 0 )   $parts[] = "{$summary['unaudited']} unaudited";
		\WP_CLI::log( "Scanned {$total} components in {$elapsed}s: " . implode( ', ', $parts ) );

		// Coverage
		$audited  = $summary['clean'] + $summary['vulnerable'] + $summary['malware'];
		$coverage = $total > 0 ? round( $audited / $total * 100 ) : 100;
		$cov_color = $coverage === 100 ? '%g' : ( $coverage >= 75 ? '%y' : '%r' );
		\WP_CLI::log( \WP_CLI::colorize( "WP Registry: {$cov_color}{$coverage}%%%n coverage ({$audited}/{$total} audited)" ) );

		// Hints
		if ( $summary['vulnerable'] > 0 || $summary['malware'] > 0 ) {
			\WP_CLI::log( 'Run `wp registry update --dry-run` to check for available patches.' );
		}
		if ( $summary['unaudited'] > 0 ) {
			\WP_CLI::log( sprintf( 'Run `wp registry upload` to send %d unaudited component(s) for audit.', $summary['unaudited'] ) );
		}
	}

	/**
	 * Details view: line-style with key_issue text, sorted by severity then alphabetical.
	 */
	private static function render_details( array $results ): void {
		$grouped = [];
		foreach ( $results as $r ) {
			$grouped[ $r['type'] ][] = $r;
		}

		$type_labels = [ 'plugin' => 'Plugins', 'theme' => 'Themes', 'file' => 'Loose Files' ];

		foreach ( $type_labels as $type => $label ) {
			if ( empty( $grouped[ $type ] ) ) {
				continue;
			}

			usort( $grouped[ $type ], function ( $a, $b ) {
				$sa = ! empty( $a['malware'] ) ? 'malware' : $a['status'];
				$sb = ! empty( $b['malware'] ) ? 'malware' : $b['status'];
				$diff = ( self::SEVERITY_ORDER[ $sb ] ?? 0 ) - ( self::SEVERITY_ORDER[ $sa ] ?? 0 );
				return $diff !== 0 ? $diff : strcmp( $a['slug'], $b['slug'] );
			} );

			\WP_CLI::log( \WP_CLI::colorize( "%W{$label}%n" ) );

			foreach ( $grouped[ $type ] as $r ) {
				$icon  = self::status_icon( $r['status'], $r['malware'] );
				$audit = ! empty( $r['malware'] ) ? 'MALWARE' : $r['status'];
				$issue = $r['key_issue'] ? " -- {$r['key_issue']}" : '';
				\WP_CLI::log( "  {$icon} {$r['slug']}  {$r['hash']}  {$audit}{$issue}" );
			}

			\WP_CLI::log( '' );
		}
	}

	/**
	 * Default view: clean padded table, no key_issue text.
	 */
	private static function render_table( array $results ): void {
		$grouped = [];
		foreach ( $results as $r ) {
			$grouped[ $r['type'] ][] = $r;
		}

		$type_labels = [ 'plugin' => 'Plugins', 'theme' => 'Themes', 'file' => 'Loose Files' ];

		foreach ( $type_labels as $type => $label ) {
			if ( empty( $grouped[ $type ] ) ) {
				continue;
			}

			// Sort by severity desc, then alphabetically
			usort( $grouped[ $type ], function ( $a, $b ) {
				$sa = ! empty( $a['malware'] ) ? 'malware' : $a['status'];
				$sb = ! empty( $b['malware'] ) ? 'malware' : $b['status'];
				$diff = ( self::SEVERITY_ORDER[ $sb ] ?? 0 ) - ( self::SEVERITY_ORDER[ $sa ] ?? 0 );
				return $diff !== 0 ? $diff : strcmp( $a['slug'], $b['slug'] );
			} );

			// Calculate column widths
			$name_width   = 4;
			$status_width = 6;
			foreach ( $grouped[ $type ] as $r ) {
				$name_width   = max( $name_width, strlen( $r['slug'] ) );
				$audit_label  = ! empty( $r['malware'] ) ? 'MALWARE' : $r['status'];
				$status_width = max( $status_width, strlen( $audit_label ) );
			}

			$count = count( $grouped[ $type ] );
			\WP_CLI::log( \WP_CLI::colorize( "%W{$label}%n" ) . " ({$count})" );

			// Header
			\WP_CLI::log( sprintf(
				"  %-{$name_width}s  %-12s  %-{$status_width}s",
				'Name', 'Hash', 'Audit'
			) );

			foreach ( $grouped[ $type ] as $r ) {
				$icon         = self::status_icon( $r['status'], $r['malware'] );
				$audit_label  = ! empty( $r['malware'] ) ? 'MALWARE' : $r['status'];
				$padded_name  = str_pad( $r['slug'], $name_width );
				$padded_audit = str_pad( $audit_label, $status_width );

				\WP_CLI::log( "{$icon} {$padded_name}  {$r['hash']}  {$padded_audit}" );
			}

			\WP_CLI::log( '' );
		}
	}

	/**
	 * Apply security patches from the WP Registry patch list.
	 *
	 * Checks installed plugins and themes against the patches manifest
	 * and installs patched versions for any matches.
	 *
	 * ## OPTIONS
	 *
	 * [--dry-run]
	 * : Show what would be updated without making changes.
	 *
	 * [--format=<format>]
	 * : Output format. Accepts: table, json.
	 * ---
	 * default: table
	 * ---
	 *
	 * ## EXAMPLES
	 *
	 *     wp registry update
	 *     wp registry update --dry-run
	 *
	 * @when after_wp_load
	 */
	public function update( $args, $assoc_args ) {
		$dry_run = isset( $assoc_args['dry-run'] );
		$format  = $assoc_args['format'] ?? 'table';

		\WP_CLI::log( 'Fetching patches manifest...' );
		$manifest = self::fetch_manifest( 'manifest.json' );
		$patches  = (array) ( $manifest['patches'] ?? [] );

		if ( empty( $patches ) ) {
			\WP_CLI::success( 'No patches available.' );
			return;
		}

		\WP_CLI::log( sprintf( '  %d patches available', count( $patches ) ) );

		// Get installed plugins and themes
		$installed = [];
		if ( ! function_exists( 'get_plugins' ) ) {
			require_once ABSPATH . 'wp-admin/includes/plugin.php';
		}
		foreach ( get_plugins() as $file => $data ) {
			$slug = dirname( $file );
			if ( $slug === '.' ) {
				$slug = str_replace( '.php', '', $file );
			}
			$installed[] = [
				'type'    => 'plugin',
				'slug'    => $slug,
				'version' => $data['Version'] ?? '',
			];
		}
		foreach ( wp_get_themes() as $slug => $theme ) {
			$installed[] = [
				'type'    => 'theme',
				'slug'    => $slug,
				'version' => $theme->get( 'Version' ),
			];
		}

		// Match against patches
		$available = [];
		foreach ( $installed as $component ) {
			$key   = "{$component['type']}|{$component['slug']}|{$component['version']}";
			$patch = $patches[ $key ] ?? null;
			if ( $patch ) {
				$patch = (array) $patch;
				$available[] = [
					'type'            => $component['type'],
					'slug'            => $component['slug'],
					'version'         => $component['version'],
					'patched_version' => $patch['patched_version'] ?? '',
					'download_url'    => $patch['download_url'] ?? '',
					'description'     => $patch['description'] ?? '',
					'severity'        => $patch['severity'] ?? '',
				];
			}
		}

		if ( empty( $available ) ) {
			\WP_CLI::success( 'All components are up to date. No patches needed.' );
			return;
		}

		if ( $format === 'json' ) {
			echo json_encode( $available, JSON_PRETTY_PRINT ) . "\n";
			if ( $dry_run ) {
				return;
			}
		}

		// Show what will be updated
		foreach ( $available as $patch ) {
			$icon = $patch['severity'] === 'critical'
				? \WP_CLI::colorize( '%r✗%n' )
				: \WP_CLI::colorize( '%y⚠%n' );
			\WP_CLI::log( sprintf(
				'  %s %s %s → %s (%s)',
				$icon,
				$patch['slug'],
				$patch['version'],
				$patch['patched_version'],
				$patch['severity']
			) );
			if ( $patch['description'] ) {
				\WP_CLI::log( "    " . $patch['description'] );
			}
		}

		if ( $dry_run ) {
			\WP_CLI::log( '' );
			\WP_CLI::log( sprintf( '%d patch(es) available. Use without --dry-run to apply.', count( $available ) ) );
			return;
		}

		\WP_CLI::log( '' );

		// Apply patches
		$success = 0;
		$failed  = 0;
		foreach ( $available as $patch ) {
			\WP_CLI::log( sprintf( 'Patching %s %s...', $patch['slug'], $patch['version'] ) );

			$command = $patch['type'] === 'theme' ? 'theme' : 'plugin';
			// WP_CLI::runcommand takes a CLI-style string (not a shell command), so
			// escapeshellarg's single quotes would be parsed as literal chars by the
			// CLI runner. The download_url is sourced from the trusted patch manifest;
			// pass it bare and rely on URL syntax for tokenization.
			$result  = \WP_CLI::runcommand(
				sprintf( '%s install %s --force', $command, $patch['download_url'] ),
				[ 'return' => 'all', 'exit_error' => false ]
			);

			if ( $result->return_code === 0 ) {
				\WP_CLI::log( \WP_CLI::colorize( "  %g✓ Patched to {$patch['patched_version']}%n" ) );
				$success++;
			} else {
				\WP_CLI::warning( "  Failed to patch {$patch['slug']}: {$result->stderr}" );
				$failed++;
			}
		}

		\WP_CLI::log( '' );
		if ( $failed === 0 ) {
			\WP_CLI::success( sprintf( '%d patch(es) applied successfully.', $success ) );
		} else {
			\WP_CLI::warning( sprintf( '%d applied, %d failed.', $success, $failed ) );
		}
	}

	/**
	 * Show full audit findings for one installed component.
	 *
	 * Hashes the local plugin/theme directory, fetches every recorded
	 * finding for that exact hash from the WP Registry, and prints them
	 * with severity, vulnerability type, file location, code snippet, and
	 * recommendation.
	 *
	 * ## OPTIONS
	 *
	 * <slug>
	 * : Component slug. Matched against plugins/<slug>/ first, then themes/<slug>/.
	 *
	 * [--type=<type>]
	 * : Force a specific type instead of auto-detecting. Accepts: plugin, theme.
	 *
	 * [--format=<format>]
	 * : Output format. Accepts: table, json.
	 * ---
	 * default: table
	 * ---
	 *
	 * ## EXAMPLES
	 *
	 *     wp registry show elementor-pro
	 *     wp registry show twentytwentyfive --type=theme
	 *     wp registry show elementor-pro --format=json
	 *
	 * @when after_wp_load
	 */
	public function show( $args, $assoc_args ) {
		$slug   = $args[0] ?? '';
		$type   = $assoc_args['type'] ?? '';
		$format = $assoc_args['format'] ?? 'table';

		if ( $slug === '' ) {
			\WP_CLI::error( 'Provide a slug, e.g. `wp registry show elementor-pro`' );
		}

		// Resolve slug → directory. Try plugin first (more common), then theme.
		$candidates = [];
		if ( $type === '' || $type === 'plugin' ) {
			$dir = WP_CONTENT_DIR . '/plugins/' . $slug;
			if ( is_dir( $dir ) ) {
				$candidates[] = [ 'type' => 'plugin', 'dir' => $dir ];
			}
		}
		if ( $type === '' || $type === 'theme' ) {
			$dir = WP_CONTENT_DIR . '/themes/' . $slug;
			if ( is_dir( $dir ) ) {
				$candidates[] = [ 'type' => 'theme', 'dir' => $dir ];
			}
		}
		if ( empty( $candidates ) ) {
			\WP_CLI::error( "No plugin or theme found with slug '{$slug}'" );
		}
		if ( count( $candidates ) > 1 ) {
			\WP_CLI::warning( "'{$slug}' exists as both plugin and theme; showing the plugin. Use --type=theme to target the theme." );
		}
		$target = $candidates[0];

		$hash = Hasher::hash_directory( $target['dir'] );

		// Fetch per-hash findings from the public Cloudflare-fronted endpoint.
		$url      = self::API_BASE . '/findings/' . $hash . '.json';
		$response = wp_remote_get( $url, [ 'timeout' => 30 ] );
		if ( is_wp_error( $response ) ) {
			\WP_CLI::error( 'Failed to fetch findings: ' . $response->get_error_message() );
		}
		$code = wp_remote_retrieve_response_code( $response );
		if ( $code !== 200 ) {
			\WP_CLI::error( "Findings endpoint returned HTTP {$code}" );
		}
		$data = json_decode( wp_remote_retrieve_body( $response ), true );
		if ( ! is_array( $data ) ) {
			\WP_CLI::error( 'Invalid response from findings endpoint' );
		}

		// Hash exists on disk but not in the registry — this build is unaudited.
		if ( empty( $data['audited'] ) ) {
			if ( $format === 'json' ) {
				echo json_encode( [ 'slug' => $slug, 'type' => $target['type'], 'hash' => $hash, 'audited' => false ], JSON_PRETTY_PRINT ) . "\n";
				return;
			}
			\WP_CLI::log( "{$target['type']}/{$slug}  " . substr( $hash, 0, 12 ) );
			\WP_CLI::log( '' );
			\WP_CLI::warning( 'This exact code has not been audited yet. Run `wp registry upload` to send it for review.' );
			return;
		}

		if ( $format === 'json' ) {
			echo json_encode( $data, JSON_PRETTY_PRINT ) . "\n";
			return;
		}

		self::render_show( $data, $target['type'], $slug, $hash );
	}

	/**
	 * Render the findings detail view for `wp registry show <slug>`.
	 */
	private static function render_show( array $data, string $type, string $slug, string $hash ): void {
		$status   = $data['status'] ?? 'unaudited';
		$malware  = ! empty( $data['malware'] );
		$icon     = self::status_icon( $status, $malware );
		$verdict  = $malware ? 'MALWARE' : $status;
		$name     = ! empty( $data['display_name'] ) ? $data['display_name'] : ( $data['slug'] ?? $slug );
		$version  = $data['version'] ?? '';
		$findings = $data['findings'] ?? [];

		\WP_CLI::log( '' );
		\WP_CLI::log(
			\WP_CLI::colorize( "%W{$name}%n" )
			. ( $version !== '' ? " v{$version}" : '' )
			. "  {$icon} {$verdict}"
		);
		\WP_CLI::log( "  {$type}/{$slug}  " . substr( $hash, 0, 12 ) );

		if ( ! empty( $data['key_issue'] ) ) {
			\WP_CLI::log( '  ' . $data['key_issue'] );
		}

		// Auditor attribution
		$auditors = [];
		foreach ( (array) ( $data['audits'] ?? [] ) as $a ) {
			if ( ! empty( $a['auditor'] ) ) {
				$auditors[ $a['auditor'] ] = true;
			}
		}
		if ( ! empty( $auditors ) ) {
			\WP_CLI::log( '  audited by: ' . implode( ', ', array_keys( $auditors ) ) );
		}

		if ( empty( $findings ) ) {
			\WP_CLI::log( '' );
			\WP_CLI::log( '  No specific findings recorded.' );
			return;
		}

		\WP_CLI::log( '' );
		\WP_CLI::log( \WP_CLI::colorize( '%W' . count( $findings ) . ' finding(s)%n' ) );

		foreach ( $findings as $f ) {
			$sev      = (string) ( $f['severity'] ?? 'low' );
			$code     = (string) ( $f['finding_code'] ?? '' );
			$title    = (string) ( $f['title'] ?? '' );
			$vuln     = (string) ( $f['vuln_type'] ?? '' );
			$path     = (string) ( $f['location_path'] ?? '' );
			$lines    = (string) ( $f['location_lines'] ?? '' );
			$desc     = (string) ( $f['description'] ?? '' );
			$snippet  = (string) ( $f['code_snippet'] ?? '' );
			$rec      = (string) ( $f['recommendation'] ?? '' );

			\WP_CLI::log( '' );
			\WP_CLI::log( '  ' . self::severity_label( $sev ) . ( $code !== '' ? " [{$code}]" : '' ) . "  {$title}" );
			if ( $vuln !== '' ) {
				\WP_CLI::log( "    type:   {$vuln}" );
			}
			if ( $path !== '' ) {
				$location = $path . ( $lines !== '' ? ':' . $lines : '' );
				\WP_CLI::log( "    where:  {$location}" );
			}
			if ( $desc !== '' ) {
				\WP_CLI::log( "    detail: " . self::wrap_indent( $desc, '            ', 4 ) );
			}
			if ( $snippet !== '' ) {
				\WP_CLI::log( '    code:' );
				foreach ( explode( "\n", rtrim( $snippet ) ) as $ln ) {
					\WP_CLI::log( '      ' . $ln );
				}
			}
			if ( $rec !== '' ) {
				\WP_CLI::log( "    fix:    " . self::wrap_indent( $rec, '            ', 4 ) );
			}
		}
	}

	/**
	 * Color a severity word the same way status_icon colors its symbol.
	 */
	private static function severity_label( string $severity ): string {
		switch ( $severity ) {
			case 'critical': return \WP_CLI::colorize( '%r' . str_pad( strtoupper( $severity ), 8 ) . '%n' );
			case 'high':     return \WP_CLI::colorize( '%r' . str_pad( strtoupper( $severity ), 8 ) . '%n' );
			case 'medium':   return \WP_CLI::colorize( '%y' . str_pad( strtoupper( $severity ), 8 ) . '%n' );
			case 'low':      return \WP_CLI::colorize( '%b' . str_pad( strtoupper( $severity ), 8 ) . '%n' );
			default:         return str_pad( strtoupper( $severity ), 8 );
		}
	}

	/**
	 * Indent wrapped lines so multi-line description/recommendation text aligns
	 * with the label column. Used for narrow terminals.
	 */
	private static function wrap_indent( string $text, string $indent, int $first_indent ): string {
		$width = max( 60, ( getenv( 'COLUMNS' ) ? (int) getenv( 'COLUMNS' ) : 100 ) - strlen( $indent ) );
		$wrapped = wordwrap( $text, $width, "\n", false );
		$lines = explode( "\n", $wrapped );
		// First line is already prefixed by caller; subsequent lines get the indent.
		return $lines[0] . ( count( $lines ) > 1 ? "\n" . $indent . implode( "\n" . $indent, array_slice( $lines, 1 ) ) : '' );
	}

	/**
	 * Fetch a manifest from the updates API.
	 */
	private static function fetch_manifest( string $filename ): array {
		$response = wp_remote_get( self::API_BASE . '/' . $filename, [ 'timeout' => 30 ] );

		if ( is_wp_error( $response ) || 200 !== wp_remote_retrieve_response_code( $response ) ) {
			\WP_CLI::warning( "Failed to fetch {$filename} from " . self::API_BASE );
			return [];
		}

		$data = json_decode( wp_remote_retrieve_body( $response ), true );
		if ( ! is_array( $data ) ) {
			\WP_CLI::warning( "Invalid manifest format for {$filename}" );
			return [];
		}

		return $data;
	}

	/**
	 * Resolve one local component's display status from the batch lookup + local
	 * update state. An audited verdict wins; otherwise a registry "outdated" flag
	 * (the queue system found a newer version exists) shows as "update" and
	 * overrides the site's own update transient — the registry is the authority,
	 * since WordPress's update data is exactly what's unreliable here. Failing that,
	 * "in queue" (this exact build is awaiting audit) beats a locally-detected
	 * "update" beats a plain uploadable "unaudited".
	 */
	private static function resolve_component( string $type, string $slug, string $hash, array $lookup, array $update_slugs ): array {
		$entry = $lookup[ $hash ] ?? null;

		if ( $entry && ! empty( $entry['audited'] ) ) {
			return [
				'type'      => $type,
				'slug'      => $slug,
				'hash'      => substr( $hash, 0, 12 ),
				'status'    => $entry['status'] ?? 'clean',
				'malware'   => ! empty( $entry['malware'] ),
				'key_issue' => $entry['key_issue'] ?? '',
			];
		}

		$key_issue = '';
		if ( $entry && ! empty( $entry['outdated'] ) ) {
			$status    = 'update';
			$latest    = (string) ( $entry['latest_version'] ?? '' );
			$key_issue = $latest !== '' ? "newer version available (latest {$latest})" : 'newer version available';
		} elseif ( $entry && ! empty( $entry['in_queue'] ) ) {
			$status = 'in queue';
		} elseif ( isset( $update_slugs[ $slug ] ) ) {
			$status = 'update';
		} else {
			$status = 'unaudited';
		}

		return [
			'type'      => $type,
			'slug'      => $slug,
			'hash'      => substr( $hash, 0, 12 ),
			'status'    => $status,
			'malware'   => false,
			'key_issue' => $key_issue,
		];
	}

	/**
	 * Look up content hashes via prefix shards: group the site's hashes by their
	 * first SHARD_PREFIX_LEN hex chars, fetch only those `/hashes/<prefix>.json`
	 * shards (in parallel; each is edge-cached and shared across all sites), and
	 * merge their per-hash entries. Returns a map keyed by full hash — absent means
	 * neither audited nor queued. Only the site's own hashes leave (never URLs or
	 * file contents).
	 */
	private static function lookup_hashes( array $hashes ): array {
		$hashes = array_values( array_unique( array_filter( $hashes ) ) );
		if ( empty( $hashes ) ) {
			return [];
		}
		$prefixes = [];
		foreach ( $hashes as $h ) {
			$prefixes[ substr( $h, 0, self::SHARD_PREFIX_LEN ) ] = true;
		}
		return self::fetch_shards( array_keys( $prefixes ) );
	}

	/**
	 * Fetch the given prefix shards and merge their `hashes` maps. Concurrency is
	 * capped (waves of 20) and non-200 shards are retried: a cold edge cache makes
	 * one big burst of ~100 parallel requests hammer the origin, so some fail and
	 * their components would wrongly read "unaudited"/"update". Chunking keeps the
	 * origin from being stormed; the retry mops up stragglers once they're warm. A
	 * hash lives in exactly one shard, so the maps union cleanly.
	 */
	private static function fetch_shards( array $prefixes ): array {
		$lookup  = [];
		$pending = array_values( array_unique( $prefixes ) );

		for ( $attempt = 1; $attempt <= 3 && ! empty( $pending ); $attempt++ ) {
			$failed = [];
			foreach ( array_chunk( $pending, 20 ) as $chunk ) {
				$failed = array_merge( $failed, self::fetch_shard_chunk( $chunk, $lookup ) );
			}
			$pending = $failed;
		}

		if ( ! empty( $pending ) ) {
			\WP_CLI::warning( sprintf(
				'%d hash shard(s) unreachable after retries — some statuses may show as unaudited. Re-run to refresh.',
				count( $pending )
			) );
		}
		return $lookup;
	}

	/**
	 * Fetch one wave of shards in parallel; merge HTTP-200s into $lookup and return
	 * the prefixes that failed (non-200 / no response) so the caller can retry them.
	 */
	private static function fetch_shard_chunk( array $prefixes, array &$lookup ): array {
		$merge = static function ( $body ) use ( &$lookup ) {
			$data = json_decode( (string) $body, true );
			if ( is_array( $data ) && ! empty( $data['hashes'] ) && is_array( $data['hashes'] ) ) {
				$lookup += $data['hashes'];
			}
		};

		$class = class_exists( '\\WpOrg\\Requests\\Requests' ) ? '\\WpOrg\\Requests\\Requests'
			: ( class_exists( '\\Requests' ) ? '\\Requests' : '' );

		if ( $class ) {
			$requests = [];
			foreach ( $prefixes as $pp ) {
				$requests[ $pp ] = [ 'url' => self::API_BASE . '/hashes/' . $pp . '.json', 'type' => 'GET' ];
			}
			try {
				$responses = $class::request_multiple( $requests, [ 'timeout' => 30 ] );
				$failed = [];
				foreach ( $responses as $pp => $resp ) {
					if ( is_object( $resp ) && ! empty( $resp->success ) && (int) $resp->status_code === 200 ) {
						$merge( $resp->body );
					} else {
						$failed[] = $pp;
					}
				}
				return $failed;
			} catch ( \Exception $e ) {
				return $prefixes; // whole wave failed — retry all
			}
		}

		// No parallel transport available — sequential fallback.
		$failed = [];
		foreach ( $prefixes as $pp ) {
			$r = wp_remote_get( self::API_BASE . '/hashes/' . $pp . '.json', [ 'timeout' => 15 ] );
			if ( ! is_wp_error( $r ) && 200 === wp_remote_retrieve_response_code( $r ) ) {
				$merge( wp_remote_retrieve_body( $r ) );
			} else {
				$failed[] = $pp;
			}
		}
		return $failed;
	}

	/**
	 * Get a colored status icon.
	 */
	private static function status_icon( string $status, bool $malware ): string {
		if ( $malware ) {
			return \WP_CLI::colorize( '%1 MALWARE %n' );
		}
		switch ( $status ) {
			case 'clean':     return \WP_CLI::colorize( '%g✓%n' );
			case 'low':       return \WP_CLI::colorize( '%b⚠%n' );
			case 'medium':    return \WP_CLI::colorize( '%y⚠%n' );
			case 'high':      return \WP_CLI::colorize( '%r⚠%n' );
			case 'critical':  return \WP_CLI::colorize( '%r✗%n' );
			case 'unaudited': return \WP_CLI::colorize( '%y?%n' );
			case 'update':    return \WP_CLI::colorize( '%y↑%n' );
			case 'in queue':  return \WP_CLI::colorize( '%c…%n' );
			default:          return ' ';
		}
	}

	/**
	 * Upload unaudited components to the WP Registry audit queue.
	 *
	 * Scans plugins and themes and uploads only builds that are (a) not already
	 * audited, (b) not already in the queue, and (c) on the latest installed
	 * version. Out-of-date builds are skipped — update them and re-run rather
	 * than queueing a build that's about to change. The Cloudflare worker
	 * re-hashes and validates each zip on receipt, so only genuine plugin/theme
	 * builds are accepted. Only slugs, versions, and content hashes are sent.
	 *
	 * ## OPTIONS
	 *
	 * [<target>]
	 * : Limit to one component as type/slug (e.g. plugin/vuetifused) or a bare slug. Omit to upload everything eligible.
	 *
	 * [--dry-run]
	 * : Preview what would be uploaded without sending it.
	 *
	 * ## EXAMPLES
	 *
	 *     wp registry upload
	 *     wp registry upload plugin/vuetifused
	 *     wp registry upload vuetifused
	 *     wp registry upload --dry-run
	 *
	 * @when after_wp_load
	 */
	public function upload( $args, $assoc_args ) {
		$dry_run = isset( $assoc_args['dry-run'] );

		// Optional target: "type/slug" (e.g. plugin/vuetifused) or a bare slug.
		// When set, only that component is considered (and only it is hashed).
		$target_type = '';
		$target_slug = '';
		if ( ! empty( $args[0] ) ) {
			if ( strpos( $args[0], '/' ) !== false ) {
				list( $target_type, $target_slug ) = explode( '/', $args[0], 2 );
				$target_type = strtolower( trim( $target_type ) );
				$target_slug = trim( $target_slug );
				if ( ! in_array( $target_type, [ 'plugin', 'theme' ], true ) ) {
					\WP_CLI::error( "Target type must be 'plugin' or 'theme', e.g. `wp registry upload plugin/{$target_slug}`" );
				}
			} else {
				$target_slug = trim( $args[0] );
			}
		}
		$targeted = ( $target_slug !== '' );

		\WP_CLI::log( $targeted ? "Checking {$args[0]}..." : 'Scanning for components to upload...' );

		self::refresh_update_data();
		$updates = [
			'plugin' => self::slugs_with_updates( 'plugin' ),
			'theme'  => self::slugs_with_updates( 'theme' ),
		];

		// Candidate set. In targeted mode we hash only the named dir rather than
		// every plugin/theme.
		$bases  = [ 'plugin' => WP_CONTENT_DIR . '/plugins/', 'theme' => WP_CONTENT_DIR . '/themes/' ];
		$groups = [];
		foreach ( $bases as $gtype => $base ) {
			if ( $target_type !== '' && $gtype !== $target_type ) {
				continue;
			}
			if ( $targeted ) {
				$dir    = $base . $target_slug;
				$hashes = is_dir( $dir ) ? [ $target_slug => Hasher::hash_directory( $dir ) ] : [];
			} else {
				$hashes = $gtype === 'plugin' ? Hasher::hash_plugins() : Hasher::hash_themes();
			}
			$groups[] = [ 'type' => $gtype, 'hashes' => $hashes, 'updates' => $updates[ $gtype ], 'base' => $base ];
		}

		// One batch lookup for every candidate hash (audited + in_queue state).
		$all_hashes = [];
		foreach ( $groups as $group ) {
			foreach ( $group['hashes'] as $hash ) {
				$all_hashes[] = $hash;
			}
		}
		$lookup = self::lookup_hashes( $all_hashes );

		if ( $targeted ) {
			$found = false;
			foreach ( $groups as $g ) {
				if ( isset( $g['hashes'][ $target_slug ] ) ) { $found = true; break; }
			}
			if ( ! $found ) {
				\WP_CLI::error( "No installed " . ( $target_type ?: 'plugin or theme' ) . " found with slug '{$target_slug}'." );
			}
		}

		$unaudited = [];
		$skipped   = [ 'audited' => 0, 'queued' => 0, 'outdated' => 0 ];
		foreach ( $groups as $group ) {
			foreach ( $group['hashes'] as $slug => $hash ) {
				// Per-item gating. In targeted mode an excluded item gets an explicit
				// reason; in scan mode it's a silent tally.
				$entry = $lookup[ $hash ] ?? null;
				if ( $entry && ! empty( $entry['audited'] ) ) {
					$skipped['audited']++;
					if ( $targeted ) { \WP_CLI::warning( "{$group['type']}/{$slug} is already audited — nothing to upload." ); }
					continue;
				}
				if ( $entry && ! empty( $entry['outdated'] ) ) {
					// The registry already knows a newer version exists — don't re-queue
					// a stale build even if this site's update transient hasn't caught up.
					$skipped['outdated']++;
					if ( $targeted ) {
						$latest = (string) ( $entry['latest_version'] ?? '' );
						\WP_CLI::warning( "{$group['type']}/{$slug} is outdated" . ( $latest !== '' ? " (latest {$latest})" : '' ) . " — update it first, then upload the latest build." );
					}
					continue;
				}
				if ( $entry && ! empty( $entry['in_queue'] ) ) {
					$skipped['queued']++;
					if ( $targeted ) { \WP_CLI::warning( "{$group['type']}/{$slug} is already in the audit queue." ); }
					continue;
				}
				if ( isset( $group['updates'][ $slug ] ) ) {
					$skipped['outdated']++;
					if ( $targeted ) { \WP_CLI::warning( "{$group['type']}/{$slug} has an update available — update it first, then upload the latest build." ); }
					continue;
				}
				$unaudited[] = [
					'type'    => $group['type'],
					'slug'    => $slug,
					'hash'    => $hash,
					'dir'     => $group['base'] . $slug,
					'version' => $group['type'] === 'plugin' ? self::get_plugin_version( $slug ) : self::get_theme_version( $slug ),
				];
			}
		}

		if ( empty( $unaudited ) ) {
			if ( $targeted ) {
				return;   // the specific reason was already printed above
			}
			\WP_CLI::success( sprintf( 'Nothing to upload. (skipped %d audited, %d already queued, %d out-of-date)', $skipped['audited'], $skipped['queued'], $skipped['outdated'] ) );
			return;
		}

		if ( $targeted ) {
			\WP_CLI::log( sprintf( '%d component(s) ready to upload:', count( $unaudited ) ) );
		} else {
			\WP_CLI::log( sprintf( '%d component(s) ready to upload (skipped %d audited, %d already queued, %d out-of-date):', count( $unaudited ), $skipped['audited'], $skipped['queued'], $skipped['outdated'] ) );
		}
		foreach ( $unaudited as $item ) {
			\WP_CLI::log( sprintf( '  %s/%s %s  %s', $item['type'], $item['slug'], $item['version'], substr( $item['hash'], 0, 12 ) ) );
		}

		if ( $dry_run ) {
			\WP_CLI::log( '' );
			\WP_CLI::log( 'Use without --dry-run to upload.' );
			return;
		}

		\WP_CLI::log( '' );
		$uploaded = 0;
		$already  = 0;
		$failed   = 0;
		foreach ( $unaudited as $item ) {
			\WP_CLI::log( sprintf( 'Uploading %s %s...', $item['slug'], $item['version'] ) );
			$zip = self::create_zip( $item['dir'] );
			if ( ! $zip ) {
				\WP_CLI::warning( "  Failed to create zip for {$item['slug']}" );
				$failed++;
				continue;
			}
			$result = self::upload_zip( $zip, $item );
			@unlink( $zip );
			if ( $result === 'uploaded' ) {
				\WP_CLI::log( \WP_CLI::colorize( '  %g✓ Queued for audit%n' ) );
				$uploaded++;
			} elseif ( $result === 'exists' ) {
				\WP_CLI::log( '  Already in queue' );
				$already++;
			} else {
				\WP_CLI::warning( "  Upload failed for {$item['slug']}: {$result}" );
				$failed++;
			}
		}

		\WP_CLI::log( '' );
		$parts = [];
		if ( $uploaded > 0 ) $parts[] = "{$uploaded} uploaded";
		if ( $already > 0 )  $parts[] = "{$already} already queued";
		if ( $failed > 0 )   $parts[] = "{$failed} failed";
		\WP_CLI::success( implode( ', ', $parts ) . '.' );
	}

	/**
	 * Zip a plugin/theme directory. Entries are slug/... (matching the worker
	 * gatekeeper + the hash prefix); node_modules and .git are excluded. Returns
	 * the temp path or false.
	 */
	private static function create_zip( string $dir ) {
		if ( ! class_exists( '\ZipArchive' ) ) {
			\WP_CLI::warning( 'ZipArchive extension not available.' );
			return false;
		}
		$tmp = tempnam( sys_get_temp_dir(), 'registry_' ) . '.zip';
		$zip = new \ZipArchive();
		if ( $zip->open( $tmp, \ZipArchive::CREATE | \ZipArchive::OVERWRITE ) !== true ) {
			return false;
		}
		$base     = dirname( $dir );
		$iterator = new \RecursiveIteratorIterator(
			new \RecursiveDirectoryIterator( $dir, \FilesystemIterator::SKIP_DOTS ),
			\RecursiveIteratorIterator::LEAVES_ONLY
		);
		foreach ( $iterator as $file ) {
			if ( ! $file->isFile() ) {
				continue;
			}
			$path = $file->getPathname();
			if ( strpos( $path, 'node_modules/' ) !== false || strpos( $path, '.git/' ) !== false ) {
				continue;
			}
			$relative = ltrim( str_replace( $base, '', $path ), '/' );
			$zip->addFile( $path, $relative );
		}
		$zip->close();
		return $tmp;
	}

	/**
	 * Upload a zip to the audit queue. Returns 'uploaded' or an error string.
	 */
	private static function upload_zip( string $zip_path, array $meta ): string {
		$size = filesize( $zip_path );
		if ( $size > 30 * 1024 * 1024 ) {
			return 'zip too large (' . round( $size / 1024 / 1024 ) . 'MB; 30MB max)';
		}
		$url = self::API_BASE . '/upload?' . http_build_query( [
			'slug'    => $meta['slug'],
			'version' => $meta['version'],
			'type'    => $meta['type'],
			'hash'    => $meta['hash'],
		] );
		$response = wp_remote_post( $url, [
			'timeout' => 120,
			'headers' => [ 'Content-Type' => 'application/zip' ],
			'body'    => file_get_contents( $zip_path ),
		] );
		if ( is_wp_error( $response ) ) {
			return $response->get_error_message();
		}
		$code = wp_remote_retrieve_response_code( $response );
		$body = json_decode( wp_remote_retrieve_body( $response ), true );
		if ( $code === 200 && isset( $body['status'] ) && in_array( $body['status'], [ 'uploaded', 'exists' ], true ) ) {
			return $body['status'];
		}
		return isset( $body['error'] ) ? "HTTP {$code}: {$body['error']}" : "HTTP {$code}";
	}

	private static function get_plugin_version( string $slug ): string {
		if ( ! function_exists( 'get_plugins' ) ) {
			require_once ABSPATH . 'wp-admin/includes/plugin.php';
		}
		foreach ( get_plugins() as $file => $data ) {
			$file_slug = dirname( $file );
			if ( $file_slug === '.' ) {
				$file_slug = str_replace( '.php', '', $file );
			}
			if ( $file_slug === $slug ) {
				return $data['Version'] ?? '';
			}
		}
		return '';
	}

	private static function get_theme_version( string $slug ): string {
		$theme = wp_get_theme( $slug );
		return $theme->exists() ? (string) $theme->get( 'Version' ) : '';
	}

	/**
	 * Refresh WordPress's update transients so the "update"/latest checks reflect
	 * current data. Both core helpers self-throttle (no network if checked
	 * recently), so this is cheap to call on every check/upload.
	 */
	private static function refresh_update_data(): void {
		if ( ! function_exists( 'wp_update_plugins' ) ) {
			require_once ABSPATH . 'wp-admin/includes/update.php';
		}
		wp_update_plugins();
		wp_update_themes();
	}

	/**
	 * slug => true for components of the given type ('plugin'|'theme') that have
	 * an available update, read from WordPress's update transient. Plugin keys
	 * are normalized to the directory slug Hasher uses.
	 */
	private static function slugs_with_updates( string $type ): array {
		$slugs = [];
		if ( $type === 'plugin' ) {
			$t = get_site_transient( 'update_plugins' );
			if ( is_object( $t ) && ! empty( $t->response ) ) {
				foreach ( array_keys( $t->response ) as $file ) {
					$dir = dirname( $file );
					$slugs[ $dir === '.' ? str_replace( '.php', '', $file ) : $dir ] = true;
				}
			}
		} else {
			$t = get_site_transient( 'update_themes' );
			if ( is_object( $t ) && ! empty( $t->response ) ) {
				foreach ( array_keys( $t->response ) as $stylesheet ) {
					$slugs[ $stylesheet ] = true;
				}
			}
		}
		return $slugs;
	}
}
