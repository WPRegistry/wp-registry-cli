<?php

namespace WPRegistry;

class Command {

	private const API_BASE = 'https://wpregistry.io';

	private const SEVERITY_ORDER = [
		'malware'   => 6,
		'critical'  => 5,
		'high'      => 4,
		'medium'    => 3,
		'low'       => 2,
		'clean'     => 1,
		'unaudited' => 0,
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

		$results = [];

		if ( $type === 'all' || $type === 'plugins' ) {
			\WP_CLI::log( 'Scanning plugins...' );
			$hashes   = Hasher::hash_plugins();
			$manifest = self::fetch_manifest( 'plugins-hashes.json' );
			$results  = array_merge( $results, self::check_hashes( $hashes, $manifest, 'plugin' ) );
		}

		if ( $type === 'all' || $type === 'themes' ) {
			\WP_CLI::log( 'Scanning themes...' );
			$hashes   = Hasher::hash_themes();
			$manifest = self::fetch_manifest( 'themes-hashes.json' );
			$results  = array_merge( $results, self::check_hashes( $hashes, $manifest, 'theme' ) );
		}

		if ( $type === 'all' || $type === 'files' ) {
			\WP_CLI::log( 'Scanning loose files...' );
			$hashes   = Hasher::hash_loose_files();
			$manifest = self::fetch_manifest( 'files-hashes.json' );
			$results  = array_merge( $results, self::check_hashes( $hashes, $manifest, 'file' ) );
		}

		// Sort: malware first, then by severity desc, then alphabetical
		usort( $results, function ( $a, $b ) {
			$sa = ! empty( $a['malware'] ) ? 'malware' : $a['status'];
			$sb = ! empty( $b['malware'] ) ? 'malware' : $b['status'];
			$diff = ( self::SEVERITY_ORDER[ $sb ] ?? 0 ) - ( self::SEVERITY_ORDER[ $sa ] ?? 0 );
			return $diff !== 0 ? $diff : strcmp( $a['slug'], $b['slug'] );
		} );

		// Count summary
		$summary = [ 'clean' => 0, 'vulnerable' => 0, 'malware' => 0, 'unaudited' => 0 ];
		foreach ( $results as $r ) {
			if ( ! empty( $r['malware'] ) ) {
				$summary['malware']++;
			} elseif ( $r['status'] === 'unaudited' ) {
				$summary['unaudited']++;
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
			\WP_CLI::warning( 'This exact code has not been audited yet. Submit a build for review at https://wpregistry.io.' );
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
	 * Check local hashes against a manifest.
	 */
	private static function check_hashes( array $local_hashes, array $manifest, string $type ): array {
		$db      = (array) ( $manifest['hashes'] ?? [] );
		$results = [];

		foreach ( $local_hashes as $slug => $hash ) {
			$match = $db[ $hash ] ?? null;

			if ( $match ) {
				$match = (array) $match;
				$results[] = [
					'type'      => $type,
					'slug'      => $slug,
					'hash'      => substr( $hash, 0, 12 ),
					'status'    => $match['status'] ?? 'clean',
					'malware'   => ! empty( $match['malware'] ),
					'key_issue' => $match['key_issue'] ?? '',
				];
			} else {
				$results[] = [
					'type'      => $type,
					'slug'      => $slug,
					'hash'      => substr( $hash, 0, 12 ),
					'status'    => 'unaudited',
					'malware'   => false,
					'key_issue' => '',
				];
			}
		}

		return $results;
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
			default:          return ' ';
		}
	}
}
