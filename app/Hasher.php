<?php

namespace WPRegistry;

/**
 * PHP port of WP Registry's bash hash_directory() algorithm.
 *
 * Produces identical SHA256 hashes to the bash version:
 *   find "$dir" -type f ... -exec sha256sum {} + | LC_ALL=C sort -k2 | sha256sum
 *
 * Including symlinks as SYMLINK:<target> entries.
 */
class Hasher {

	/**
	 * Hash a directory (plugin/theme) using the CaptainCore algorithm.
	 *
	 * Paths in the hash input are relative to wp-content/, matching the bash version
	 * which runs `find plugins/slug/ ...` from within wp-content/.
	 *
	 * @param string $dir    Absolute path to the directory (e.g., /path/wp-content/plugins/akismet).
	 * @param string $prefix Path prefix for relative paths (e.g., "plugins"). Auto-detected from parent dir name if empty.
	 * @return string SHA256 hash of the directory contents.
	 */
	public static function hash_directory( string $dir, string $prefix = '' ): string {
		if ( ! is_dir( $dir ) ) {
			return '';
		}

		// Auto-detect prefix from parent directory name (plugins/, themes/, mu-plugins/)
		if ( $prefix === '' ) {
			$prefix = basename( dirname( $dir ) );
		}

		$slug  = basename( $dir );
		$lines = [];

		$iterator = new \RecursiveIteratorIterator(
			new \RecursiveDirectoryIterator( $dir, \FilesystemIterator::SKIP_DOTS | \FilesystemIterator::CURRENT_AS_PATHNAME ),
			\RecursiveIteratorIterator::SELF_FIRST
		);

		foreach ( $iterator as $path ) {
			// Build relative path matching bash: "plugins/akismet/akismet.php"
			$relative = $prefix . '/' . $slug . '/' . ltrim( str_replace( $dir, '', $path ), '/' );

			// Skip excluded paths (matches bash find exclusions)
			if ( self::is_excluded( $relative ) ) {
				continue;
			}

			if ( is_link( $path ) ) {
				// Symlinks: hash as "SYMLINK:<target>"
				$target     = readlink( $path );
				$hash       = hash( 'sha256', "SYMLINK:{$target}" );
				$lines[]    = "{$hash}  {$relative}";
			} elseif ( is_file( $path ) ) {
				// Regular files: SHA256 of content
				$hash    = hash_file( 'sha256', $path );
				$lines[] = "{$hash}  {$relative}";
			}
		}

		// Sort by filename (column 2) using C locale — matches LC_ALL=C sort -k2
		usort( $lines, function ( $a, $b ) {
			$file_a = substr( $a, 66 ); // SHA256 (64 chars) + "  " (2 chars)
			$file_b = substr( $b, 66 );
			return strcmp( $file_a, $file_b );
		} );

		// Hash the sorted list — matches "| sha256sum"
		$combined = implode( "\n", $lines ) . "\n";
		return hash( 'sha256', $combined );
	}

	/**
	 * Hash a single file.
	 *
	 * @param string $path Absolute path to the file.
	 * @return string SHA256 hash of file contents.
	 */
	public static function hash_file( string $path ): string {
		if ( ! is_file( $path ) ) {
			return '';
		}
		return hash_file( 'sha256', $path );
	}

	/**
	 * Check if a relative path should be excluded from hashing.
	 *
	 * Applied to both directory-based hashing (plugins/themes) and loose-file
	 * hashing so that runtime cruft never enters the hash.
	 */
	public static function is_excluded( string $relative ): bool {
		if ( strpos( $relative, 'node_modules/' ) !== false ) {
			return true;
		}
		if ( strpos( $relative, '.git/' ) !== false ) {
			return true;
		}
		$basename = basename( $relative );
		if ( $basename === '.DS_Store' || $basename === 'error_log' ) {
			return true;
		}
		return false;
	}

	/**
	 * Hash all plugins and return slug => hash map.
	 *
	 * @return array [ 'akismet' => 'sha256...', ... ]
	 */
	public static function hash_plugins(): array {
		$plugins_dir = WP_CONTENT_DIR . '/plugins';
		if ( ! is_dir( $plugins_dir ) ) {
			return [];
		}

		$hashes = [];
		foreach ( glob( $plugins_dir . '/*', GLOB_ONLYDIR ) as $dir ) {
			$slug           = basename( $dir );
			$hashes[ $slug ] = self::hash_directory( $dir );
		}

		return $hashes;
	}

	/**
	 * Hash all themes and return slug => hash map.
	 *
	 * @return array [ 'twentytwentyfive' => 'sha256...', ... ]
	 */
	public static function hash_themes(): array {
		$themes_dir = WP_CONTENT_DIR . '/themes';
		if ( ! is_dir( $themes_dir ) ) {
			return [];
		}

		$hashes = [];
		foreach ( glob( $themes_dir . '/*', GLOB_ONLYDIR ) as $dir ) {
			$slug           = basename( $dir );
			$hashes[ $slug ] = self::hash_directory( $dir );
		}

		return $hashes;
	}

	/**
	 * Hash all loose PHP files in wp-content (outside plugins/themes/mu-plugins).
	 *
	 * @return array [ 'index.php' => 'sha256...', 'uploads/foo.php' => 'sha256...', ... ]
	 */
	public static function hash_loose_files(): array {
		$wpc = WP_CONTENT_DIR;
		if ( ! is_dir( $wpc ) ) {
			return [];
		}

		$excluded_dirs = [
			'plugins', 'themes', 'mu-plugins',
			'cache', 'wps-cache', 'wphb-cache',
			'updraft', 'upgrade-temp-backup', 'umbrella-upgrade-temp-backup',
		];

		$hashes   = [];
		$iterator = new \RecursiveIteratorIterator(
			new \RecursiveDirectoryIterator( $wpc, \FilesystemIterator::SKIP_DOTS ),
			\RecursiveIteratorIterator::SELF_FIRST
		);

		foreach ( $iterator as $file ) {
			if ( ! $file->isFile() || $file->getExtension() !== 'php' ) {
				continue;
			}

			$relative = ltrim( str_replace( $wpc, '', $file->getPathname() ), '/' );

			// Check if path starts with an excluded directory
			$skip = false;
			foreach ( $excluded_dirs as $excluded ) {
				if ( strpos( $relative, $excluded . '/' ) === 0 || $relative === $excluded ) {
					$skip = true;
					break;
				}
			}
			if ( $skip ) {
				continue;
			}

			// Reuse the shared exclusion list (node_modules/, .git/, .DS_Store, error_log)
			// so loose-file hashing matches the directory hasher's behavior.
			if ( self::is_excluded( $relative ) ) {
				continue;
			}

			$hashes[ $relative ] = hash_file( 'sha256', $file->getPathname() );
		}

		ksort( $hashes );
		return $hashes;
	}
}
