<?php

namespace WPRegistry;

class Updater {

	public $plugin_slug;
	public $plugin_basename;
	public $version;
	public $cache_key;

	public function __construct( string $plugin_file = '' ) {
		$file = $plugin_file !== '' ? $plugin_file : dirname( __DIR__ ) . '/wp-registry-cli.php';

		// plugin_basename gives "wp-registry-cli/wp-registry-cli.php" regardless of how
		// the folder or bootstrap is named — surviving any future renames.
		$this->plugin_basename = plugin_basename( $file );
		$this->plugin_slug     = dirname( $this->plugin_basename );
		$this->version         = WPREGISTRY_VERSION;
		$this->cache_key       = 'wpregistry_updater';

		add_filter( 'plugins_api', [ $this, 'info' ], 30, 3 );
		add_filter( 'site_transient_update_plugins', [ $this, 'update' ] );
		add_action( 'upgrader_process_complete', [ $this, 'purge' ], 10, 2 );
	}

	public function request() {
		$manifest_file  = dirname( __DIR__ ) . '/manifest.json';
		$local_manifest = null;
		if ( file_exists( $manifest_file ) ) {
			$local_manifest = json_decode( file_get_contents( $manifest_file ) );
		}
		if ( ! is_object( $local_manifest ) ) {
			$local_manifest = new \stdClass();
		}

		$remote = get_transient( $this->cache_key );

		// Sentinel value cached after a failed fetch — avoids hammering GitHub
		// (and spamming the error log) when the repo or release is unavailable.
		// Cached for HOUR_IN_SECONDS, so transient retries happen at most hourly.
		if ( 'failed' === $remote ) {
			return $local_manifest;
		}

		if ( false === $remote ) {
			$manifest_url = 'https://raw.githubusercontent.com/WPRegistry/wp-registry-cli/main/manifest.json';
			$response     = wp_remote_get(
				$manifest_url,
				[ 'timeout' => 30, 'headers' => [ 'Accept' => 'application/json' ] ]
			);

			$fail_reason = null;
			if ( is_wp_error( $response ) ) {
				$fail_reason = $response->get_error_message();
			} else {
				$code = wp_remote_retrieve_response_code( $response );
				$body = wp_remote_retrieve_body( $response );
				if ( 200 !== $code || empty( $body ) ) {
					$fail_reason = "HTTP {$code}";
				} else {
					$remote = json_decode( $body );
				}
			}

			if ( $fail_reason !== null ) {
				// Cache the failure so we don't retry for an hour. Only log when
				// WP_DEBUG is on so production sites with EOL'd repos stay quiet.
				set_transient( $this->cache_key, 'failed', HOUR_IN_SECONDS );
				if ( defined( 'WP_DEBUG' ) && WP_DEBUG ) {
					error_log( "[wp-registry-cli] manifest fetch failed ({$fail_reason}) from {$manifest_url}" );
				}
				return $local_manifest;
			}

			set_transient( $this->cache_key, $remote, DAY_IN_SECONDS );
		}

		return is_object( $remote ) ? $remote : $local_manifest;
	}

	public function info( $response, $action, $args ) {
		if ( 'plugin_information' !== $action || empty( $args->slug ) || $this->plugin_slug !== $args->slug ) {
			return $response;
		}

		$remote = $this->request();
		if ( ! $remote ) {
			return $response;
		}

		$response                 = new \stdClass();
		$response->name           = $remote->name ?? 'WP Registry';
		$response->slug           = $remote->slug ?? $this->plugin_slug;
		$response->version        = $remote->version ?? $this->version;
		$response->tested         = $remote->tested ?? '';
		$response->requires       = $remote->requires ?? '';
		$response->author         = $remote->author ?? '';
		$response->author_profile = $remote->author_profile ?? '';
		$response->homepage       = $remote->homepage ?? '';
		$response->download_link  = $remote->download_url ?? '';
		$response->trunk          = $remote->download_url ?? '';
		$response->requires_php   = $remote->requires_php ?? '';
		$response->last_updated   = $remote->last_updated ?? '';
		$response->sections       = [ 'description' => $remote->sections->description ?? '' ];

		if ( ! empty( $remote->banners ) ) {
			$response->banners = [
				'low'  => $remote->banners->low ?? '',
				'high' => $remote->banners->high ?? '',
			];
		}

		return $response;
	}

	public function update( $transient ) {
		if ( empty( $transient->checked ) ) {
			return $transient;
		}

		$remote = $this->request();
		if ( $remote && isset( $remote->version ) && version_compare( $this->version, $remote->version, '<' ) ) {
			$response              = new \stdClass();
			$response->slug        = $this->plugin_slug;
			$response->plugin      = $this->plugin_basename;
			$response->new_version = $remote->version;
			$response->package     = $remote->download_url;
			$response->tested      = $remote->tested ?? '';
			$response->requires_php = $remote->requires_php ?? '';
			$transient->response[ $response->plugin ] = $response;
		}

		return $transient;
	}

	public function purge( $upgrader, $options ) {
		if ( 'update' === $options['action'] && 'plugin' === $options['type'] ) {
			delete_transient( $this->cache_key );
		}
	}
}
