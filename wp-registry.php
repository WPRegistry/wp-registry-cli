<?php
/**
 * @link              https://wpregistry.io
 * @since             1.0.0
 * @package           WPRegistry
 *
 * @wordpress-plugin
 * Plugin Name:       WP Registry
 * Plugin URI:        https://wpregistry.io
 * Description:       Check your WordPress site against the WP Registry, a public database of hashed plugins, themes, and files. Hash-based vulnerability and malware detection.
 * Version:           1.0.0
 * Requires at least: 5.6
 * Requires PHP:      7.2
 * Author:            Austin Ginder
 * Author URI:        https://austinginder.com
 * License:           MIT
 * License URI:       https://opensource.org/licenses/MIT
 * Text Domain:       wp-registry
 * Update URI:        https://github.com/WPRegistry/wp-registry
 */

if ( ! defined( 'WPINC' ) ) {
	die;
}

// Guard against double-bootstrap. WP-CLI's `plugin install --force --activate`
// includes this file twice in the same process (once on activation, once on the
// follow-up plugins_loaded pass), which without _once-style guards would redeclare
// the Composer autoloader class and fatal.
if ( defined( 'WPREGISTRY_VERSION' ) ) {
	return;
}

define( 'WPREGISTRY_VERSION', '1.0.0' );
define( 'WPREGISTRY_DIR', plugin_dir_path( __FILE__ ) );

require_once WPREGISTRY_DIR . 'vendor/autoload.php';

// Self-updater via GitHub releases
new WPRegistry\Updater( __FILE__ );

// WP-CLI commands
if ( defined( 'WP_CLI' ) && WP_CLI ) {
	\WP_CLI::add_command( 'registry', 'WPRegistry\Command' );
}
