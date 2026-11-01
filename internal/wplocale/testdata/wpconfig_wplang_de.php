<?php
/**
 * Fixture wp-config.php with a classic single-quoted WPLANG define.
 */
define( 'WP_HOME', 'https://example.com' );
define('WPLANG', 'de_DE');
$table_prefix = 'wp_';

/* That's all, stop editing! Happy publishing. */

/** Absolute path to the WordPress directory. */
if ( ! defined( 'ABSPATH' ) ) {
	define( 'ABSPATH', __DIR__ . '/' );
}

// define('WPLANG', 'ru_RU'); -- commented out, must be ignored
define( 'WPLANG_NOISE', 'xx_XX' ); // different constant, must be ignored
