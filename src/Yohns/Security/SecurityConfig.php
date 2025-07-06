<?php

namespace Yohns\Security;

use Yohns\Core\Config;
use Yohns\Core\ConfigEditor;

/**
 * SecurityConfig class for managing security configuration.
 *
 * This class provides methods for loading and managing security-related
 * configuration settings for the spam prevention and security system.
 *
 * Examples:
 * ```php
 * // Load security configuration
 * $config = SecurityConfig::load();
 *
 * // Get a specific security setting
 * $csrfExpiration = SecurityConfig::get('csrf_expiration');
 *
 * // Update a security setting
 * SecurityConfig::set('honeypot_field_name', 'url');
 * ```
 */
class SecurityConfig {
	/**
	 * @var string Config file for security settings
	 */
	private static string $configFile = 'security';

	/**
	 * @var array Default security configuration
	 */
	private static array $defaults = [
		// CSRF Protection
		'csrf_enabled' => true,
		'csrf_expiration' => 1800, // 30 minutes in seconds
		'csrf_session_prefix' => 'csrf_token_',
		'csrf_header_name' => 'X-CSRF-TOKEN',
		'csrf_cookie_name' => 'XSRF-TOKEN',
		'csrf_same_site' => 'Lax',

		// Honeypot
		'honeypot_enabled' => true,
		'honeypot_field_name' => 'website',
		'honeypot_min_time' => 2, // seconds
		'honeypot_max_time' => 3600, // 1 hour in seconds
		'honeypot_session_prefix' => 'honeypot_',

		// Spam Detection
		'spam_detection_enabled' => true,
		'spam_log_enabled' => true,
		'spam_log_file' => '../logs/spam_detection.log',
		'challenge_enabled' => false,
		'js_token_secret' => '',

		// Rate Limiting
		'rate_limiting_enabled' => true,
		'rate_limit_storage' => 'database', // 'database' or 'memory'
		'rate_limit_global_max' => 1000, // requests per hour
		'rate_limit_per_endpoint' => 100, // requests per minute
		'rate_limit_per_ip' => 300, // requests per minute
		'rate_limit_login_max' => 5, // attempts per 15 minutes

		// Token Storage
		'token_storage' => 'session', // 'session' or 'database'
		'db_based_csrf_cleanup_interval' => 3600, // 1 hour in seconds
	];

	/**
	 * Load security configuration, creating it if it doesn't exist.
	 *
	 * @return array The loaded configuration
	 */
	public static function load(): array {
		$config = Config::getAll(self::$configFile);

		if ($config === null) {
			// Generate a secure random token secret if needed
			self::$defaults['js_token_secret'] = bin2hex(random_bytes(16));

			// Create configuration file with defaults
			ConfigEditor::addToConfig(self::$defaults, self::$configFile);

			return self::$defaults;
		}

		return $config;
	}

	/**
	 * Get a security configuration value.
	 *
	 * @param string $key The key of the configuration to retrieve
	 * @param mixed $default Default value if the key doesn't exist
	 * @return mixed The configuration value
	 */
	public static function get(string $key, mixed $default = null): mixed {
		$value = Config::get($key, self::$configFile);
		return $value !== null ? $value : $default;
	}

	/**
	 * Set a security configuration value.
	 *
	 * @param string $key The key of the configuration to set
	 * @param mixed $value The value to assign to the configuration
	 * @return void
	 */
	public static function set(string $key, mixed $value): void {
		Config::set($key, $value, self::$configFile);
	}

	/**
	 * Get all security settings.
	 *
	 * @return array The complete security configuration
	 */
	public static function getAll(): array {
		$config = Config::getAll(self::$configFile);

		if ($config === null) {
			return self::load();
		}

		return $config;
	}

	/**
	 * Apply security configuration to relevant classes.
	 *
	 * @return void
	 */
	public static function applyConfig(): void {
		$config = self::getAll();

		// Apply CSRF configuration
		CSRFToken::init(self::$configFile);

		// Apply Honeypot configuration
		Honeypot::init(self::$configFile);
	}
}