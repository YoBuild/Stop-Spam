<?php

namespace Yohns\Security;

use Yohns\Core\Config;
use InvalidArgumentException;

/**
 * CSRFToken class for generating and validating CSRF tokens.
 *
 * This class handles the creation, validation, and management of CSRF tokens
 * to protect against Cross-Site Request Forgery attacks.
 *
 * Examples:
 * ```php
 * // Generate a CSRF token for a form
 * $token = CSRFToken::generate('login_form');
 *
 * // Validate a submitted token
 * if (CSRFToken::validate($_POST['csrf_token'], 'login_form')) {
 *     // Process the form
 * }
 *
 * // Generate a token field for HTML forms
 * echo CSRFToken::tokenField('registration_form');
 * ```
 */
class CSRFToken {
	/**
	 * @var string Session key prefix for storing tokens
	 */
	private static string $sessionPrefix = 'csrf_token_';

	/**
	 * @var int Default token expiration time in seconds (30 minutes)
	 */
	private static int $defaultExpiration = 1800;

	/**
	 * Initialize the CSRF token system.
	 *
	 * @param string|null $configFile Optional configuration file to load settings from
	 * @return void
	 */
	public static function init(?string $configFile = null): void {
		if (session_status() === PHP_SESSION_NONE) {
			session_start();
		}

		// Load configuration if provided
		if ($configFile !== null) {
			$expiration = Config::get('csrf_expiration', $configFile);
			if ($expiration !== null && is_numeric($expiration)) {
				self::$defaultExpiration = (int)$expiration;
			}

			$prefix = Config::get('csrf_session_prefix', $configFile);
			if ($prefix !== null && is_string($prefix)) {
				self::$sessionPrefix = $prefix;
			}
		}

		// Clean expired tokens on initialization
		self::cleanExpiredTokens();
	}

	/**
	 * Generate a new CSRF token for the specified context.
	 *
	 * @param string $context The context for which the token is generated (e.g., 'login_form')
	 * @param int|null $expiration Token expiration time in seconds, null for default
	 * @return string The generated token
	 */
	public static function generate(string $context, ?int $expiration = null): string {
		if (empty($context)) {
			throw new InvalidArgumentException("Context cannot be empty");
		}

		$tokenExpiration = $expiration ?? self::$defaultExpiration;
		$token = bin2hex(random_bytes(32)); // 64 character secure random token

		// Store token in session with expiration time
		$_SESSION[self::$sessionPrefix . $context] = [
			'token' => $token,
			'expires' => time() + $tokenExpiration
		];

		return $token;
	}

	/**
	 * Validate a CSRF token against the stored token for the given context.
	 *
	 * @param string $token The token to validate
	 * @param string $context The context to validate against
	 * @return bool True if the token is valid, false otherwise
	 */
	public static function validate(string $token, string $context): bool {
		if (empty($token) || empty($context)) {
			return false;
		}

		$sessionKey = self::$sessionPrefix . $context;

		// Check if token exists in session
		if (!isset($_SESSION[$sessionKey]) ||
			!isset($_SESSION[$sessionKey]['token']) ||
			!isset($_SESSION[$sessionKey]['expires'])) {
			return false;
		}

		$storedToken = $_SESSION[$sessionKey]['token'];
		$expirationTime = $_SESSION[$sessionKey]['expires'];

		// Check if token has expired
		if (time() > $expirationTime) {
			// Remove expired token
			unset($_SESSION[$sessionKey]);
			return false;
		}

		// Check if token matches
		$valid = hash_equals($storedToken, $token);

		// Rotate token if valid (one-time use)
		if ($valid) {
			self::generate($context);
		}

		return $valid;
	}

	/**
	 * Generate an HTML input field containing a CSRF token.
	 *
	 * @param string $context The context for the token
	 * @param int|null $expiration Token expiration time in seconds, null for default
	 * @return string HTML input field with token
	 */
	public static function tokenField(string $context, ?int $expiration = null): string {
		$token = self::generate($context, $expiration);
		return sprintf(
			'<input type="hidden" name="csrf_token" value="%s">',
			htmlspecialchars($token, ENT_QUOTES, 'UTF-8')
		);
	}

	/**
	 * Clean expired tokens from the session.
	 *
	 * @return void
	 */
	public static function cleanExpiredTokens(): void {
		if (empty($_SESSION)) {
			return;
		}

		$currentTime = time();

		foreach ($_SESSION as $key => $value) {
			// Only process CSRF token entries
			if (strpos($key, self::$sessionPrefix) === 0) {
				if (isset($value['expires']) && $currentTime > $value['expires']) {
					unset($_SESSION[$key]);
				}
			}
		}
	}

	/**
	 * Manually expire a token for a specific context.
	 *
	 * @param string $context The context of the token to expire
	 * @return bool True if a token was found and expired, false otherwise
	 */
	public static function expireToken(string $context): bool {
		$sessionKey = self::$sessionPrefix . $context;

		if (isset($_SESSION[$sessionKey])) {
			unset($_SESSION[$sessionKey]);
			return true;
		}

		return false;
	}
}