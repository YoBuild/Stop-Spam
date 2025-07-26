<?php

namespace Yohns\Security;

use Yohns\Core\Config;

/**
 * CSRFToken class for Cross-Site Request Forgery protection
 *
 * Provides secure token generation and validation to prevent CSRF attacks.
 * Supports multiple storage backends and provides flexible integration options.
 *
 * @package Yohns\Security
 * @version 1.0.0
 * @author  Yohns Framework
 *
 * Usage example:
 * ```php
 * $csrf = new CSRFToken();
 * // In your form:
 * echo $csrf->getHiddenField('contact_form');
 * echo $csrf->getMetaTag('contact_form');
 * // In your form handler:
 * if (!$csrf->validateRequest('contact_form')) {
 *     die('CSRF token validation failed');
 * }
 * ```
 */
class CSRFToken {
	private FileStorage $storage;
	private bool        $enabled;
	private int         $expiration;
	private string      $sessionPrefix;
	private string      $headerName;
	private string      $cookieName;
	private string      $sameSite;
	private int         $tokenLength;

	/**
	 * Constructor - Initialize CSRF protection with configuration
	 *
	 * Sets up CSRF protection system with configuration from Config class.
	 * Starts session if not already active and configures token parameters.
	 *
	 * @throws \Exception If FileStorage initialization fails
	 *
	 * Usage example:
	 * ```php
	 * $csrf = new CSRFToken();
	 * // CSRF protection is now ready to use
	 * ```
	 */
	public function __construct() {
		$this->storage = new FileStorage();
		$this->enabled = Config::get('csrf.enabled', 'security') ?? true;
		$this->expiration = Config::get('csrf.expiration', 'security') ?: 1800;
		$this->sessionPrefix = Config::get('csrf.session_prefix', 'security') ?: 'csrf_token_';
		$this->headerName = Config::get('csrf.header_name', 'security') ?: 'X-CSRF-TOKEN';
		$this->cookieName = Config::get('csrf.cookie_name', 'security') ?: 'XSRF-TOKEN';
		$this->sameSite = Config::get('csrf.same_site', 'security') ?: 'Lax';
		$this->tokenLength = Config::get('csrf.token_length', 'security') ?: 32;

		// Start session if not already started
		if (session_status() === PHP_SESSION_NONE) {
			session_start();
		}
	}

	/**
	 * Generate a new CSRF token
	 *
	 * Creates a cryptographically secure token for the specified context.
	 * Stores token in session, file storage, and optionally sets a cookie.
	 *
	 * @param string $context Context identifier for the token (default: 'default')
	 * @return string Generated CSRF token or empty string if disabled
	 *
	 * Usage example:
	 * ```php
	 * $csrf = new CSRFToken();
	 * $token = $csrf->generateToken('user_profile');
	 * echo "Generated token: " . $token;
	 * // Use this token in your forms or AJAX requests
	 * ```
	 */
	public function generateToken(string $context = 'default'): string {
		if (!$this->enabled) {
			return '';
		}

		$token = bin2hex(random_bytes($this->tokenLength));
		$expiresAt = time() + $this->expiration;

		// Store in session
		$sessionKey = $this->sessionPrefix . $context;
		$_SESSION[$sessionKey] = [
			'token'      => $token,
			'expires_at' => $expiresAt,
			'created_at' => time(),
		];

		// Store in file storage for stateless applications
		$this->storage->insert('csrf_tokens', [
			'token'      => $token,
			'context'    => $context,
			'user_id'    => $_SESSION['user_id'] ?? null,
			'ip_address' => $this->getClientIP(),
			'user_agent' => $_SERVER['HTTP_USER_AGENT'] ?? '',
			'expires_at' => $expiresAt,
		]);

		// Set cookie for JavaScript access (only if headers not sent)
		if (!headers_sent()) {
			setcookie(
				$this->cookieName,
				$token,
				[
					'expires'  => $expiresAt,
					'path'     => '/',
					'domain'   => '',
					'secure'   => isset($_SERVER['HTTPS']),
					'httponly' => false, // JavaScript needs access
					'samesite' => $this->sameSite,
				]
			);
		}

		return $token;
	}

	/**
	 * Validate a CSRF token
	 *
	 * Checks if the provided token is valid for the given context.
	 * Verifies token existence, expiration, and context match.
	 *
	 * @param string $token   Token to validate
	 * @param string $context Context the token should be valid for
	 * @return bool True if token is valid, false otherwise
	 *
	 * Usage example:
	 * ```php
	 * $csrf = new CSRFToken();
	 * $isValid = $csrf->validateToken($_POST['csrf_token'], 'user_profile');
	 * if ($isValid) {
	 *     // Process form submission
	 * } else {
	 *     // Handle invalid token
	 * }
	 * ```
	 */
	public function validateToken(string $token, string $context = 'default'): bool {
		if (!$this->enabled) {
			return true;
		}

		if (empty($token)) {
			return false;
		}

		// Check session first
		$sessionKey = $this->sessionPrefix . $context;
		if (isset($_SESSION[$sessionKey])) {
			$sessionData = $_SESSION[$sessionKey];
			if ($sessionData['token'] === $token && $sessionData['expires_at'] > time()) {
				return true;
			}
		}

		// Check file storage
		$storedToken = $this->storage->findOne('csrf_tokens', [
			'token'   => $token,
			'context' => $context,
		]);

		if ($storedToken && $storedToken['expires_at'] > time()) {
			return true;
		}

		return false;
	}

	/**
	 * Get token from various sources (POST, GET, headers)
	 *
	 * Attempts to retrieve CSRF token from POST data, GET parameters,
	 * or HTTP headers in that order of priority.
	 *
	 * @param string $context Context identifier (currently unused but for future compatibility)
	 * @return string|null Found token or null if not found
	 *
	 * Usage example:
	 * ```php
	 * $csrf = new CSRFToken();
	 * $token = $csrf->getTokenFromRequest();
	 * if ($token) {
	 *     echo "Found token: " . $token;
	 * } else {
	 *     echo "No CSRF token found in request";
	 * }
	 * ```
	 */
	public function getTokenFromRequest(string $context = 'default'): ?string {
		// Check POST data
		if (isset($_POST['csrf_token'])) {
			return $_POST['csrf_token'];
		}

		// Check GET data
		if (isset($_GET['csrf_token'])) {
			return $_GET['csrf_token'];
		}

		// Check headers
		$headers = getallheaders();
		if (isset($headers[$this->headerName])) {
			return $headers[$this->headerName];
		}

		// Check alternative header formats
		$headerKey = 'HTTP_' . str_replace('-', '_', strtoupper($this->headerName));
		if (isset($_SERVER[$headerKey])) {
			return $_SERVER[$headerKey];
		}

		return null;
	}

	/**
	 * Validate token from request
	 *
	 * Convenience method that extracts token from the current request
	 * and validates it for the specified context.
	 *
	 * @param string $context Context to validate token against
	 * @return bool True if request contains valid CSRF token, false otherwise
	 *
	 * Usage example:
	 * ```php
	 * $csrf = new CSRFToken();
	 * if ($csrf->validateRequest('contact_form')) {
	 *     // Process the form submission
	 *     processContactForm($_POST);
	 * } else {
	 *     http_response_code(403);
	 *     die('CSRF validation failed');
	 * }
	 * ```
	 */
	public function validateRequest(string $context = 'default'): bool {
		$token = $this->getTokenFromRequest($context);
		return $this->validateToken($token ?: '', $context);
	}

	/**
	 * Generate HTML hidden input field for forms
	 *
	 * Creates a hidden input field containing a CSRF token for the specified context.
	 * This should be included in all forms that modify server state.
	 *
	 * @param string $context Context identifier for the token
	 * @return string HTML hidden input element or empty string if disabled
	 *
	 * Usage example:
	 * ```php
	 * $csrf = new CSRFToken();
	 * echo '<form method="post">';
	 * echo $csrf->getHiddenField('user_settings');
	 * echo '<input type="text" name="username">';
	 * echo '<button type="submit">Save</button>';
	 * echo '</form>';
	 * ```
	 */
	public function getHiddenField(string $context = 'default'): string {
		if (!$this->enabled) {
			return '';
		}

		$token = $this->generateToken($context);
		return '<input type="hidden" name="csrf_token" value="' . htmlspecialchars($token) . '">';
	}

	/**
	 * Generate meta tag for JavaScript access
	 *
	 * Creates a meta tag containing CSRF token for JavaScript/AJAX requests.
	 * Place this in your HTML head section for frontend access.
	 *
	 * @param string $context Context identifier for the token
	 * @return string HTML meta tag or empty string if disabled
	 *
	 * Usage example:
	 * ```php
	 * $csrf = new CSRFToken();
	 * echo '<head>';
	 * echo $csrf->getMetaTag('api_calls');
	 * echo '</head>';
	 * // In JavaScript: document.querySelector('meta[name="csrf-token"]').content
	 * ```
	 */
	public function getMetaTag(string $context = 'default'): string {
		if (!$this->enabled) {
			return '';
		}

		$token = $this->generateToken($context);
		return '<meta name="csrf-token" content="' . htmlspecialchars($token) . '">';
	}

	/**
	 * Invalidate a token
	 *
	 * Removes token from session, file storage, and clears associated cookie.
	 * Use this when you want to force token regeneration.
	 *
	 * @param string $context Context of token to invalidate
	 * @return void
	 *
	 * Usage example:
	 * ```php
	 * $csrf = new CSRFToken();
	 * // After successful form submission or security event
	 * $csrf->invalidateToken('user_profile');
	 * echo "Token invalidated, new token required";
	 * ```
	 */
	public function invalidateToken(string $context = 'default'): void {
		// Remove from session
		$sessionKey = $this->sessionPrefix . $context;
		unset($_SESSION[$sessionKey]);

		// Remove from file storage
		$tokens = $this->storage->find('csrf_tokens', ['context' => $context]);
		foreach ($tokens as $token) {
			$this->storage->delete('csrf_tokens', $token['id']);
		}

		// Clear cookie (only if headers not sent)
		if (!headers_sent()) {
			setcookie($this->cookieName, '', time() - 3600, '/');
		}
	}

	/**
	 * Regenerate token (for enhanced security)
	 *
	 * Invalidates the current token and generates a new one for the context.
	 * Useful for enhanced security after sensitive operations.
	 *
	 * @param string $context Context to regenerate token for
	 * @return string Newly generated CSRF token
	 *
	 * Usage example:
	 * ```php
	 * $csrf = new CSRFToken();
	 * // After password change or other sensitive operation
	 * $newToken = $csrf->regenerateToken('user_profile');
	 * echo "New token generated: " . $newToken;
	 * ```
	 */
	public function regenerateToken(string $context = 'default'): string {
		$this->invalidateToken($context);
		return $this->generateToken($context);
	}

	/**
	 * Clean up expired tokens
	 *
	 * Removes expired tokens from both session and file storage to prevent
	 * storage bloat and maintain performance.
	 *
	 * @return int Number of tokens cleaned up
	 *
	 * Usage example:
	 * ```php
	 * $csrf = new CSRFToken();
	 * $cleaned = $csrf->cleanupExpiredTokens();
	 * echo "Cleaned up {$cleaned} expired tokens";
	 * // Run this periodically via cron job
	 * ```
	 */
	public function cleanupExpiredTokens(): int {
		$tokens = $this->storage->read('csrf_tokens');
		$now = time();
		$deleted = 0;

		foreach ($tokens as $id => $token) {
			if ($token['expires_at'] <= $now) {
				$this->storage->delete('csrf_tokens', $id);
				$deleted++;
			}
		}

		// Clean up session tokens
		foreach ($_SESSION as $key => $value) {
			if (strpos($key, $this->sessionPrefix) === 0) {
				if (is_array($value) && isset($value['expires_at']) && $value['expires_at'] <= $now) {
					unset($_SESSION[$key]);
				}
			}
		}

		return $deleted;
	}

	/**
	 * Get client IP address
	 *
	 * Determines the real IP address of the client, handling various
	 * proxy and forwarding scenarios (CloudFlare, load balancers, etc.).
	 *
	 * @return string Client IP address or '0.0.0.0' if unable to determine
	 *
	 * Usage example:
	 * ```php
	 * $clientIP = $this->getClientIP();
	 * echo "Token generated for IP: " . $clientIP;
	 * // Used internally for token tracking and security
	 * ```
	 */
	private function getClientIP(): string {
		$ipKeys = ['HTTP_X_FORWARDED_FOR', 'HTTP_X_REAL_IP', 'HTTP_CLIENT_IP', 'REMOTE_ADDR'];

		foreach ($ipKeys as $key) {
			if (!empty($_SERVER[$key])) {
				$ip = $_SERVER[$key];
				// Handle comma-separated IPs (forwarded)
				if (strpos($ip, ',') !== false) {
					$ip = trim(explode(',', $ip)[0]);
				}
				// Validate IP
				if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE)) {
					return $ip;
				}
			}
		}

		return $_SERVER['REMOTE_ADDR'] ?? '0.0.0.0';
	}

	/**
	 * Check if CSRF protection is enabled
	 *
	 * Returns the current enabled status of the CSRF protection system
	 * based on configuration settings.
	 *
	 * @return bool True if CSRF protection is enabled, false otherwise
	 *
	 * Usage example:
	 * ```php
	 * $csrf = new CSRFToken();
	 * if ($csrf->isEnabled()) {
	 *     echo $csrf->getHiddenField();
	 * } else {
	 *     echo "CSRF protection is disabled";
	 * }
	 * ```
	 */
	public function isEnabled(): bool {
		return $this->enabled;
	}

	/**
	 * Get token statistics
	 *
	 * Returns comprehensive statistics about CSRF tokens including
	 * total count, active/expired breakdown, and context distribution.
	 *
	 * @return array Statistics array with 'total', 'active', 'expired', 'contexts' keys
	 *
	 * Usage example:
	 * ```php
	 * $csrf = new CSRFToken();
	 * $stats = $csrf->getStats();
	 * echo "Total tokens: " . $stats['total'];
	 * echo "Active tokens: " . $stats['active'];
	 * echo "Expired tokens: " . $stats['expired'];
	 * print_r($stats['contexts']);
	 * ```
	 */
	public function getStats(): array {
		$tokens = $this->storage->read('csrf_tokens');
		$now = time();

		$stats = [
			'total'    => count($tokens),
			'active'   => 0,
			'expired'  => 0,
			'contexts' => [],
		];

		foreach ($tokens as $token) {
			if ($token['expires_at'] > $now) {
				$stats['active']++;
			} else {
				$stats['expired']++;
			}

			$context = $token['context'] ?? 'default';
			$stats['contexts'][$context] = ($stats['contexts'][$context] ?? 0) + 1;
		}

		return $stats;
	}
}