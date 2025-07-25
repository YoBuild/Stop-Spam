<?php

namespace Yohns\Security;

use Yohns\Core\Config;

/**
 * CSRFToken class for Cross-Site Request Forgery protection
 *
 * Provides secure token generation and validation to prevent CSRF attacks.
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
	 */
	public function validateRequest(string $context = 'default'): bool {
		$token = $this->getTokenFromRequest($context);
		return $this->validateToken($token ?: '', $context);
	}

	/**
	 * Generate HTML hidden input field for forms
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
	 */
	public function regenerateToken(string $context = 'default'): string {
		$this->invalidateToken($context);
		return $this->generateToken($context);
	}

	/**
	 * Clean up expired tokens
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
	 */
	public function isEnabled(): bool {
		return $this->enabled;
	}

	/**
	 * Get token statistics
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