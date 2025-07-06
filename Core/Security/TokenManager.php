<?php

namespace Yohns\Core\Security;

use PDOChainer\PDOChainer;
use PDOChainer\DBAL;
use Yohns\Core\Config;
use RuntimeException;

/**
 * TokenManager class for generating and validating security tokens.
 *
 * This class handles CSRF protection tokens, form submission tokens,
 * and other security tokens to prevent various attacks.
 *
 * Examples:
 * ```php
 * // Generate a CSRF token for a form
 * $tokenManager = new TokenManager($pdoChainer);
 * $csrfToken = $tokenManager->generateToken('csrf', 3600); // 1 hour expiration
 *
 * // In your form
 * echo '<input type="hidden" name="csrf_token" value="' . $csrfToken . '">';
 *
 * // Later, when the form is submitted
 * if ($tokenManager->validateToken($_POST['csrf_token'], 'csrf')) {
 *     // Token is valid, process the form
 * } else {
 *     // Invalid token, reject the form
 * }
 * ```
 */
class TokenManager {
	/**
	 * @var DBAL Database abstraction layer
	 */
	private DBAL $db;

	/**
	 * @var bool Whether to store tokens in the database
	 */
	private bool $useDatabase;

	/**
	 * @var string Secret key for token generation
	 */
	private string $secretKey;

	/**
	 * @var array In-memory token cache
	 */
	private array $tokenCache = [];

	/**
	 * Constructor for TokenManager.
	 *
	 * @param PDOChainer|null $pdo PDO chain wrapper instance (if using database storage)
	 * @param bool $useDatabase Whether to store tokens in the database
	 */
	public function __construct(?PDOChainer $pdo = null, bool $useDatabase = true) {
		$this->useDatabase = $useDatabase && $pdo !== null;

		if ($this->useDatabase && $pdo !== null) {
			$this->db = new DBAL($pdo);
			$this->createTokenTableIfNotExists();
		}

		// Get secret key from config or generate a new one
		$this->secretKey = Config::get('token_secret', 'security');
		if (empty($this->secretKey)) {
			$this->secretKey = $this->generateRandomString(64);
			// Save the new secret key to config
			\Yohns\Core\ConfigEditor::addToConfig([
				'token_secret' => $this->secretKey
			], 'security');
		}
	}

	/**
	 * Generate a secure token for a specific context.
	 *
	 * @param string $context The context or purpose of the token (e.g., 'csrf', 'password_reset')
	 * @param int $expiration Expiration time in seconds (default: 3600 = 1 hour)
	 * @param array $data Additional data to associate with the token
	 * @return string The generated token
	 */
	public function generateToken(string $context, int $expiration = 3600, array $data = []): string {
		// Generate a cryptographically secure random string
		$tokenValue = $this->generateRandomString(32);

		// Calculate expiration timestamp
		$expiresAt = time() + $expiration;

		// Create token record
		$tokenRecord = [
			'token'      => $tokenValue,
			'context'    => $context,
			'expires_at' => $expiresAt,
			'data'       => json_encode($data),
			'created_at' => time()
		];

		// Store the token
		if ($this->useDatabase) {
			$this->storeTokenInDb($tokenRecord);
		} else {
			$this->storeTokenInMemory($tokenRecord);
		}

		// For CSRF tokens, also store in session
		if ($context === 'csrf') {
			if (session_status() !== PHP_SESSION_ACTIVE) {
				session_start();
			}
			$_SESSION['csrf_tokens'][$tokenValue] = $expiresAt;
		}

		return $tokenValue;
	}

	/**
	 * Validate a token.
	 *
	 * @param string $token The token to validate
	 * @param string $context The context or purpose of the token
	 * @param bool $consumeToken Whether to consume (invalidate) the token after validation
	 * @return bool True if the token is valid, false otherwise
	 */
	public function validateToken(string $token, string $context, bool $consumeToken = true): bool {
		// Special handling for CSRF tokens stored in session
		if ($context === 'csrf' && isset($_SESSION['csrf_tokens'][$token])) {
			if ($_SESSION['csrf_tokens'][$token] >= time()) {
				if ($consumeToken) {
					unset($_SESSION['csrf_tokens'][$token]);
				}
				return true;
			}
			// Token expired
			unset($_SESSION['csrf_tokens'][$token]);
			return false;
		}

		// Get token record
		$tokenRecord = $this->useDatabase ?
			$this->getTokenFromDb($token, $context) :
			$this->getTokenFromMemory($token, $context);

		// If token not found or doesn't match context
		if (empty($tokenRecord)) {
			return false;
		}

		// Check if token has expired
		if ($tokenRecord['expires_at'] < time()) {
			// Token expired, remove it
			if ($this->useDatabase) {
				$this->deleteTokenFromDb($token);
			} else {
				$this->deleteTokenFromMemory($token);
			}
			return false;
		}

		// If token should be consumed (one-time use)
		if ($consumeToken) {
			if ($this->useDatabase) {
				$this->deleteTokenFromDb($token);
			} else {
				$this->deleteTokenFromMemory($token);
			}
		}

		return true;
	}

	/**
	 * Get data associated with a token.
	 *
	 * @param string $token The token
	 * @param string $context The context or purpose of the token
	 * @return array|null The data associated with the token, or null if token is invalid
	 */
	public function getTokenData(string $token, string $context): ?array {
		// Get token record
		$tokenRecord = $this->useDatabase ?
			$this->getTokenFromDb($token, $context) :
			$this->getTokenFromMemory($token, $context);

		// If token not found, expired, or doesn't match context
		if (empty($tokenRecord) || $tokenRecord['expires_at'] < time()) {
			return null;
		}

		return json_decode($tokenRecord['data'], true) ?: [];
	}

	/**
	 * Invalidate a token.
	 *
	 * @param string $token The token to invalidate
	 * @param string $context The context or purpose of the token
	 * @return bool True if the token was invalidated, false otherwise
	 */
	public function invalidateToken(string $token, string $context): bool {
		// Special handling for CSRF tokens stored in session
		if ($context === 'csrf' && isset($_SESSION['csrf_tokens'][$token])) {
			unset($_SESSION['csrf_tokens'][$token]);
			return true;
		}

		if ($this->useDatabase) {
			return $this->deleteTokenFromDb($token) > 0;
		} else {
			return $this->deleteTokenFromMemory($token);
		}
	}

	/**
	 * Generate a CSRF token and output the HTML input field.
	 *
	 * @param int $expiration Expiration time in seconds (default: 3600 = 1 hour)
	 * @return string HTML input field with CSRF token
	 */
	public function csrfField(int $expiration = 3600): string {
		$token = $this->generateToken('csrf', $expiration);
		return '<input type="hidden" name="csrf_token" value="' . htmlspecialchars($token) . '">';
	}

	/**
	 * Validate a CSRF token from a request.
	 *
	 * @param array $request The request array ($_POST, $_GET, etc.)
	 * @param bool $consumeToken Whether to consume the token after validation
	 * @return bool True if the CSRF token is valid, false otherwise
	 */
	public function validateCsrfToken(array $request, bool $consumeToken = true): bool {
		if (!isset($request['csrf_token'])) {
			return false;
		}

		return $this->validateToken($request['csrf_token'], 'csrf', $consumeToken);
	}

	/**
	 * Clean up expired tokens.
	 *
	 * @return int Number of tokens removed
	 */
	public function cleanupExpiredTokens(): int {
		if ($this->useDatabase) {
			return $this->cleanupExpiredTokensFromDb();
		} else {
			return $this->cleanupExpiredTokensFromMemory();
		}
	}

	/**
	 * Generate a cryptographically secure random string.
	 *
	 * @param int $length Length of the random string
	 * @return string Random string
	 */
	private function generateRandomString(int $length): string {
		return bin2hex(random_bytes($length / 2));
	}

	/**
	 * Create the token table if it doesn't exist.
	 *
	 * @return void
	 */
	private function createTokenTableIfNotExists(): void {
		$sql = "CREATE TABLE IF NOT EXISTS `security_tokens` (
			`id` INT UNSIGNED NOT NULL AUTO_INCREMENT,
			`token` VARCHAR(64) NOT NULL,
			`context` VARCHAR(50) NOT NULL,
			`expires_at` INT UNSIGNED NOT NULL,
			`data` TEXT NULL,
			`created_at` INT UNSIGNED NOT NULL,
			PRIMARY KEY (`id`),
			UNIQUE INDEX `token_idx` (`token`),
			INDEX `context_idx` (`context`),
			INDEX `expires_at_idx` (`expires_at`)
		) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;";

		$this->db->select($sql, 0);
	}

	/**
	 * Store a token in the database.
	 *
	 * @param array $tokenRecord The token record
	 * @return int The inserted ID
	 */
	private function storeTokenInDb(array $tokenRecord): int {
		$data = [
			['token', $tokenRecord['token']],
			['context', $tokenRecord['context']],
			['expires_at', $tokenRecord['expires_at'], \PDO::PARAM_INT],
			['data', $tokenRecord['data']],
			['created_at', $tokenRecord['created_at'], \PDO::PARAM_INT]
		];

		return $this->db->insert('security_tokens', $data);
	}

	/**
	 * Get a token from the database.
	 *
	 * @param string $token The token
	 * @param string $context The context
	 * @return array|null The token record, or null if not found
	 */
	private function getTokenFromDb(string $token, string $context): ?array {
		$binds = [
			[':token', $token],
			[':context', $context]
		];

		$sql = "SELECT * FROM `security_tokens`
				WHERE `token` = :token
				AND `context` = :context
				LIMIT 1";

		return $this->db->select($sql, 1, $binds) ?: null;
	}

	/**
	 * Delete a token from the database.
	 *
	 * @param string $token The token
	 * @return int Number of affected rows
	 */
	private function deleteTokenFromDb(string $token): int {
		$where = [
			['token', $token]
		];

		return $this->db->delete('security_tokens', $where);
	}

	/**
	 * Clean up expired tokens from the database.
	 *
	 * @return int Number of tokens removed
	 */
	private function cleanupExpiredTokensFromDb(): int {
		$sql = "DELETE FROM `security_tokens` WHERE `expires_at` < " . time();
		$this->db->select($sql, 0);

		return $this->db->rowCount();
	}

	/**
	 * Store a token in memory.
	 *
	 * @param array $tokenRecord The token record
	 * @return void
	 */
	private function storeTokenInMemory(array $tokenRecord): void {
		$this->tokenCache[$tokenRecord['token']] = $tokenRecord;
	}

	/**
	 * Get a token from memory.
	 *
	 * @param string $token The token
	 * @param string $context The context
	 * @return array|null The token record, or null if not found
	 */
	private function getTokenFromMemory(string $token, string $context): ?array {
		if (!isset($this->tokenCache[$token]) || $this->tokenCache[$token]['context'] !== $context) {
			return null;
		}

		return $this->tokenCache[$token];
	}

	/**
	 * Delete a token from memory.
	 *
	 * @param string $token The token
	 * @return bool True if the token was deleted, false otherwise
	 */
	private function deleteTokenFromMemory(string $token): bool {
		if (!isset($this->tokenCache[$token])) {
			return false;
		}

		unset($this->tokenCache[$token]);
		return true;
	}

	/**
	 * Clean up expired tokens from memory.
	 *
	 * @return int Number of tokens removed
	 */
	private function cleanupExpiredTokensFromMemory(): int {
		$now = time();
		$count = 0;

		foreach ($this->tokenCache as $token => $record) {
			if ($record['expires_at'] < $now) {
				unset($this->tokenCache[$token]);
				$count++;
			}
		}

		return $count;
	}
}