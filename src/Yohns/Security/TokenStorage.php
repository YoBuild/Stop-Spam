<?php

namespace Yohns\Security;

use PDOChainer\PDOChainer;
use PDOChainer\DBAL;

/**
 * TokenStorage class for storing and retrieving CSRF tokens from database.
 *
 * This class provides database storage for CSRF tokens as an alternative to
 * session-based storage, useful for stateless applications or microservices.
 *
 * Examples:
 * ```php
 * // Store a token
 * TokenStorage::store('form_id', 'token_value', 3600);
 *
 * // Retrieve a token
 * $token = TokenStorage::retrieve('form_id');
 *
 * // Validate a token
 * if (TokenStorage::validate('form_id', 'submitted_token')) {
 *     // Process the form
 * }
 * ```
 */
class TokenStorage {
	/**
	 * @var DBAL|null Database abstraction layer instance
	 */
	private static ?DBAL $db = null;

	/**
	 * Initialize the token storage with a database connection.
	 *
	 * @param PDOChainer $pdo PDO connection
	 * @return void
	 */
	public static function init(PDOChainer $pdo): void {
		self::$db = new DBAL($pdo);
	}

	/**
	 * Store a token in the database.
	 *
	 * @param string $context The context or form ID
	 * @param string $token The token value
	 * @param int $expiration Expiration time in seconds
	 * @param int|null $userId Optional user ID
	 * @return bool True if the token was stored successfully
	 */
	public static function store(string $context, string $token, int $expiration = 1800, ?int $userId = null): bool {
		if (self::$db === null) {
			throw new \RuntimeException('TokenStorage not initialized with database connection');
		}

		$expiresAt = date('Y-m-d H:i:s', time() + $expiration);
		$ipAddress = $_SERVER['REMOTE_ADDR'] ?? '0.0.0.0';
		$userAgent = $_SERVER['HTTP_USER_AGENT'] ?? '';

		$data = [
			['token', $token],
			['context', $context],
			['ip_address', $ipAddress],
			['user_agent', $userAgent],
			['expires_at', $expiresAt]
		];

		if ($userId !== null) {
			$data[] = ['user_id', $userId, \PDO::PARAM_INT];
		}

		try {
			// Insert token into database
			$result = self::$db->insert('security_csrf_tokens', $data);
			return $result > 0;
		} catch (\Throwable $e) {
			// Handle potential duplicate token
			return false;
		}
	}

	/**
	 * Retrieve a token from the database.
	 *
	 * @param string $context The context or form ID
	 * @param int|null $userId Optional user ID
	 * @return string|null The token or null if not found
	 */
	public static function retrieve(string $context, ?int $userId = null): ?string {
		if (self::$db === null) {
			throw new \RuntimeException('TokenStorage not initialized with database connection');
		}

		$sql = "SELECT token FROM security_csrf_tokens
				WHERE context = :context AND expires_at > NOW()";

		$binds = [
			[':context', $context]
		];

		if ($userId !== null) {
			$sql .= " AND user_id = :user_id";
			$binds[] = [':user_id', $userId, \PDO::PARAM_INT];
		}

		$sql .= " ORDER BY created_at DESC LIMIT 1";

		$result = self::$db->select($sql, 1, $binds);

		return $result && isset($result['token']) ? $result['token'] : null;
	}

	/**
	 * Validate a token against the stored token for the given context.
	 *
	 * @param string $context The context or form ID
	 * @param string $token The token to validate
	 * @param int|null $userId Optional user ID
	 * @param bool $deleteAfterValidation Whether to delete the token after validation
	 * @return bool True if the token is valid
	 */
	public static function validate(string $context, string $token, ?int $userId = null, bool $deleteAfterValidation = true): bool {
		if (self::$db === null) {
			throw new \RuntimeException('TokenStorage not initialized with database connection');
		}

		if (empty($token) || empty($context)) {
			return false;
		}

		$sql = "SELECT id, token FROM security_csrf_tokens
				WHERE context = :context AND token = :token AND expires_at > NOW()";

		$binds = [
			[':context', $context],
			[':token', $token]
		];

		if ($userId !== null) {
			$sql .= " AND user_id = :user_id";
			$binds[] = [':user_id', $userId, \PDO::PARAM_INT];
		}

		$sql .= " LIMIT 1";

		$result = self::$db->select($sql, 1, $binds);

		$valid = $result && isset($result['token']) && $result['token'] === $token;

		// Delete the token if valid and deleteAfterValidation is true
		if ($valid && $deleteAfterValidation && isset($result['id'])) {
			self::$db->delete('security_csrf_tokens', [
				['id', $result['id'], \PDO::PARAM_INT]
			]);
		}

		return $valid;
	}

	/**
	 * Delete expired tokens from the database.
	 *
	 * @return int Number of tokens deleted
	 */
	public static function cleanExpiredTokens(): int {
		if (self::$db === null) {
			throw new \RuntimeException('TokenStorage not initialized with database connection');
		}

		$sql = "DELETE FROM security_csrf_tokens WHERE expires_at < NOW()";

		self::$db->select($sql, 0);

		// Get the number of affected rows
		return self::$db->rowCount();
	}

	/**
	 * Delete all tokens for a specific context.
	 *
	 * @param string $context The context or form ID
	 * @param int|null $userId Optional user ID
	 * @return int Number of tokens deleted
	 */
	public static function deleteContextTokens(string $context, ?int $userId = null): int {
		if (self::$db === null) {
			throw new \RuntimeException('TokenStorage not initialized with database connection');
		}

		$data = [
			['context', $context]
		];

		if ($userId !== null) {
			$data[] = ['user_id', $userId, \PDO::PARAM_INT];
		}

		self::$db->delete('security_csrf_tokens', $data, 100); // Delete up to 100 records

		return self::$db->rowCount();
	}
}