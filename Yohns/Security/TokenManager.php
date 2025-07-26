<?php

namespace Yohns\Security;

use Yohns\Core\Config;

/**
 * TokenManager class for managing various types of security tokens
 *
 * Handles API tokens, session tokens, verification tokens, and more.
 * Provides comprehensive token lifecycle management including generation,
 * validation, expiration, and usage tracking.
 *
 * @package Yohns\Security
 * @version 1.0.0
 * @author  Yohns Framework
 *
 * Usage example:
 * ```php
 * $tokenManager = new TokenManager();
 * // Generate API token
 * $apiToken = $tokenManager->generateAPIToken(123, ['read', 'write']);
 * // Validate token
 * $result = $tokenManager->validateToken($apiToken, 'api_access');
 * if ($result['is_valid']) {
 *     echo "Token is valid!";
 * }
 * ```
 */
class TokenManager {
	private FileStorage $storage;
	private bool        $enabled;
	private int         $defaultExpiration;
	private array       $tokenTypes;
	/**
	 * Constructor - Initialize token management system
	 *
	 * Sets up token management with configuration from Config class
	 * and initializes token type definitions and storage.
	 *
	 * @throws \Exception If FileStorage initialization fails
	 *
	 * Usage example:
	 * ```php
	 * $tokenManager = new TokenManager();
	 * // Token management system is now ready
	 * ```
	 */
	public function __construct() {
		$this->storage = new FileStorage();
		$this->enabled = Config::get('token_management.enabled', 'security') ?? true;
		$this->defaultExpiration = Config::get('token_management.default_expiration', 'security') ?: 3600;

		$this->initializeTokenTypes();
	}

	/**
	 * Generate a new token
	 *
	 * Creates a new security token of the specified type with associated data
	 * and expiration. Stores token securely and logs the generation event.
	 *
	 * @param string   $type      Token type (e.g., 'api_access', 'email_verification')
	 * @param array    $data      Associated data to store with token
	 * @param int|null $expiresIn Expiration time in seconds (null uses type default)
	 * @return string Generated token string
	 * @throws \RuntimeException If token management is disabled
	 *
	 * Usage example:
	 * ```php
	 * $tokenManager = new TokenManager();
	 * $token = $tokenManager->generateToken('api_access', [
	 *     'user_id' => 123,
	 *     'permissions' => ['read', 'write']
	 * ], 86400);
	 * echo "Generated token: " . $token;
	 * ```
	 */
	public function generateToken(string $type, array $data = [], int $expiresIn = null): string {
		if (!$this->enabled) {
			throw new \RuntimeException('Token management is disabled');
		}

		$tokenConfig = $this->tokenTypes[$type] ?? $this->tokenTypes['default'];
		$expiresIn = $expiresIn ?: $tokenConfig['expiration'];

		$token = $this->createSecureToken($tokenConfig['length']);
		$expiresAt = time() + $expiresIn;

		$tokenData = [
			'token'       => $token,
			'type'        => $type,
			'data'        => json_encode($data),
			'expires_at'  => $expiresAt,
			'ip_address'  => $this->getClientIP(),
			'user_agent'  => $_SERVER['HTTP_USER_AGENT'] ?? '',
			'user_id'     => $_SESSION['user_id'] ?? null,
			'is_active'   => true,
			'usage_count' => 0,
			'max_usage'   => $tokenConfig['max_usage'] ?? null,
		];

		$this->storage->insert('security_tokens', $tokenData);

		$this->logTokenEvent('token_generated', [
			'type'       => $type,
			'expires_in' => $expiresIn,
			'token_hash' => hash('sha256', $token),
		]);

		return $token;
	}

	/**
	 * Validate a token
	 *
	 * Checks if a token is valid, not expired, and matches expected type.
	 * Updates usage count and handles single-use token deactivation.
	 *
	 * @param string      $token        Token to validate
	 * @param string|null $expectedType Expected token type (null accepts any)
	 * @param bool        $singleUse    Whether to deactivate token after validation
	 * @return array Validation result with validity, data, error, and remaining uses
	 *
	 * Usage example:
	 * ```php
	 * $tokenManager = new TokenManager();
	 * $result = $tokenManager->validateToken($userToken, 'email_verification', true);
	 * if ($result['is_valid']) {
	 *     $userData = $result['token_data'];
	 *     echo "Email verified for: " . $userData['email'];
	 * } else {
	 *     echo "Validation failed: " . $result['error'];
	 * }
	 * ```
	 */
	public function validateToken(string $token, string $expectedType = null, bool $singleUse = false): array {
		$result = [
			'is_valid'       => false,
			'token_data'     => null,
			'error'          => '',
			'remaining_uses' => 0,
		];

		if (!$this->enabled) {
			$result['error'] = 'Token management is disabled';
			return $result;
		}

		$tokenRecord = $this->storage->findOne('security_tokens', [
			'token'     => $token,
			'is_active' => true,
		]);

		if (!$tokenRecord) {
			$result['error'] = 'Token not found or inactive';
			$this->logTokenEvent('token_not_found', ['token_hash' => hash('sha256', $token)]);
			return $result;
		}

		// Check expiration
		if ($tokenRecord['expires_at'] < time()) {
			$result['error'] = 'Token has expired';
			$this->deactivateToken($token);
			$this->logTokenEvent('token_expired', ['token_hash' => hash('sha256', $token)]);
			return $result;
		}

		// Check type if specified
		if ($expectedType && $tokenRecord['type'] !== $expectedType) {
			$result['error'] = 'Token type mismatch';
			$this->logTokenEvent('token_type_mismatch', [
				'token_hash' => hash('sha256', $token),
				'expected'   => $expectedType,
				'actual'     => $tokenRecord['type'],
			]);
			return $result;
		}

		// Check usage limits
		$usageCount = $tokenRecord['usage_count'] ?? 0;
		$maxUsage = $tokenRecord['max_usage'];

		if ($maxUsage && $usageCount >= $maxUsage) {
			$result['error'] = 'Token usage limit exceeded';
			$this->deactivateToken($token);
			$this->logTokenEvent('token_usage_exceeded', ['token_hash' => hash('sha256', $token)]);
			return $result;
		}

		// Update usage count
		$newUsageCount = $usageCount + 1;
		$this->storage->update('security_tokens', $tokenRecord['id'], [
			'usage_count'  => $newUsageCount,
			'last_used_at' => time(),
			'last_used_ip' => $this->getClientIP(),
		]);

		// Deactivate if single use or max usage reached
		if ($singleUse || ($maxUsage && $newUsageCount >= $maxUsage)) {
			$this->deactivateToken($token);
		}

		$result['is_valid'] = true;
		$result['token_data'] = json_decode($tokenRecord['data'] ?? '{}', true);
		$result['remaining_uses'] = $maxUsage ? max(0, $maxUsage - $newUsageCount) : -1;

		$this->logTokenEvent('token_validated', [
			'type'        => $tokenRecord['type'],
			'usage_count' => $newUsageCount,
			'token_hash'  => hash('sha256', $token),
		]);

		return $result;
	}

	/**
	 * Generate API token for user
	 *
	 * Creates a long-lived API access token for a user with specific permissions.
	 * Typically used for programmatic access to APIs.
	 *
	 * @param int        $userId      User ID to generate token for
	 * @param array      $permissions Array of permissions for this token
	 * @param int|null   $expiresIn   Expiration time in seconds (default: 30 days)
	 * @return string Generated API token
	 *
	 * Usage example:
	 * ```php
	 * $tokenManager = new TokenManager();
	 * $apiToken = $tokenManager->generateAPIToken(123, [
	 *     'users:read', 'posts:write', 'comments:delete'
	 * ], 86400 * 90); // 90 days
	 * echo "API Token: " . $apiToken;
	 * ```
	 */
	public function generateAPIToken(int $userId, array $permissions = [], int $expiresIn = null): string {
		$data = [
			'user_id'      => $userId,
			'permissions'  => $permissions,
			'generated_at' => time(),
		];

		$expiresIn = $expiresIn ?: (86400 * 30); // 30 days default for API tokens

		return $this->generateToken('api_access', $data, $expiresIn);
	}

	/**
	 * Generate email verification token
	 *
	 * Creates a single-use token for email address verification.
	 * Token expires after 1 hour and can only be used once.
	 *
	 * @param string   $email  Email address to verify
	 * @param int|null $userId User ID (optional)
	 * @return string Generated email verification token
	 *
	 * Usage example:
	 * ```php
	 * $tokenManager = new TokenManager();
	 * $verifyToken = $tokenManager->generateEmailVerificationToken('user@example.com', 123);
	 * $verifyUrl = "https://example.com/verify?token=" . $verifyToken;
	 * // Send verification email with $verifyUrl
	 * ```
	 */
	public function generateEmailVerificationToken(string $email, int $userId = null): string {
		$data = [
			'email'             => $email,
			'user_id'           => $userId,
			'verification_type' => 'email',
		];

		return $this->generateToken('email_verification', $data, 3600); // 1 hour
	}

	/**
	 * Generate password reset token
	 *
	 * Creates a single-use token for password reset functionality.
	 * Invalidates any existing password reset tokens for the user.
	 *
	 * @param int    $userId User ID requesting password reset
	 * @param string $email  User's email address
	 * @return string Generated password reset token
	 *
	 * Usage example:
	 * ```php
	 * $tokenManager = new TokenManager();
	 * $resetToken = $tokenManager->generatePasswordResetToken(123, 'user@example.com');
	 * $resetUrl = "https://example.com/reset-password?token=" . $resetToken;
	 * // Send password reset email with $resetUrl
	 * ```
	 */
	public function generatePasswordResetToken(int $userId, string $email): string {
		// Invalidate any existing password reset tokens for this user
		$this->invalidateTokensByData(['user_id' => $userId], 'password_reset');

		$data = [
			'user_id'    => $userId,
			'email'      => $email,
			'reset_type' => 'password',
		];

		return $this->generateToken('password_reset', $data, 1800); // 30 minutes
	}

	/**
	 * Generate two-factor authentication token
	 *
	 * Creates a short-lived token for two-factor authentication process.
	 * Token expires after 5 minutes and is single-use.
	 *
	 * @param int $userId User ID for 2FA process
	 * @return string Generated 2FA token
	 *
	 * Usage example:
	 * ```php
	 * $tokenManager = new TokenManager();
	 * $twoFAToken = $tokenManager->generate2FAToken(123);
	 * $_SESSION['2fa_token'] = $twoFAToken;
	 * // Use token to verify second factor
	 * ```
	 */
	public function generate2FAToken(int $userId): string {
		$data = [
			'user_id'   => $userId,
			'auth_step' => '2fa',
		];

		return $this->generateToken('two_factor', $data, 300); // 5 minutes
	}

	/**
	 * Generate session token
	 *
	 * Creates a token for session management with configurable lifetime.
	 * Used to maintain user sessions across requests.
	 *
	 * @param int   $userId      User ID for the session
	 * @param array $sessionData Additional session data to store
	 * @return string Generated session token
	 *
	 * Usage example:
	 * ```php
	 * $tokenManager = new TokenManager();
	 * $sessionToken = $tokenManager->generateSessionToken(123, [
	 *     'role' => 'admin',
	 *     'login_time' => time(),
	 *     'ip_address' => $_SERVER['REMOTE_ADDR']
	 * ]);
	 * setcookie('session_token', $sessionToken, time() + 86400);
	 * ```
	 */
	public function generateSessionToken(int $userId, array $sessionData = []): string {
		$data = array_merge([
			'user_id'       => $userId,
			'session_start' => time(),
		], $sessionData);

		$expiresIn = Config::get('session.lifetime', 'security') ?: 86400; // 24 hours default

		return $this->generateToken('session', $data, $expiresIn);
	}

	/**
	 * Generate file upload token
	 *
	 * Creates a token for secure file upload with specific constraints
	 * like file size limits and allowed types.
	 *
	 * @param array $uploadConfig Upload configuration (max_size, allowed_types, path)
	 * @return string Generated upload token
	 *
	 * Usage example:
	 * ```php
	 * $tokenManager = new TokenManager();
	 * $uploadToken = $tokenManager->generateUploadToken([
	 *     'max_size' => 5242880, // 5MB
	 *     'allowed_types' => ['image/jpeg', 'image/png', 'application/pdf'],
	 *     'path' => '/uploads/documents'
	 * ]);
	 * echo "Upload token: " . $uploadToken;
	 * ```
	 */
	public function generateUploadToken(array $uploadConfig): string {
		$data = [
			'max_file_size' => $uploadConfig['max_size'] ?? 10485760, // 10MB default
			'allowed_types' => $uploadConfig['allowed_types'] ?? ['image/jpeg', 'image/png'],
			'upload_path'   => $uploadConfig['path'] ?? '/tmp',
		];

		return $this->generateToken('file_upload', $data, 1800); // 30 minutes
	}

	/**
	 * Deactivate a token
	 *
	 * Marks a token as inactive, preventing further use.
	 * Logs the deactivation event for audit purposes.
	 *
	 * @param string $token Token to deactivate
	 * @return bool True if token was deactivated, false if not found
	 *
	 * Usage example:
	 * ```php
	 * $tokenManager = new TokenManager();
	 * if ($tokenManager->deactivateToken($suspiciousToken)) {
	 *     echo "Token deactivated successfully";
	 * } else {
	 *     echo "Token not found";
	 * }
	 * ```
	 */
	public function deactivateToken(string $token): bool {
		$tokenRecord = $this->storage->findOne('security_tokens', ['token' => $token]);

		if (!$tokenRecord) {
			return false;
		}

		$updated = $this->storage->update('security_tokens', $tokenRecord['id'], [
			'is_active'      => false,
			'deactivated_at' => time(),
		]);

		if ($updated) {
			$this->logTokenEvent('token_deactivated', [
				'type'       => $tokenRecord['type'],
				'token_hash' => hash('sha256', $token),
			]);
		}

		return $updated;
	}

	/**
	 * Invalidate tokens by criteria
	 *
	 * Deactivates multiple tokens that match specific data criteria.
	 * Useful for bulk operations like revoking all tokens for a user.
	 *
	 * @param array       $criteria Key-value pairs to match in token data
	 * @param string|null $type     Optional token type filter
	 * @return int Number of tokens invalidated
	 *
	 * Usage example:
	 * ```php
	 * $tokenManager = new TokenManager();
	 * // Revoke all API tokens for user 123
	 * $revoked = $tokenManager->invalidateTokensByData(['user_id' => 123], 'api_access');
	 * echo "Revoked {$revoked} API tokens";
	 * ```
	 */
	public function invalidateTokensByData(array $criteria, string $type = null): int {
		$searchCriteria = ['is_active' => true];
		if ($type) {
			$searchCriteria['type'] = $type;
		}

		$tokens = $this->storage->find('security_tokens', $searchCriteria);
		$invalidated = 0;

		foreach ($tokens as $token) {
			$tokenData = json_decode($token['data'] ?? '{}', true);

			$matches = true;
			foreach ($criteria as $key => $value) {
				if (!isset($tokenData[$key]) || $tokenData[$key] !== $value) {
					$matches = false;
					break;
				}
			}

			if ($matches) {
				$this->storage->update('security_tokens', $token['id'], [
					'is_active'      => false,
					'deactivated_at' => time(),
				]);
				$invalidated++;
			}
		}

		if ($invalidated > 0) {
			$this->logTokenEvent('tokens_invalidated', [
				'count'    => $invalidated,
				'criteria' => $criteria,
				'type'     => $type,
			]);
		}

		return $invalidated;
	}

	/**
	 * Refresh token (extend expiration)
	 *
	 * Extends the expiration time of an active token by the specified
	 * additional time or the token type's default expiration.
	 *
	 * @param string   $token          Token to refresh
	 * @param int|null $additionalTime Additional time in seconds (null uses type default)
	 * @return bool True if token was refreshed, false if not found
	 *
	 * Usage example:
	 * ```php
	 * $tokenManager = new TokenManager();
	 * if ($tokenManager->refreshToken($sessionToken, 3600)) {
	 *     echo "Session extended by 1 hour";
	 * }
	 * ```
	 */
	public function refreshToken(string $token, int $additionalTime = null): bool {
		$tokenRecord = $this->storage->findOne('security_tokens', [
			'token'     => $token,
			'is_active' => true,
		]);

		if (!$tokenRecord) {
			return false;
		}

		$tokenConfig = $this->tokenTypes[$tokenRecord['type']] ?? $this->tokenTypes['default'];
		$extensionTime = $additionalTime ?: $tokenConfig['expiration'];
		$newExpiresAt = time() + $extensionTime;

		$updated = $this->storage->update('security_tokens', $tokenRecord['id'], [
			'expires_at'   => $newExpiresAt,
			'refreshed_at' => time(),
		]);

		if ($updated) {
			$this->logTokenEvent('token_refreshed', [
				'type'           => $tokenRecord['type'],
				'extension_time' => $extensionTime,
				'token_hash'     => hash('sha256', $token),
			]);
		}

		return $updated;
	}

	/**
	 * Get token information without validating
	 *
	 * Retrieves token metadata and configuration without performing
	 * validation or updating usage counts.
	 *
	 * @param string $token Token to get information for
	 * @return array|null Token information or null if not found
	 *
	 * Usage example:
	 * ```php
	 * $tokenManager = new TokenManager();
	 * $info = $tokenManager->getTokenInfo($userToken);
	 * if ($info) {
	 *     echo "Token type: " . $info['type'];
	 *     echo "Expires at: " . date('Y-m-d H:i:s', $info['expires_at']);
	 *     echo "Usage count: " . $info['usage_count'];
	 * }
	 * ```
	 */
	public function getTokenInfo(string $token): ?array {
		$tokenRecord = $this->storage->findOne('security_tokens', ['token' => $token]);

		if (!$tokenRecord) {
			return null;
		}

		return [
			'type'        => $tokenRecord['type'],
			'created_at'  => $tokenRecord['created_at'] ?? 0,
			'expires_at'  => $tokenRecord['expires_at'],
			'is_active'   => $tokenRecord['is_active'],
			'usage_count' => $tokenRecord['usage_count'] ?? 0,
			'max_usage'   => $tokenRecord['max_usage'],
			'data'        => json_decode($tokenRecord['data'] ?? '{}', true),
		];
	}

	/**
	 * Get tokens for user
	 *
	 * Retrieves all active tokens for a specific user, optionally
	 * filtered by token type.
	 *
	 * @param int         $userId User ID to get tokens for
	 * @param string|null $type   Optional token type filter
	 * @return array Array of user's tokens with metadata
	 *
	 * Usage example:
	 * ```php
	 * $tokenManager = new TokenManager();
	 * $userTokens = $tokenManager->getUserTokens(123, 'api_access');
	 * foreach ($userTokens as $token) {
	 *     echo "API token created: " . date('Y-m-d', $token['created_at']);
	 *     echo "Usage count: " . $token['usage_count'];
	 * }
	 * ```
	 */
	public function getUserTokens(int $userId, string $type = null): array {
		$criteria = ['is_active' => true];
		if ($type) {
			$criteria['type'] = $type;
		}

		$tokens = $this->storage->find('security_tokens', $criteria);
		$userTokens = [];

		foreach ($tokens as $token) {
			$tokenData = json_decode($token['data'] ?? '{}', true);

			if (isset($tokenData['user_id']) && $tokenData['user_id'] === $userId) {
				$userTokens[] = [
					'type'         => $token['type'],
					'created_at'   => $token['created_at'] ?? 0,
					'expires_at'   => $token['expires_at'],
					'usage_count'  => $token['usage_count'] ?? 0,
					'last_used_at' => $token['last_used_at'] ?? null,
				];
			}
		}

		return $userTokens;
	}

	/**
	 * Clean up expired tokens
	 *
	 * Removes all expired tokens from storage to prevent database bloat
	 * and maintain performance. Logs cleanup statistics.
	 *
	 * @return int Number of expired tokens cleaned up
	 *
	 * Usage example:
	 * ```php
	 * $tokenManager = new TokenManager();
	 * $cleaned = $tokenManager->cleanupExpiredTokens();
	 * echo "Cleaned up {$cleaned} expired tokens";
	 * // Run this periodically via cron job
	 * ```
	 */
	public function cleanupExpiredTokens(): int {
		$tokens = $this->storage->read('security_tokens');
		$now = time();
		$cleaned = 0;

		foreach ($tokens as $id => $token) {
			if ($token['expires_at'] < $now) {
				$this->storage->delete('security_tokens', $id);
				$cleaned++;
			}
		}

		if ($cleaned > 0) {
			$this->logTokenEvent('tokens_cleaned', ['count' => $cleaned]);
		}

		return $cleaned;
	}

	/**
	 * Create cryptographically secure token
	 *
	 * Generates a cryptographically secure random token using
	 * PHP's random_bytes function for maximum security.
	 *
	 * @param int $length Token length in bytes (default: 32)
	 * @return string Hexadecimal representation of secure random token
	 *
	 * Usage example:
	 * ```php
	 * $secureToken = $this->createSecureToken(64);
	 * // Returns 128-character hex string (64 bytes)
	 * ```
	 */
	private function createSecureToken(int $length = 32): string {
		return bin2hex(random_bytes($length));
	}

	/**
	 * Get client IP address
	 *
	 * Determines the real IP address of the client by checking various
	 * headers in order of priority, handling proxy scenarios.
	 *
	 * @return string Client IP address or '0.0.0.0' if unable to determine
	 *
	 * Usage example:
	 * ```php
	 * $clientIP = $this->getClientIP();
	 * // Used internally for token tracking and security logging
	 * ```
	 */
	private function getClientIP(): string {
		$ipKeys = ['HTTP_X_FORWARDED_FOR', 'HTTP_X_REAL_IP', 'HTTP_CLIENT_IP', 'REMOTE_ADDR'];

		foreach ($ipKeys as $key) {
			if (!empty($_SERVER[$key])) {
				$ip = $_SERVER[$key];
				if (strpos($ip, ',') !== false) {
					$ip = trim(explode(',', $ip)[0]);
				}
				if (filter_var($ip, FILTER_VALIDATE_IP)) {
					return $ip;
				}
			}
		}

		return $_SERVER['REMOTE_ADDR'] ?? '0.0.0.0';
	}

	/**
	 * Initialize token types and their configurations
	 *
	 * Sets up default token type configurations including length,
	 * expiration times, usage limits, and descriptions.
	 *
	 * @return void
	 *
	 * Usage example:
	 * ```php
	 * $this->initializeTokenTypes();
	 * // Token type configurations are now loaded
	 * ```
	 */
	private function initializeTokenTypes(): void {
		$this->tokenTypes = [
			'api_access'         => [
				'length'      => 32,
				'expiration'  => 86400 * 30, // 30 days
				'max_usage'   => null, // unlimited
				'description' => 'API access token',
			],
			'email_verification' => [
				'length'      => 32,
				'expiration'  => 3600, // 1 hour
				'max_usage'   => 1, // single use
				'description' => 'Email verification token',
			],
			'password_reset'     => [
				'length'      => 32,
				'expiration'  => 1800, // 30 minutes
				'max_usage'   => 1, // single use
				'description' => 'Password reset token',
			],
			'two_factor'         => [
				'length'      => 16,
				'expiration'  => 300, // 5 minutes
				'max_usage'   => 1, // single use
				'description' => '2FA verification token',
			],
			'session'            => [
				'length'      => 48,
				'expiration'  => 86400, // 24 hours
				'max_usage'   => null, // unlimited
				'description' => 'Session token',
			],
			'file_upload'        => [
				'length'      => 24,
				'expiration'  => 1800, // 30 minutes
				'max_usage'   => 10, // max 10 files
				'description' => 'File upload token',
			],
			'webhook'            => [
				'length'      => 40,
				'expiration'  => 86400 * 365, // 1 year
				'max_usage'   => null, // unlimited
				'description' => 'Webhook verification token',
			],
			'temporary_access'   => [
				'length'      => 28,
				'expiration'  => 900, // 15 minutes
				'max_usage'   => 3, // limited use
				'description' => 'Temporary access token',
			],
			'default'            => [
				'length'      => 32,
				'expiration'  => 3600, // 1 hour
				'max_usage'   => null,
				'description' => 'Default token type',
			],
		];
	}

	/**
	 * Log token-related events
	 *
	 * Records token management events for security auditing and
	 * monitoring purposes with appropriate severity levels.
	 *
	 * @param string $eventType Type of token event
	 * @param array  $details   Event details and context
	 * @return void
	 *
	 * Usage example:
	 * ```php
	 * $this->logTokenEvent('token_generated', [
	 *     'type' => 'api_access',
	 *     'user_id' => 123,
	 *     'expires_in' => 86400
	 * ]);
	 * ```
	 */
	private function logTokenEvent(string $eventType, array $details): void {
		$this->storage->insert('token_log', [
			'event_type' => $eventType,
			'ip_address' => $this->getClientIP(),
			'user_agent' => $_SERVER['HTTP_USER_AGENT'] ?? '',
			'user_id'    => $_SESSION['user_id'] ?? null,
			'details'    => json_encode($details),
			'severity'   => $this->getEventSeverity($eventType),
		]);
	}

	/**
	 * Get event severity level
	 *
	 * Determines the appropriate severity level for token events
	 * based on event type for proper logging and alerting.
	 *
	 * @param string $eventType Token event type
	 * @return string Severity level ('info', 'warning', 'error')
	 *
	 * Usage example:
	 * ```php
	 * $severity = $this->getEventSeverity('token_not_found');
	 * // Returns 'warning' for security-related events
	 * ```
	 */
	private function getEventSeverity(string $eventType): string {
		$severityMap = [
			'token_generated'      => 'info',
			'token_validated'      => 'info',
			'token_deactivated'    => 'info',
			'token_refreshed'      => 'info',
			'tokens_cleaned'       => 'info',
			'tokens_invalidated'   => 'warning',
			'token_not_found'      => 'warning',
			'token_expired'        => 'warning',
			'token_type_mismatch'  => 'error',
			'token_usage_exceeded' => 'error',
		];

		return $severityMap[$eventType] ?? 'info';
	}

	/**
	 * Get token statistics
	 *
	 * Returns comprehensive statistics about token usage including
	 * counts, types breakdown, and validation metrics.
	 *
	 * @return array Token statistics with counts, breakdowns, and usage data
	 *
	 * Usage example:
	 * ```php
	 * $tokenManager = new TokenManager();
	 * $stats = $tokenManager->getTokenStats();
	 * echo "Active tokens: " . $stats['active_tokens'];
	 * echo "Total validations: " . $stats['usage_stats']['total_validations'];
	 * foreach ($stats['type_breakdown'] as $type => $count) {
	 *     echo "Type {$type}: {$count} tokens";
	 * }
	 * ```
	 */
	public function getTokenStats(): array {
		$tokens = $this->storage->read('security_tokens');
		$tokenLog = $this->storage->read('token_log');
		$now = time();
		$recentCutoff = $now - 86400; // Last 24 hours

		$stats = [
			'total_tokens'   => count($tokens),
			'active_tokens'  => 0,
			'expired_tokens' => 0,
			'type_breakdown' => [],
			'recent_events'  => 0,
			'usage_stats'    => [
				'total_validations'  => 0,
				'failed_validations' => 0,
			],
		];

		// Analyze tokens
		foreach ($tokens as $token) {
			if ($token['is_active']) {
				if ($token['expires_at'] > $now) {
					$stats['active_tokens']++;
				} else {
					$stats['expired_tokens']++;
				}
			}

			$type = $token['type'] ?? 'unknown';
			$stats['type_breakdown'][$type] = ($stats['type_breakdown'][$type] ?? 0) + 1;
		}

		// Analyze events
		foreach ($tokenLog as $event) {
			if (($event['created_at'] ?? 0) > $recentCutoff) {
				$stats['recent_events']++;
			}

			$eventType = $event['event_type'] ?? '';
			if ($eventType === 'token_validated') {
				$stats['usage_stats']['total_validations']++;
			} elseif (in_array($eventType, ['token_not_found', 'token_expired', 'token_type_mismatch'])) {
				$stats['usage_stats']['failed_validations']++;
			}
		}

		return $stats;
	}

	/**
	 * Generate one-time use token with callback
	 *
	 * Creates a token that can only be used once for a specific action.
	 * Automatically deactivated after first use.
	 *
	 * @param string $action    Action this token authorizes
	 * @param array  $data      Additional data to store with token
	 * @param int    $expiresIn Expiration time in seconds (default: 1 hour)
	 * @return string Generated one-time token
	 *
	 * Usage example:
	 * ```php
	 * $tokenManager = new TokenManager();
	 * $deleteToken = $tokenManager->generateOneTimeToken('delete_account', [
	 *     'user_id' => 123,
	 *     'confirmation_required' => true
	 * ], 1800);
	 * echo "One-time delete token: " . $deleteToken;
	 * ```
	 */
	public function generateOneTimeToken(string $action, array $data = [], int $expiresIn = 3600): string {
		$tokenData = array_merge($data, [
			'action'       => $action,
			'one_time_use' => true,
		]);

		return $this->generateToken('one_time_action', $tokenData, $expiresIn);
	}

	/**
	 * Validate and consume one-time token
	 *
	 * Validates a one-time token for a specific action and automatically
	 * deactivates it after successful validation.
	 *
	 * @param string $token          Token to validate and consume
	 * @param string $expectedAction Expected action for this token
	 * @return array Validation result with action verification
	 *
	 * Usage example:
	 * ```php
	 * $tokenManager = new TokenManager();
	 * $result = $tokenManager->validateOneTimeToken($deleteToken, 'delete_account');
	 * if ($result['is_valid']) {
	 *     $userId = $result['token_data']['user_id'];
	 *     // Proceed with account deletion
	 * }
	 * ```
	 */
	public function validateOneTimeToken(string $token, string $expectedAction): array {
		$result = $this->validateToken($token, 'one_time_action', true);

		if ($result['is_valid']) {
			$action = $result['token_data']['action'] ?? '';
			if ($action !== $expectedAction) {
				$result['is_valid'] = false;
				$result['error'] = 'Action mismatch';
			}
		}

		return $result;
	}

	/**
	 * Batch generate tokens
	 *
	 * Generates multiple tokens of the same type efficiently.
	 * Useful for creating invitation codes or access tokens in bulk.
	 *
	 * @param string   $type       Token type to generate
	 * @param int      $count      Number of tokens to generate
	 * @param array    $baseData   Base data to include in all tokens
	 * @param int|null $expiresIn  Expiration time in seconds
	 * @return array Array of generated tokens
	 *
	 * Usage example:
	 * ```php
	 * $tokenManager = new TokenManager();
	 * $inviteTokens = $tokenManager->batchGenerateTokens('invitation', 10, [
	 *     'event_id' => 456,
	 *     'role' => 'guest'
	 * ], 86400 * 7); // 7 days
	 * foreach ($inviteTokens as $i => $token) {
	 *     echo "Invitation " . ($i + 1) . ": " . $token . "\n";
	 * }
	 * ```
	 */
	public function batchGenerateTokens(string $type, int $count, array $baseData = [], int $expiresIn = null): array {
		$tokens = [];

		for ($i = 0; $i < $count; $i++) {
			$data = array_merge($baseData, ['batch_id' => uniqid(), 'batch_index' => $i]);
			$tokens[] = $this->generateToken($type, $data, $expiresIn);
		}

		$this->logTokenEvent('batch_generated', [
			'type'  => $type,
			'count' => $count,
		]);

		return $tokens;
	}

	/**
	 * Revoke all tokens for a user
	 *
	 * Deactivates all active tokens for a specific user, optionally
	 * filtered by token type. Useful for security incidents.
	 *
	 * @param int         $userId User ID to revoke tokens for
	 * @param string|null $type   Optional token type filter
	 * @return int Number of tokens revoked
	 *
	 * Usage example:
	 * ```php
	 * $tokenManager = new TokenManager();
	 * // Revoke all tokens for compromised user
	 * $revoked = $tokenManager->revokeUserTokens(123);
	 * echo "Revoked {$revoked} tokens for user";
	 *
	 * // Revoke only API tokens
	 * $apiRevoked = $tokenManager->revokeUserTokens(123, 'api_access');
	 * ```
	 */
	public function revokeUserTokens(int $userId, string $type = null): int {
		return $this->invalidateTokensByData(['user_id' => $userId], $type);
	}

	/**
	 * Check token rate limiting
	 *
	 * Verifies if token generation is allowed based on rate limiting rules
	 * to prevent token abuse and brute force attacks.
	 *
	 * @param string $identifier Identifier for rate limiting (IP, user ID, etc.)
	 * @param string $action     Action being rate limited (default: 'token_generation')
	 * @return bool True if rate limit allows action, false if limited
	 *
	 * Usage example:
	 * ```php
	 * $tokenManager = new TokenManager();
	 * $clientIP = $_SERVER['REMOTE_ADDR'];
	 * if ($tokenManager->checkTokenRateLimit($clientIP, 'password_reset')) {
	 *     $resetToken = $tokenManager->generatePasswordResetToken($userId, $email);
	 * } else {
	 *     echo "Rate limit exceeded. Please try again later.";
	 * }
	 * ```
	 */
	public function checkTokenRateLimit(string $identifier, string $action = 'token_generation'): bool {
		$rateLimiter = new RateLimiter();
		return !$rateLimiter->isLimited($identifier, $action);
	}

	/**
	 * Generate secure token with custom entropy
	 *
	 * Creates a secure random token with custom length and character set.
	 * Useful for specific formatting requirements.
	 *
	 * @param int         $length  Length of token to generate
	 * @param string|null $charset Custom character set (null uses alphanumeric)
	 * @return string Generated custom token
	 *
	 * Usage example:
	 * ```php
	 * $tokenManager = new TokenManager();
	 * // Generate numeric-only token
	 * $numericToken = $tokenManager->generateCustomToken(8, '0123456789');
	 * echo "Verification code: " . $numericToken;
	 *
	 * // Generate URL-safe token
	 * $urlSafeToken = $tokenManager->generateCustomToken(16, 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_');
	 * ```
	 */
	public function generateCustomToken(int $length, string $charset = null): string {
		$charset = $charset ?: '0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ';
		$charsetLength = strlen($charset);
		$token = '';

		for ($i = 0; $i < $length; $i++) {
			$randomIndex = random_int(0, $charsetLength - 1);
			$token .= $charset[$randomIndex];
		}

		return $token;
	}

	/**
	 * Verify token signature (for advanced security)
	 *
	 * Verifies that a token signature matches the expected HMAC signature
	 * for additional security in high-security environments.
	 *
	 * @param string      $token     Token to verify
	 * @param string      $signature HMAC signature to verify
	 * @param string|null $secret    Secret key (null uses config default)
	 * @return bool True if signature is valid, false otherwise
	 *
	 * Usage example:
	 * ```php
	 * $tokenManager = new TokenManager();
	 * $token = "abc123def456";
	 * $signature = "provided_signature_from_client";
	 *
	 * if ($tokenManager->verifyTokenSignature($token, $signature)) {
	 *     echo "Token signature is valid";
	 * } else {
	 *     echo "Invalid token signature";
	 * }
	 * ```
	 */
	public function verifyTokenSignature(string $token, string $signature, string $secret = null): bool {
		$secret = $secret ?: Config::get('token_management.signing_secret', 'security') ?: 'default_secret';
		$expectedSignature = hash_hmac('sha256', $token, $secret);
		return hash_equals($expectedSignature, $signature);
	}

	/**
	 * Sign a token for additional security
	 *
	 * Creates an HMAC signature for a token using a secret key.
	 * Provides tamper detection for tokens transmitted over insecure channels.
	 *
	 * @param string      $token  Token to sign
	 * @param string|null $secret Secret key (null uses config default)
	 * @return string HMAC signature for the token
	 *
	 * Usage example:
	 * ```php
	 * $tokenManager = new TokenManager();
	 * $token = "abc123def456";
	 * $signature = $tokenManager->signToken($token);
	 *
	 * // Send both token and signature to client
	 * echo "Token: " . $token;
	 * echo "Signature: " . $signature;
	 * ```
	 */
	public function signToken(string $token, string $secret = null): string {
		$secret = $secret ?: Config::get('token_management.signing_secret', 'security') ?: 'default_secret';
		return hash_hmac('sha256', $token, $secret);
	}

	/**
	 * Export tokens for backup
	 *
	 * Exports token metadata for backup purposes while excluding
	 * actual token values for security.
	 *
	 * @param array $filters Optional filters to apply to export
	 * @return array Exported token data with hashed tokens
	 *
	 * Usage example:
	 * ```php
	 * $tokenManager = new TokenManager();
	 * // Export only API tokens
	 * $apiTokens = $tokenManager->exportTokens(['type' => 'api_access']);
	 * file_put_contents('api_tokens_backup.json', json_encode($apiTokens));
	 *
	 * // Export all active tokens
	 * $allTokens = $tokenManager->exportTokens(['is_active' => true]);
	 * ```
	 */
	public function exportTokens(array $filters = []): array {
		$tokens = $this->storage->read('security_tokens');

		if (!empty($filters)) {
			$tokens = array_filter($tokens, function ($token) use ($filters) {
				foreach ($filters as $key => $value) {
					if (!isset($token[$key]) || $token[$key] !== $value) {
						return false;
					}
				}
				return true;
			});
		}

		// Remove actual token values for security
		return array_map(function ($token) {
			unset($token['token']);
			$token['token_hash'] = hash('sha256', $token['token'] ?? '');
			return $token;
		}, $tokens);
	}

	/**
	 * Get token usage analytics
	 *
	 * Returns detailed analytics about token usage patterns, events,
	 * and error rates over a specified time period.
	 *
	 * @param int $days Number of days to analyze (default: 30)
	 * @return array Analytics data with usage patterns and error rates
	 *
	 * Usage example:
	 * ```php
	 * $tokenManager = new TokenManager();
	 * $analytics = $tokenManager->getTokenAnalytics(7); // Last 7 days
	 *
	 * echo "Total events: " . $analytics['total_events'];
	 * echo "Error rate: " . $analytics['error_rate'] . "%";
	 * foreach ($analytics['event_types'] as $type => $count) {
	 *     echo "Event {$type}: {$count} times";
	 * }
	 * foreach ($analytics['daily_breakdown'] as $date => $count) {
	 *     echo "Date {$date}: {$count} events";
	 * }
	 * ```
	 */
	public function getTokenAnalytics(int $days = 30): array {
		$cutoff = time() - ($days * 86400);
		$tokenLog = $this->storage->find('token_log');

		$recentEvents = array_filter($tokenLog, function ($event) use ($cutoff) {
			return ($event['created_at'] ?? 0) > $cutoff;
		});

		$analytics = [
			'period_days'     => $days,
			'total_events'    => count($recentEvents),
			'event_types'     => [],
			'daily_breakdown' => [],
			'error_rate'      => 0,
		];

		$eventsByType = [];
		$eventsByDay = [];
		$errorEvents = 0;

		foreach ($recentEvents as $event) {
			$eventType = $event['event_type'] ?? 'unknown';
			$eventDate = date('Y-m-d', $event['created_at'] ?? 0);
			$severity = $event['severity'] ?? 'info';

			$eventsByType[$eventType] = ($eventsByType[$eventType] ?? 0) + 1;
			$eventsByDay[$eventDate] = ($eventsByDay[$eventDate] ?? 0) + 1;

			if ($severity === 'error') {
				$errorEvents++;
			}
		}

		$analytics['event_types'] = $eventsByType;
		$analytics['daily_breakdown'] = $eventsByDay;
		$analytics['error_rate'] = count($recentEvents) > 0 ? round(($errorEvents / count($recentEvents)) * 100, 2) : 0;

		return $analytics;
	}

	/**
	 * Check if token management is enabled
	 *
	 * Returns the current enabled status of the token management system
	 * based on configuration settings.
	 *
	 * @return bool True if token management is enabled, false otherwise
	 *
	 * Usage example:
	 * ```php
	 * $tokenManager = new TokenManager();
	 * if ($tokenManager->isEnabled()) {
	 *     $token = $tokenManager->generateToken('api_access', $data);
	 * } else {
	 *     echo "Token management is disabled";
	 * }
	 * ```
	 */
	public function isEnabled(): bool {
		return $this->enabled;
	}

	/**
	 * Get available token types
	 *
	 * Returns a list of all configured token types that can be
	 * generated by the token manager.
	 *
	 * @return array Array of available token type names
	 *
	 * Usage example:
	 * ```php
	 * $tokenManager = new TokenManager();
	 * $types = $tokenManager->getTokenTypes();
	 * foreach ($types as $type) {
	 *     echo "Available token type: " . $type . "\n";
	 * }
	 * // Outputs: api_access, email_verification, password_reset, etc.
	 * ```
	 */
	public function getTokenTypes(): array {
		return array_keys($this->tokenTypes);
	}

	/**
	 * Add custom token type
	 *
	 * Registers a new token type with custom configuration including
	 * length, expiration, usage limits, and description.
	 *
	 * @param string $type   Token type name
	 * @param array  $config Token type configuration
	 * @return void
	 *
	 * Usage example:
	 * ```php
	 * $tokenManager = new TokenManager();
	 * $tokenManager->addTokenType('payment_authorization', [
	 *     'length' => 48,
	 *     'expiration' => 600, // 10 minutes
	 *     'max_usage' => 1,
	 *     'description' => 'Payment authorization token'
	 * ]);
	 *
	 * // Now you can generate tokens of this type
	 * $paymentToken = $tokenManager->generateToken('payment_authorization', $paymentData);
	 * ```
	 */
	public function addTokenType(string $type, array $config): void {
		$this->tokenTypes[$type] = array_merge([
			'length'      => 32,
			'expiration'  => 3600,
			'max_usage'   => null,
			'description' => 'Custom token type',
		], $config);

		$this->logTokenEvent('token_type_added', [
			'type'   => $type,
			'config' => $config,
		]);
	}
}