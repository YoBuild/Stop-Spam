<?php

namespace Yohns\Security;

use Yohns\Core\Config;

/**
 * TokenManager class for managing various types of security tokens
 *
 * Handles API tokens, session tokens, verification tokens, and more.
 */
class TokenManager {
	private FileStorage $storage;
	private bool        $enabled;
	private int         $defaultExpiration;
	private array       $tokenTypes;

	public function __construct() {
		$this->storage = new FileStorage();
		$this->enabled = Config::get('token_management.enabled', 'security') ?? true;
		$this->defaultExpiration = Config::get('token_management.default_expiration', 'security') ?: 3600;

		$this->initializeTokenTypes();
	}

	/**
	 * Generate a new token
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
	 */
	private function createSecureToken(int $length = 32): string {
		return bin2hex(random_bytes($length));
	}

	/**
	 * Get client IP address
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
	 */
	public function revokeUserTokens(int $userId, string $type = null): int {
		return $this->invalidateTokensByData(['user_id' => $userId], $type);
	}

	/**
	 * Check token rate limiting
	 */
	public function checkTokenRateLimit(string $identifier, string $action = 'token_generation'): bool {
		$rateLimiter = new RateLimiter();
		return !$rateLimiter->isLimited($identifier, $action);
	}

	/**
	 * Generate secure token with custom entropy
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
	 */
	public function verifyTokenSignature(string $token, string $signature, string $secret = null): bool {
		$secret = $secret ?: Config::get('token_management.signing_secret', 'security') ?: 'default_secret';
		$expectedSignature = hash_hmac('sha256', $token, $secret);
		return hash_equals($expectedSignature, $signature);
	}

	/**
	 * Sign a token for additional security
	 */
	public function signToken(string $token, string $secret = null): string {
		$secret = $secret ?: Config::get('token_management.signing_secret', 'security') ?: 'default_secret';
		return hash_hmac('sha256', $token, $secret);
	}

	/**
	 * Export tokens for backup
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
	 */
	public function isEnabled(): bool {
		return $this->enabled;
	}

	/**
	 * Get available token types
	 */
	public function getTokenTypes(): array {
		return array_keys($this->tokenTypes);
	}

	/**
	 * Add custom token type
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