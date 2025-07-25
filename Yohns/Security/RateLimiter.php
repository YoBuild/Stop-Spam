<?php

namespace Yohns\Security;

use Yohns\Core\Config;

/**
 * RateLimiter class for preventing abuse through rate limiting
 *
 * Implements progressive timeouts and tracks requests by IP and action type.
 */
class RateLimiter {
	private FileStorage $storage;
	private bool        $enabled;
	private int         $globalMax;
	private int         $perEndpoint;
	private int         $perIP;
	private int         $loginMax;
	private int         $blockDuration;
	private float       $blockMultiplier;

	public function __construct() {
		$this->storage = new FileStorage();
		$this->enabled = Config::get('rate_limiting.enabled', 'security') ?? true;
		$this->globalMax = Config::get('rate_limiting.global_max', 'security') ?: 1000;
		$this->perEndpoint = Config::get('rate_limiting.per_endpoint', 'security') ?: 100;
		$this->perIP = Config::get('rate_limiting.per_ip', 'security') ?: 300;
		$this->loginMax = Config::get('rate_limiting.login_max', 'security') ?: 5;
		$this->blockDuration = Config::get('rate_limiting.block_duration', 'security') ?: 900;
		$this->blockMultiplier = Config::get('rate_limiting.block_multiplier', 'security') ?: 2.0;
	}

	/**
	 * Check if a request should be rate limited
	 */
	public function isLimited(string $ipAddress, string $actionType, ?int $userId = null): bool {
		if (!$this->enabled) {
			return false;
		}

		$identifier = $userId ? "user_{$userId}" : "ip_{$ipAddress}";
		$now = time();

		// Check if currently blocked
		if ($this->isBlocked($identifier, $actionType)) {
			return true;
		}

		// Get or create rate limit record
		$rateLimit = $this->storage->findOne('rate_limits', [
			'identifier'  => $identifier,
			'action_type' => $actionType,
		]);

		if (!$rateLimit) {
			// Create new rate limit record
			$this->storage->insert('rate_limits', [
				'identifier'         => $identifier,
				'action_type'        => $actionType,
				'request_count'      => 1,
				'first_request_time' => $now,
				'last_request_time'  => $now,
				'blocked_until'      => null,
				'violation_count'    => 0,
			]);
			return false;
		}

		// Calculate time window and limits based on action type
		$limits = $this->getActionLimits($actionType);
		$timeWindow = $limits['time_window'];
		$maxRequests = $limits['max_requests'];

		// Reset counter if time window has passed
		if (($now - $rateLimit['first_request_time']) > $timeWindow) {
			$this->storage->update('rate_limits', $rateLimit['id'], [
				'request_count'      => 1,
				'first_request_time' => $now,
				'last_request_time'  => $now,
			]);
			return false;
		}

		// Check if limit exceeded
		if ($rateLimit['request_count'] >= $maxRequests) {
			$this->blockUser($identifier, $actionType, $rateLimit);
			return true;
		}

		// Increment request count
		$this->storage->update('rate_limits', $rateLimit['id'], [
			'request_count'     => $rateLimit['request_count'] + 1,
			'last_request_time' => $now,
		]);

		return false;
	}

	/**
	 * Check if user/IP is currently blocked
	 */
	public function isBlocked(string $identifier, string $actionType): bool {
		$rateLimit = $this->storage->findOne('rate_limits', [
			'identifier'  => $identifier,
			'action_type' => $actionType,
		]);

		if (!$rateLimit || !$rateLimit['blocked_until']) {
			return false;
		}

		if (time() < $rateLimit['blocked_until']) {
			return true;
		}

		// Block period expired, unblock user
		$this->storage->update('rate_limits', $rateLimit['id'], [
			'blocked_until' => null,
		]);

		return false;
	}

	/**
	 * Block a user/IP with progressive timeout
	 */
	private function blockUser(string $identifier, string $actionType, array $rateLimit): void {
		$violationCount = ($rateLimit['violation_count'] ?? 0) + 1;
		$blockDuration = $this->blockDuration * pow($this->blockMultiplier, $violationCount - 1);
		$blockedUntil = time() + (int) $blockDuration;

		$this->storage->update('rate_limits', $rateLimit['id'], [
			'blocked_until'   => $blockedUntil,
			'violation_count' => $violationCount,
		]);

		// Log the block event
		$this->logRateLimitViolation($identifier, $actionType, $blockDuration);
	}

	/**
	 * Get rate limit configuration for action type
	 */
	private function getActionLimits(string $actionType): array {
		$defaults = [
			'login'        => [
				'max_requests' => $this->loginMax,
				'time_window'  => 900, // 15 minutes
			],
			'post'         => [
				'max_requests' => 10,
				'time_window'  => 600, // 10 minutes
			],
			'message'      => [
				'max_requests' => 20,
				'time_window'  => 600, // 10 minutes
			],
			'search'       => [
				'max_requests' => 15,
				'time_window'  => 60, // 1 minute
			],
			'profile_view' => [
				'max_requests' => 50,
				'time_window'  => 300, // 5 minutes
			],
			'default'      => [
				'max_requests' => $this->perEndpoint,
				'time_window'  => 60, // 1 minute
			],
		];

		return $defaults[$actionType] ?? $defaults['default'];
	}

	/**
	 * Log rate limit violation
	 */
	private function logRateLimitViolation(string $identifier, string $actionType, int $blockDuration): void {
		$this->storage->insert('rate_limit_violations', [
			'identifier'     => $identifier,
			'action_type'    => $actionType,
			'block_duration' => $blockDuration,
			'ip_address'     => $this->getClientIP(),
			'user_agent'     => $_SERVER['HTTP_USER_AGENT'] ?? '',
			'request_uri'    => $_SERVER['REQUEST_URI'] ?? '',
		]);
	}

	/**
	 * Manually block a user/IP
	 */
	public function blockIdentifier(string $identifier, string $actionType, int $duration = null): void {
		$blockDuration = $duration ?: $this->blockDuration;
		$blockedUntil = time() + $blockDuration;

		$existing = $this->storage->findOne('rate_limits', [
			'identifier'  => $identifier,
			'action_type' => $actionType,
		]);

		if ($existing) {
			$this->storage->update('rate_limits', $existing['id'], [
				'blocked_until'   => $blockedUntil,
				'violation_count' => ($existing['violation_count'] ?? 0) + 1,
			]);
		} else {
			$this->storage->insert('rate_limits', [
				'identifier'         => $identifier,
				'action_type'        => $actionType,
				'request_count'      => 0,
				'first_request_time' => time(),
				'last_request_time'  => time(),
				'blocked_until'      => $blockedUntil,
				'violation_count'    => 1,
			]);
		}
	}

	/**
	 * Unblock a user/IP
	 */
	public function unblockIdentifier(string $identifier, string $actionType): bool {
		$rateLimit = $this->storage->findOne('rate_limits', [
			'identifier'  => $identifier,
			'action_type' => $actionType,
		]);

		if (!$rateLimit) {
			return false;
		}

		return $this->storage->update('rate_limits', $rateLimit['id'], [
			'blocked_until' => null,
		]);
	}

	/**
	 * Get remaining requests for identifier
	 */
	public function getRemainingRequests(string $identifier, string $actionType): int {
		if (!$this->enabled) {
			return PHP_INT_MAX;
		}

		$rateLimit = $this->storage->findOne('rate_limits', [
			'identifier'  => $identifier,
			'action_type' => $actionType,
		]);

		if (!$rateLimit) {
			$limits = $this->getActionLimits($actionType);
			return $limits['max_requests'];
		}

		$limits = $this->getActionLimits($actionType);
		$timeWindow = $limits['time_window'];
		$maxRequests = $limits['max_requests'];

		// Reset if time window passed
		if ((time() - $rateLimit['first_request_time']) > $timeWindow) {
			return $maxRequests;
		}

		return max(0, $maxRequests - $rateLimit['request_count']);
	}

	/**
	 * Get block time remaining for identifier
	 */
	public function getBlockTimeRemaining(string $identifier, string $actionType): int {
		$rateLimit = $this->storage->findOne('rate_limits', [
			'identifier'  => $identifier,
			'action_type' => $actionType,
		]);

		if (!$rateLimit || !$rateLimit['blocked_until']) {
			return 0;
		}

		return max(0, $rateLimit['blocked_until'] - time());
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
	 * Clean up old rate limit records
	 */
	public function cleanup(): int {
		$rateLimits = $this->storage->read('rate_limits');
		$now = time();
		$deleted = 0;
		$maxAge = 86400 * 7; // Keep records for 7 days

		foreach ($rateLimits as $id => $rateLimit) {
			$age = $now - ($rateLimit['created_at'] ?? 0);

			// Delete old records that are not currently blocked
			if ($age > $maxAge && (!$rateLimit['blocked_until'] || $rateLimit['blocked_until'] < $now)) {
				$this->storage->delete('rate_limits', $id);
				$deleted++;
			}
		}

		return $deleted;
	}

	/**
	 * Get rate limiting statistics
	 */
	public function getStats(): array {
		$rateLimits = $this->storage->read('rate_limits');
		$violations = $this->storage->read('rate_limit_violations');
		$now = time();

		$stats = [
			'total_records'     => count($rateLimits),
			'currently_blocked' => 0,
			'total_violations'  => count($violations),
			'action_types'      => [],
			'top_violators'     => [],
		];

		$actionCounts = [];
		$violatorCounts = [];

		foreach ($rateLimits as $rateLimit) {
			$actionType = $rateLimit['action_type'] ?? 'unknown';
			$actionCounts[$actionType] = ($actionCounts[$actionType] ?? 0) + 1;

			if ($rateLimit['blocked_until'] && $rateLimit['blocked_until'] > $now) {
				$stats['currently_blocked']++;
			}

			$identifier = $rateLimit['identifier'] ?? 'unknown';
			$violatorCounts[$identifier] = ($violatorCounts[$identifier] ?? 0) + ($rateLimit['violation_count'] ?? 0);
		}

		$stats['action_types'] = $actionCounts;
		arsort($violatorCounts);
		$stats['top_violators'] = array_slice($violatorCounts, 0, 10, true);

		return $stats;
	}

	/**
	 * Reset all rate limits for an identifier
	 */
	public function resetIdentifier(string $identifier): int {
		$rateLimits = $this->storage->find('rate_limits', ['identifier' => $identifier]);
		$deleted = 0;

		foreach ($rateLimits as $rateLimit) {
			$this->storage->delete('rate_limits', $rateLimit['id']);
			$deleted++;
		}

		return $deleted;
	}

	/**
	 * Check if rate limiting is enabled
	 */
	public function isEnabled(): bool {
		return $this->enabled;
	}
}