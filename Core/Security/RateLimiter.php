<?php

namespace Yohns\Core\Security;

use PDOChainer\PDOChainer;
use PDOChainer\DBAL;
use Yohns\Core\Config;
use RuntimeException;

/**
 * RateLimiter class for preventing spam and abuse through rate limiting.
 *
 * This class tracks requests by IP address and/or user ID and implements
 * progressive timeouts for excessive requests.
 *
 * Examples:
 * ```php
 * // Create a rate limiter instance
 * $rateLimiter = new RateLimiter($pdoChainer);
 *
 * // Check if a request should be limited
 * if ($rateLimiter->isLimited('192.168.1.1', 'post')) {
 *     // Request is limited, show error
 *     echo "You've exceeded the limit for this action. Try again later.";
 *     exit;
 * }
 *
 * // For logged-in users, also include the user ID
 * if ($rateLimiter->isLimited('192.168.1.1', 'message', 42)) {
 *     // Request is limited, show error
 *     echo "You've exceeded the messaging limit. Try again later.";
 *     exit;
 * }
 * ```
 */
class RateLimiter {
	/**
	 * @var DBAL Database abstraction layer
	 */
	private DBAL $db;

	/**
	 * @var array Cache for rate limit configurations
	 */
	private array $configCache = [];

	/**
	 * @var bool Whether to use database or static configuration
	 */
	private bool $useDbConfig;

	/**
	 * Constructor for RateLimiter.
	 *
	 * @param PDOChainer $pdo PDO chain wrapper instance
	 * @param bool $useDbConfig Whether to use database config (true) or static config (false)
	 */
	public function __construct(PDOChainer $pdo, bool $useDbConfig = true) {
		$this->db = new DBAL($pdo);
		$this->useDbConfig = $useDbConfig;
	}

	/**
	 * Check if a request should be rate limited.
	 *
	 * @param string $ipAddress The IP address of the requester
	 * @param string $actionType The type of action being performed
	 * @param int|null $userId Optional user ID for logged-in users
	 * @return bool True if the request should be limited, false otherwise
	 */
	public function isLimited(string $ipAddress, string $actionType, ?int $userId = null): bool {
		// If user is logged in, prioritize user ID over IP
		$identifier = $userId ? "user:{$userId}" : "ip:{$ipAddress}";

		// Get the current rate limit record
		$record = $this->getRateLimitRecord($identifier, $actionType);

		// If no record exists, create one and allow the request
		if (empty($record)) {
			$this->createRateLimitRecord($identifier, $actionType);
			return false;
		}

		// Check if currently blocked
		if (!empty($record['blocked_until']) && strtotime($record['blocked_until']) > time()) {
			return true;
		}

		// Get rate limit configuration for this action
		$config = $this->getRateLimitConfig($actionType);

		// If first request was within the time window, check count
		$firstRequestTime = strtotime($record['first_request_time']);
		$timeWindow = $config['time_window'];
		$maxRequests = $config['max_requests'];

		if (time() - $firstRequestTime <= $timeWindow) {
			// Still within time window, check if exceeded max requests
			if ($record['request_count'] >= $maxRequests) {
				// Calculate block duration (progressive timeouts)
				$blockDuration = $this->calculateBlockDuration($record, $config);
				$this->blockIdentifier($identifier, $actionType, $blockDuration);
				return true;
			} else {
				// Increment request count and allow
				$this->incrementRequestCount($identifier, $actionType);
				return false;
			}
		} else {
			// Time window has passed, reset counter
			$this->resetRateLimitRecord($identifier, $actionType);
			return false;
		}
	}

	/**
	 * Get rate limit record for a specific identifier and action.
	 *
	 * @param string $identifier The identifier (IP or user ID)
	 * @param string $actionType The action type
	 * @return array|null The rate limit record or null if not found
	 */
	private function getRateLimitRecord(string $identifier, string $actionType): ?array {
		$binds = [
			[':identifier', $identifier],
			[':action_type', $actionType]
		];

		$sql = "SELECT * FROM `rate_limits`
				WHERE `identifier` = :identifier
				AND `action_type` = :action_type
				LIMIT 1";

		return $this->db->select($sql, 1, $binds) ?: null;
	}

	/**
	 * Create a new rate limit record.
	 *
	 * @param string $identifier The identifier (IP or user ID)
	 * @param string $actionType The action type
	 * @return int The inserted ID
	 */
	private function createRateLimitRecord(string $identifier, string $actionType): int {
		$now = date('Y-m-d H:i:s');
		$data = [
			['identifier', $identifier],
			['action_type', $actionType],
			['request_count', 1],
			['first_request_time', $now],
			['last_request_time', $now]
		];

		return $this->db->insert('rate_limits', $data);
	}

	/**
	 * Increment the request count for a rate limit record.
	 *
	 * @param string $identifier The identifier (IP or user ID)
	 * @param string $actionType The action type
	 * @return int Number of affected rows
	 */
	private function incrementRequestCount(string $identifier, string $actionType): int {
		$now = date('Y-m-d H:i:s');
		$data = [
			['request_count', 'request_count + 1', \PDO::PARAM_STR],
			['last_request_time', $now]
		];

		$where = [
			['identifier', $identifier],
			['action_type', $actionType]
		];

		return $this->db->update('rate_limits', $data, $where);
	}

	/**
	 * Reset a rate limit record to start counting from the current time.
	 *
	 * @param string $identifier The identifier (IP or user ID)
	 * @param string $actionType The action type
	 * @return int Number of affected rows
	 */
	private function resetRateLimitRecord(string $identifier, string $actionType): int {
		$now = date('Y-m-d H:i:s');
		$data = [
			['request_count', 1],
			['first_request_time', $now],
			['last_request_time', $now],
			['blocked_until', null]
		];

		$where = [
			['identifier', $identifier],
			['action_type', $actionType]
		];

		return $this->db->update('rate_limits', $data, $where);
	}

	/**
	 * Block an identifier for a specific action type.
	 *
	 * @param string $identifier The identifier (IP or user ID)
	 * @param string $actionType The action type
	 * @param int $blockDuration The duration to block in seconds
	 * @return int Number of affected rows
	 */
	private function blockIdentifier(string $identifier, string $actionType, int $blockDuration): int {
		$blockedUntil = date('Y-m-d H:i:s', time() + $blockDuration);
		$data = [
			['blocked_until', $blockedUntil]
		];

		$where = [
			['identifier', $identifier],
			['action_type', $actionType]
		];

		return $this->db->update('rate_limits', $data, $where);
	}

	/**
	 * Calculate block duration based on history and configuration.
	 * Implements progressive timeouts for repeat offenders.
	 *
	 * @param array $record The rate limit record
	 * @param array $config The rate limit configuration
	 * @return int Block duration in seconds
	 */
	private function calculateBlockDuration(array $record, array $config): int {
		$baseDuration = $config['block_duration'];
		$multiplier = $config['block_multiplier'];

		// If previously blocked, increase duration
		if (!empty($record['blocked_until'])) {
			// Calculate number of previous blocks (roughly)
			$prevBlockCount = floor($record['request_count'] / $config['max_requests']);
			// Apply multiplier for each previous block (with a cap to prevent excessive blocking)
			$blockFactor = min(pow($multiplier, $prevBlockCount), 10);
			return (int) ($baseDuration * $blockFactor);
		}

		return $baseDuration;
	}

	/**
	 * Get rate limit configuration for an action type.
	 *
	 * @param string $actionType The action type
	 * @return array The rate limit configuration
	 */
	private function getRateLimitConfig(string $actionType): array {
		// Check cache first
		if (isset($this->configCache[$actionType])) {
			return $this->configCache[$actionType];
		}

		// Try to get from database if enabled
		if ($this->useDbConfig) {
			$binds = [[':action_type', $actionType]];
			$sql = "SELECT * FROM `rate_limit_config`
					WHERE `action_type` = :action_type
					LIMIT 1";

			$dbConfig = $this->db->select($sql, 1, $binds);

			if (!empty($dbConfig)) {
				$this->configCache[$actionType] = $dbConfig;
				return $dbConfig;
			}
		}

		// Fall back to static config from Config class
		$staticConfig = Config::get($actionType, 'rate_limits');

		if (empty($staticConfig)) {
			// Use default config if nothing else is available
			$staticConfig = [
				'max_requests'     => 10,
				'time_window'      => 60,
				'block_duration'   => 300,
				'block_multiplier' => 2.0
			];
		}

		$this->configCache[$actionType] = $staticConfig;
		return $staticConfig;
	}

	/**
	 * Clear rate limit for a specific identifier and action.
	 * Useful for administrative actions or testing.
	 *
	 * @param string $identifier The identifier (IP or user ID)
	 * @param string $actionType The action type
	 * @return bool True if successful, false otherwise
	 */
	public function clearLimit(string $identifier, string $actionType): bool {
		$where = [
			['identifier', $identifier],
			['action_type', $actionType]
		];

		return $this->db->delete('rate_limits', $where) > 0;
	}

	/**
	 * Get the remaining number of requests allowed for an identifier and action.
	 *
	 * @param string $identifier The identifier (IP or user ID)
	 * @param string $actionType The action type
	 * @return array Information about remaining requests
	 */
	public function getRemainingRequests(string $identifier, string $actionType): array {
		$record = $this->getRateLimitRecord($identifier, $actionType);
		$config = $this->getRateLimitConfig($actionType);

		// If blocked, return 0 remaining with time until unblock
		if (!empty($record) && !empty($record['blocked_until']) && strtotime($record['blocked_until']) > time()) {
			return [
				'remaining'    => 0,
				'blocked'      => true,
				'reset_time'   => strtotime($record['blocked_until']),
				'wait_seconds' => strtotime($record['blocked_until']) - time()
			];
		}

		// If no record or time window passed, return max allowed
		if (empty($record) || (time() - strtotime($record['first_request_time']) > $config['time_window'])) {
			return [
				'remaining'    => $config['max_requests'],
				'blocked'      => false,
				'reset_time'   => null,
				'wait_seconds' => 0
			];
		}

		// Calculate remaining requests
		$remaining = max(0, $config['max_requests'] - $record['request_count']);
		$resetTime = strtotime($record['first_request_time']) + $config['time_window'];

		return [
			'remaining'    => $remaining,
			'blocked'      => false,
			'reset_time'   => $resetTime,
			'wait_seconds' => max(0, $resetTime - time())
		];
	}
}