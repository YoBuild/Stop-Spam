<?php

namespace Yohns\Security;

use Yohns\Core\Config;
use Yohns\Security\FileStorage;

/**
 * IPSecurity class for IP-based security management
 *
 * Handles IP whitelisting, blacklisting, geolocation, and reputation tracking.
 */
class IPSecurity {
	private FileStorage $storage;
	private bool        $enabled;
	private array       $whitelist;
	private array       $blacklist;
	private bool        $checkProxies;
	private int         $maxProxyDepth;
	private array       $trustedProxies;

	public function __construct() {
		$this->storage = new FileStorage();
		$this->enabled = Config::get('ip_security.enabled', 'security') ?? true;
		$this->checkProxies = Config::get('ip_security.check_proxies', 'security') ?? true;
		$this->maxProxyDepth = Config::get('ip_security.max_proxy_depth', 'security') ?: 3;

		$this->loadWhitelist();
		$this->loadBlacklist();
		$this->loadTrustedProxies();
	}

	/**
	 * Analyze IP address for security threats
	 */
	public function analyzeIP(string $ipAddress = null): array {
		$ip = $ipAddress ?: $this->getClientIP();

		$result = [
			'ip_address'      => $ip,
			'is_blocked'      => false,
			'is_whitelisted'  => false,
			'trust_score'     => 1.0,
			'threats'         => [],
			'geolocation'     => [],
			'reputation'      => [],
			'proxy_info'      => [],
			'recommendations' => [],
		];

		if (!$this->enabled) {
			return $result;
		}

		// Check whitelist first
		if ($this->isWhitelisted($ip)) {
			$result['is_whitelisted'] = true;
			$result['trust_score'] = 1.0;
			return $result;
		}

		// Check blacklist
		if ($this->isBlacklisted($ip)) {
			$result['is_blocked'] = true;
			$result['trust_score'] = 0.0;
			$result['threats'][] = [
				'type'        => 'blacklisted',
				'severity'    => 'high',
				'description' => 'IP address is in blacklist',
			];
			return $result;
		}

		// Check for proxy/VPN
		if ($this->checkProxies) {
			$result['proxy_info'] = $this->analyzeProxy($ip);
			if (!empty($result['proxy_info']['is_proxy'])) {
				$result['trust_score'] -= 0.3;
				$result['threats'][] = [
					'type'        => 'proxy_detected',
					'severity'    => 'medium',
					'description' => 'Request coming through proxy/VPN',
				];
			}
		}

		// Get IP reputation
		$result['reputation'] = $this->getIPReputation($ip);
		if (!empty($result['reputation']['score']) && $result['reputation']['score'] < 0.5) {
			$result['trust_score'] -= 0.4;
			$result['threats'][] = [
				'type'        => 'bad_reputation',
				'severity'    => 'high',
				'description' => 'IP has poor reputation score',
			];
		}

		// Check recent violations
		$violations = $this->getRecentViolations($ip);
		if ($violations['count'] > 0) {
			$severityMultiplier = min(1.0, $violations['count'] * 0.1);
			$result['trust_score'] -= $severityMultiplier;
			$result['threats'][] = [
				'type'        => 'recent_violations',
				'severity'    => $violations['count'] > 10 ? 'high' : 'medium',
				'description' => "IP has {$violations['count']} recent security violations",
			];
		}

		// Geolocation analysis
		$geolocation = $this->getGeolocation($ip);
		$result['geolocation'] = $geolocation ?? [];
		if (!empty($geolocation) && $this->isSuspiciousLocation($geolocation)) {
			$result['trust_score'] -= 0.2;
			$result['threats'][] = [
				'type'        => 'suspicious_location',
				'severity'    => 'low',
				'description' => 'Request from high-risk geographic location',
			];
		}

		// Generate recommendations
		$result['recommendations'] = $this->generateRecommendations($result);

		// Ensure trust score is between 0 and 1
		$result['trust_score'] = max(0.0, min(1.0, $result['trust_score']));

		// Auto-block if trust score is too low
		if ($result['trust_score'] < 0.2) {
			$result['is_blocked'] = true;
			$this->addToBlacklist($ip, 'Auto-blocked due to low trust score', 3600); // 1 hour
		}

		return $result;
	}

	/**
	 * Get the real client IP address
	 */
	public function getClientIP(): string {
		$ipKeys = [
			'HTTP_CF_CONNECTING_IP',     // Cloudflare
			'HTTP_X_FORWARDED_FOR',      // Standard proxy header
			'HTTP_X_REAL_IP',            // Nginx proxy
			'HTTP_X_CLIENT_IP',          // Apache mod_remoteip
			'HTTP_X_CLUSTER_CLIENT_IP',  // Cluster environments
			'HTTP_FORWARDED',            // RFC 7239
			'REMOTE_ADDR'                // Default
		];

		foreach ($ipKeys as $key) {
			if (!empty($_SERVER[$key])) {
				$ips = explode(',', $_SERVER[$key]);

				foreach ($ips as $ip) {
					$ip = trim($ip);

					// Validate IP and check if it's not private/reserved
					if ($this->isValidPublicIP($ip)) {
						return $ip;
					}
				}
			}
		}

		return $_SERVER['REMOTE_ADDR'] ?? '0.0.0.0';
	}

	/**
	 * Check if IP is valid and public
	 */
	private function isValidPublicIP(string $ip): bool {
		if (!filter_var($ip, FILTER_VALIDATE_IP)) {
			return false;
		}

		// Allow private IPs if they're from trusted proxies
		if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE)) {
			return true;
		}

		// Check if it's from a trusted proxy
		foreach ($this->trustedProxies as $proxy) {
			if ($this->ipInRange($ip, $proxy)) {
				return true;
			}
		}

		return false;
	}

	/**
	 * Check if IP is in CIDR range
	 */
	private function ipInRange(string $ip, string $range): bool {
		if (strpos($range, '/') === false) {
			return $ip === $range;
		}

		[$subnet, $bits] = explode('/', $range);

		if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) {
			$ip = ip2long($ip);
			$subnet = ip2long($subnet);
			$mask = -1 << (32 - (int) $bits);
			return ($ip & $mask) === ($subnet & $mask);
		}

		// IPv6 support would go here
		return false;
	}

	/**
	 * Check if IP is whitelisted
	 */
	public function isWhitelisted(string $ip): bool {
		foreach ($this->whitelist as $whitelistedRange) {
			if ($this->ipInRange($ip, $whitelistedRange['ip_range'])) {
				return true;
			}
		}
		return false;
	}

	/**
	 * Check if IP is blacklisted
	 */
	public function isBlacklisted(string $ip): bool {
		foreach ($this->blacklist as $blacklistedRange) {
			if ($this->ipInRange($ip, $blacklistedRange['ip_range'])) {
				// Check if blacklist entry has expired
				if (isset($blacklistedRange['expires_at']) && $blacklistedRange['expires_at'] < time()) {
					$this->removeFromBlacklist($ip);
					return false;
				}
				return true;
			}
		}
		return false;
	}

	/**
	 * Add IP to whitelist
	 */
	public function addToWhitelist(string $ip, string $reason = '', int $duration = 0): bool {
		$expiresAt = $duration > 0 ? time() + $duration : null;

		$this->storage->insert('ip_whitelist', [
			'ip_range'   => $ip,
			'reason'     => $reason,
			'expires_at' => $expiresAt,
			'added_by'   => $_SESSION['user_id'] ?? 'system',
		]);

		$this->loadWhitelist(); // Refresh cache
		return true;
	}

	/**
	 * Add IP to blacklist
	 */
	public function addToBlacklist(string $ip, string $reason = '', int $duration = 0): bool {
		$expiresAt = $duration > 0 ? time() + $duration : null;

		$this->storage->insert('ip_blacklist', [
			'ip_range'   => $ip,
			'reason'     => $reason,
			'expires_at' => $expiresAt,
			'added_by'   => $_SESSION['user_id'] ?? 'system',
		]);

		$this->loadBlacklist(); // Refresh cache

		// Log the blacklist addition
		$this->logSecurityEvent('ip_blacklisted', [
			'ip'       => $ip,
			'reason'   => $reason,
			'duration' => $duration,
		]);

		return true;
	}

	/**
	 * Remove IP from whitelist
	 */
	public function removeFromWhitelist(string $ip): bool {
		$entries = $this->storage->find('ip_whitelist', ['ip_range' => $ip]);
		$removed = false;

		foreach ($entries as $entry) {
			$this->storage->delete('ip_whitelist', $entry['id']);
			$removed = true;
		}

		if ($removed) {
			$this->loadWhitelist(); // Refresh cache
		}

		return $removed;
	}

	/**
	 * Remove IP from blacklist
	 */
	public function removeFromBlacklist(string $ip): bool {
		$entries = $this->storage->find('ip_blacklist', ['ip_range' => $ip]);
		$removed = false;

		foreach ($entries as $entry) {
			$this->storage->delete('ip_blacklist', $entry['id']);
			$removed = true;
		}

		if ($removed) {
			$this->loadBlacklist(); // Refresh cache
		}

		return $removed;
	}

	/**
	 * Analyze proxy/VPN usage
	 */
	private function analyzeProxy(string $ip): array {
		$result = [
			'is_proxy'   => false,
			'proxy_type' => null,
			'confidence' => 0.0,
			'details'    => [],
		];

		// Check common proxy headers
		$proxyHeaders = [
			'HTTP_X_FORWARDED_FOR',
			'HTTP_X_REAL_IP',
			'HTTP_X_CLUSTER_CLIENT_IP',
			'HTTP_FORWARDED',
			'HTTP_VIA',
			'HTTP_X_FORWARDED_PROTO',
		];

		$headerCount = 0;
		foreach ($proxyHeaders as $header) {
			if (!empty($_SERVER[$header])) {
				$headerCount++;
				$result['details'][] = "Header present: {$header}";
			}
		}

		if ($headerCount >= 2) {
			$result['is_proxy'] = true;
			$result['proxy_type'] = 'http_proxy';
			$result['confidence'] = min(1.0, $headerCount * 0.3);
		}

		// Check known proxy/VPN IP ranges
		$knownProxyRanges = $this->getKnownProxyRanges();
		foreach ($knownProxyRanges as $range) {
			if ($this->ipInRange($ip, $range['ip_range'])) {
				$result['is_proxy'] = true;
				$result['proxy_type'] = $range['type'];
				$result['confidence'] = 0.9;
				$result['details'][] = "Matches known {$range['type']} range";
				break;
			}
		}

		return $result;
	}

	/**
	 * Get IP reputation from stored data
	 */
	private function getIPReputation(string $ip): array {
		$reputation = $this->storage->findOne('ip_reputation', ['ip_address' => $ip]);

		if ($reputation) {
			return [
				'score'           => (float) ($reputation['reputation_score'] ?? 0.5),
				'last_updated'    => $reputation['last_updated'] ?? 0,
				'total_requests'  => $reputation['total_requests'] ?? 0,
				'violation_count' => $reputation['violation_count'] ?? 0,
				'categories'      => json_decode($reputation['categories'] ?? '[]', true) ?: [],
			];
		}

		// Return default reputation for new IPs
		return [
			'score'           => 0.5,
			'last_updated'    => 0,
			'total_requests'  => 0,
			'violation_count' => 0,
			'categories'      => [],
		];
	}

	/**
	 * Update IP reputation based on behavior
	 */
	public function updateReputation(string $ip, string $action, float $scoreChange): void {
		$reputation = $this->getIPReputation($ip);

		// Since getIPReputation now always returns an array (never null), we can safely access properties
		$newScore = max(0.0, min(1.0, $reputation['score'] + $scoreChange));
		$categories = $reputation['categories'];

		// Add action category
		if (!in_array($action, $categories)) {
			$categories[] = $action;
		}

		// Update or create reputation record
		$existing = $this->storage->findOne('ip_reputation', ['ip_address' => $ip]);

		if ($existing) {
			$this->storage->update('ip_reputation', $existing['id'], [
				'reputation_score' => $newScore,
				'last_updated'     => time(),
				'total_requests'   => $reputation['total_requests'] + 1,
				'violation_count'  => $scoreChange < 0 ? $reputation['violation_count'] + 1 : $reputation['violation_count'],
				'categories'       => json_encode($categories),
			]);
		} else {
			$this->storage->insert('ip_reputation', [
				'ip_address'       => $ip,
				'reputation_score' => $newScore,
				'last_updated'     => time(),
				'total_requests'   => 1,
				'violation_count'  => $scoreChange < 0 ? 1 : 0,
				'categories'       => json_encode($categories),
			]);
		}
	}

	/**
	 * Get recent violations for IP
	 */
	private function getRecentViolations(string $ip): array {
		$timeWindow = 3600; // 1 hour
		$cutoff = time() - $timeWindow;

		$violations = $this->storage->find('security_log', ['ip_address' => $ip]);
		$recentViolations = array_filter($violations, function ($violation) use ($cutoff) {
			return ($violation['created_at'] ?? 0) > $cutoff;
		});

		return [
			'count'  => count($recentViolations),
			'types'  => array_unique(array_column($recentViolations, 'event_type')),
			'latest' => !empty($recentViolations) ? max(array_column($recentViolations, 'created_at')) : 0,
		];
	}

	/**
	 * Get geolocation data for IP (mock implementation)
	 */
	private function getGeolocation(string $ip): array {
		// In a real implementation, you would use a geolocation service
		// For now, return mock data based on IP ranges

		if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE)) {
			// Check cached geolocation data
			$cached = $this->storage->findOne('ip_geolocation', ['ip_address' => $ip]);

			if ($cached && ($cached['created_at'] ?? 0) > (time() - 86400)) { // Cache for 24 hours
				$locationData = json_decode($cached['location_data'] ?? '{}', true);
				return is_array($locationData) ? $locationData : [];
			}

			// Mock geolocation data - in reality, use MaxMind GeoIP2 or similar
			$mockData = $this->getMockGeolocation($ip);

			// Cache the result
			if ($cached) {
				$this->storage->update('ip_geolocation', $cached['id'], [
					'location_data' => json_encode($mockData),
				]);
			} else {
				$this->storage->insert('ip_geolocation', [
					'ip_address'    => $ip,
					'location_data' => json_encode($mockData),
				]);
			}

			return $mockData;
		}

		return [];
	}

	/**
	 * Mock geolocation data (replace with real service)
	 */
	private function getMockGeolocation(string $ip): array {
		$ipNum = ip2long($ip);

		// Very basic mock based on IP ranges
		if ($ipNum >= ip2long('1.0.0.0') && $ipNum <= ip2long('126.255.255.255')) {
			return [
				'country'      => 'US',
				'country_name' => 'United States',
				'region'       => 'CA',
				'city'         => 'Los Angeles',
				'latitude'     => 34.0522,
				'longitude'    => -118.2437,
				'timezone'     => 'America/Los_Angeles',
				'asn'          => 'AS7922 Comcast Cable Communications',
			];
		}

		return [
			'country'      => 'UNKNOWN',
			'country_name' => 'Unknown',
			'region'       => '',
			'city'         => '',
			'latitude'     => 0,
			'longitude'    => 0,
			'timezone'     => '',
			'asn'          => '',
		];
	}

	/**
	 * Check if location is suspicious
	 */
	private function isSuspiciousLocation(array $geolocation): bool {
		$highRiskCountries = ['CN', 'RU', 'KP', 'IR']; // Example high-risk countries

		return in_array($geolocation['country'] ?? '', $highRiskCountries);
	}

	/**
	 * Generate security recommendations
	 */
	private function generateRecommendations(array $analysis): array {
		$recommendations = [];

		if ($analysis['trust_score'] < 0.3) {
			$recommendations[] = 'Consider blocking this IP address';
		} elseif ($analysis['trust_score'] < 0.6) {
			$recommendations[] = 'Increase monitoring for this IP address';
		}

		if (!empty($analysis['proxy_info']['is_proxy'])) {
			$recommendations[] = 'Implement additional verification for proxy users';
		}

		if (!empty($analysis['reputation']['violation_count']) && $analysis['reputation']['violation_count'] > 5) {
			$recommendations[] = 'IP has multiple violations - consider temporary block';
		}

		if (empty($recommendations)) {
			$recommendations[] = 'IP appears safe based on current analysis';
		}

		return $recommendations;
	}

	/**
	 * Get known proxy/VPN ranges
	 */
	private function getKnownProxyRanges(): array {
		$ranges = $this->storage->find('known_proxy_ranges', ['active' => true]);

		if (empty($ranges)) {
			// Add some default known proxy ranges
			$defaultRanges = [
				['ip_range' => '127.0.0.1', 'type' => 'localhost'],
				['ip_range' => '10.0.0.0/8', 'type' => 'private'],
				['ip_range' => '172.16.0.0/12', 'type' => 'private'],
				['ip_range' => '192.168.0.0/16', 'type' => 'private'],
			];

			foreach ($defaultRanges as $range) {
				$this->storage->insert('known_proxy_ranges', array_merge($range, ['active' => true]));
			}

			return $defaultRanges;
		}

		return $ranges;
	}

	/**
	 * Log security event
	 */
	private function logSecurityEvent(string $eventType, array $details): void {
		$this->storage->insert('security_log', [
			'event_type' => $eventType,
			'ip_address' => $details['ip'] ?? $this->getClientIP(),
			'user_agent' => $_SERVER['HTTP_USER_AGENT'] ?? '',
			'details'    => json_encode($details),
			'severity'   => 'medium',
		]);
	}

	/**
	 * Load whitelist from storage
	 */
	private function loadWhitelist(): void {
		$this->whitelist = $this->storage->find('ip_whitelist');

		// Add default whitelisted IPs from config
		$configWhitelist = Config::get('ip_security.whitelist', 'security') ?: [];
		foreach ($configWhitelist as $ip) {
			$this->whitelist[] = ['ip_range' => $ip, 'reason' => 'Config whitelist'];
		}
	}

	/**
	 * Load blacklist from storage
	 */
	private function loadBlacklist(): void {
		$this->blacklist = $this->storage->find('ip_blacklist');

		// Add default blacklisted IPs from config
		$configBlacklist = Config::get('ip_security.blacklist', 'security') ?: [];
		foreach ($configBlacklist as $ip) {
			$this->blacklist[] = ['ip_range' => $ip, 'reason' => 'Config blacklist'];
		}
	}

	/**
	 * Load trusted proxies
	 */
	private function loadTrustedProxies(): void {
		$this->trustedProxies = Config::get('ip_security.trusted_proxies', 'security') ?: [
			'127.0.0.1',
			'10.0.0.0/8',
			'172.16.0.0/12',
			'192.168.0.0/16',
		];
	}

	/**
	 * Bulk import IPs to blacklist
	 */
	public function bulkBlacklist(array $ips, string $reason = 'Bulk import'): int {
		$added = 0;

		foreach ($ips as $ip) {
			if (filter_var($ip, FILTER_VALIDATE_IP)) {
				$this->addToBlacklist($ip, $reason);
				$added++;
			}
		}

		return $added;
	}

	/**
	 * Get IP security statistics
	 */
	public function getSecurityStats(): array {
		$whitelist = $this->storage->read('ip_whitelist');
		$blacklist = $this->storage->read('ip_blacklist');
		$reputation = $this->storage->read('ip_reputation');
		$securityLog = $this->storage->read('security_log');

		$recentCutoff = time() - 86400; // Last 24 hours
		$recentEvents = array_filter($securityLog, function ($event) use ($recentCutoff) {
			return ($event['created_at'] ?? 0) > $recentCutoff;
		});

		return [
			'whitelist_count'      => count($whitelist),
			'blacklist_count'      => count($blacklist),
			'tracked_ips'          => count($reputation),
			'recent_events'        => count($recentEvents),
			'avg_reputation_score' => $this->calculateAverageReputation($reputation),
			'top_violators'        => $this->getTopViolators($reputation, 10),
		];
	}

	/**
	 * Calculate average reputation score
	 */
	private function calculateAverageReputation(array $reputations): float {
		if (empty($reputations)) {
			return 0.5;
		}

		$total = array_sum(array_column($reputations, 'reputation_score'));
		return round($total / count($reputations), 2);
	}

	/**
	 * Get top violating IPs
	 */
	private function getTopViolators(array $reputations, int $limit = 10): array {
		usort($reputations, function ($a, $b) {
			return ($b['violation_count'] ?? 0) <=> ($a['violation_count'] ?? 0);
		});

		return array_slice(array_map(function ($rep) {
			return [
				'ip'         => $rep['ip_address'],
				'violations' => $rep['violation_count'] ?? 0,
				'score'      => $rep['reputation_score'] ?? 0.5,
			];
		}, $reputations), 0, $limit);
	}

	/**
	 * Perform maintenance on IP security data
	 */
	public function performMaintenance(): array {
		$results = [
			'expired_blacklist' => 0,
			'expired_whitelist' => 0,
			'old_reputation'    => 0,
			'old_geolocation'   => 0,
		];

		$now = time();

		// Clean expired blacklist entries
		$blacklist = $this->storage->read('ip_blacklist');
		foreach ($blacklist as $id => $entry) {
			if (isset($entry['expires_at']) && $entry['expires_at'] < $now) {
				$this->storage->delete('ip_blacklist', $id);
				$results['expired_blacklist']++;
			}
		}

		// Clean expired whitelist entries
		$whitelist = $this->storage->read('ip_whitelist');
		foreach ($whitelist as $id => $entry) {
			if (isset($entry['expires_at']) && $entry['expires_at'] < $now) {
				$this->storage->delete('ip_whitelist', $id);
				$results['expired_whitelist']++;
			}
		}

		// Clean old reputation data (older than 30 days)
		$reputationCutoff = $now - (86400 * 30);
		$reputation = $this->storage->read('ip_reputation');
		foreach ($reputation as $id => $entry) {
			if (($entry['last_updated'] ?? 0) < $reputationCutoff) {
				$this->storage->delete('ip_reputation', $id);
				$results['old_reputation']++;
			}
		}

		// Clean old geolocation data (older than 7 days)
		$geoCutoff = $now - (86400 * 7);
		$geolocation = $this->storage->read('ip_geolocation');
		foreach ($geolocation as $id => $entry) {
			if (($entry['created_at'] ?? 0) < $geoCutoff) {
				$this->storage->delete('ip_geolocation', $id);
				$results['old_geolocation']++;
			}
		}

		// Refresh caches
		$this->loadWhitelist();
		$this->loadBlacklist();

		return $results;
	}

	/**
	 * Check if IP security is enabled
	 */
	public function isEnabled(): bool {
		return $this->enabled;
	}

	/**
	 * Export IP lists for backup
	 */
	public function exportIPLists(): array {
		return [
			'whitelist'   => $this->storage->read('ip_whitelist'),
			'blacklist'   => $this->storage->read('ip_blacklist'),
			'reputation'  => $this->storage->read('ip_reputation'),
			'exported_at' => time(),
		];
	}

	/**
	 * Import IP lists from backup
	 */
	public function importIPLists(array $data): array {
		$results = [
			'whitelist_imported'  => 0,
			'blacklist_imported'  => 0,
			'reputation_imported' => 0,
		];

		// Import whitelist
		if (isset($data['whitelist'])) {
			foreach ($data['whitelist'] as $entry) {
				$this->storage->insert('ip_whitelist', $entry);
				$results['whitelist_imported']++;
			}
		}

		// Import blacklist
		if (isset($data['blacklist'])) {
			foreach ($data['blacklist'] as $entry) {
				$this->storage->insert('ip_blacklist', $entry);
				$results['blacklist_imported']++;
			}
		}

		// Import reputation
		if (isset($data['reputation'])) {
			foreach ($data['reputation'] as $entry) {
				$this->storage->insert('ip_reputation', $entry);
				$results['reputation_imported']++;
			}
		}

		// Refresh caches
		$this->loadWhitelist();
		$this->loadBlacklist();

		return $results;
	}
}