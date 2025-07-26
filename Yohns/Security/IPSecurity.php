<?php

namespace Yohns\Security;

use Yohns\Core\Config;
use Yohns\Security\FileStorage;

/**
 * IPSecurity class for IP-based security management
 *
 * Handles IP whitelisting, blacklisting, geolocation, and reputation tracking.
 * Provides comprehensive IP analysis including proxy detection, threat assessment,
 * and automated security responses.
 *
 * @package Yohns\Security
 * @version 1.0.0
 * @author  Yohns Framework
 *
 * Usage example:
 * ```php
 * $ipSec = new IPSecurity();
 * $analysis = $ipSec->analyzeIP('192.168.1.100');
 * if ($analysis['is_blocked']) {
 *     die('Access denied from your IP address');
 * }
 * // Add suspicious IP to blacklist
 * $ipSec->addToBlacklist('192.168.1.100', 'Suspicious activity', 3600);
 * ```
 */
class IPSecurity {
	private FileStorage $storage;
	private bool        $enabled;
	private array       $whitelist;
	private array       $blacklist;
	private bool        $checkProxies;
	private int         $maxProxyDepth;
	private array       $trustedProxies;

	/**
	 * Constructor - Initialize IP security system with configuration
	 *
	 * Sets up IP security with configuration from Config class and loads
	 * whitelist, blacklist, and trusted proxy data from storage.
	 *
	 * @throws \Exception If FileStorage initialization fails
	 *
	 * Usage example:
	 * ```php
	 * $ipSec = new IPSecurity();
	 * // IP security system is now ready for analysis
	 * ```
	 */
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
	 *
	 * Performs comprehensive security analysis including whitelist/blacklist checks,
	 * proxy detection, reputation analysis, and geolocation assessment.
	 * Returns detailed threat analysis with trust score and recommendations.
	 *
	 * @param string|null $ipAddress IP address to analyze (null uses client IP)
	 * @return array Complete security analysis with trust score, threats, and recommendations
	 *
	 * Usage example:
	 * ```php
	 * $ipSec = new IPSecurity();
	 * $analysis = $ipSec->analyzeIP('203.0.113.10');
	 *
	 * echo "Trust Score: " . $analysis['trust_score'];
	 * if ($analysis['is_blocked']) {
	 *     echo "IP is blocked!";
	 * }
	 * foreach ($analysis['threats'] as $threat) {
	 *     echo "Threat: " . $threat['description'] . " (Severity: " . $threat['severity'] . ")";
	 * }
	 * ```
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
	 *
	 * Determines the actual client IP address by checking various headers
	 * in order of priority, handling proxy scenarios and validating IPs.
	 *
	 * @return string Client IP address or '0.0.0.0' if unable to determine
	 *
	 * Usage example:
	 * ```php
	 * $ipSec = new IPSecurity();
	 * $clientIP = $ipSec->getClientIP();
	 * echo "Client IP: " . $clientIP;
	 * // Handles Cloudflare, proxies, load balancers automatically
	 * ```
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
	 *
	 * Validates IP format and checks if it's a public IP address or
	 * if it's from a trusted proxy source.
	 *
	 * @param string $ip IP address to validate
	 * @return bool True if IP is valid and public/trusted, false otherwise
	 *
	 * Usage example:
	 * ```php
	 * if ($this->isValidPublicIP('192.168.1.1')) {
	 *     // Process as valid IP
	 * } else {
	 *     // Invalid or private IP
	 * }
	 * ```
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
	 * Check if IP is valid and public
	 *
	 * Validates IP format and checks if it's a public IP address or
	 * if it's from a trusted proxy source.
	 *
	 * @param string $ip IP address to validate
	 * @return bool True if IP is valid and public/trusted, false otherwise
	 *
	 * Usage example:
	 * ```php
	 * if ($this->isValidPublicIP('192.168.1.1')) {
	 *     // Process as valid IP
	 * } else {
	 *     // Invalid or private IP
	 * }
	 * ```
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
	 *
	 * Verifies if the given IP address matches any entry in the whitelist,
	 * including CIDR ranges and individual IPs.
	 *
	 * @param string $ip IP address to check
	 * @return bool True if IP is whitelisted, false otherwise
	 *
	 * Usage example:
	 * ```php
	 * $ipSec = new IPSecurity();
	 * if ($ipSec->isWhitelisted('192.168.1.100')) {
	 *     echo "IP is trusted - bypassing security checks";
	 * }
	 * ```
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
	 *
	 * Verifies if the given IP address matches any entry in the blacklist
	 * and checks for expiration of temporary blacklist entries.
	 *
	 * @param string $ip IP address to check
	 * @return bool True if IP is blacklisted, false otherwise
	 *
	 * Usage example:
	 * ```php
	 * $ipSec = new IPSecurity();
	 * if ($ipSec->isBlacklisted('203.0.113.50')) {
	 *     http_response_code(403);
	 *     die('Access denied');
	 * }
	 * ```
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
	 *
	 * Adds an IP address or CIDR range to the whitelist with optional
	 * expiration time and reason for tracking purposes.
	 *
	 * @param string $ip       IP address or CIDR range to whitelist
	 * @param string $reason   Reason for whitelisting (optional)
	 * @param int    $duration Duration in seconds (0 = permanent)
	 * @return bool True on success
	 *
	 * Usage example:
	 * ```php
	 * $ipSec = new IPSecurity();
	 * $ipSec->addToWhitelist('192.168.1.0/24', 'Office network', 0);
	 * $ipSec->addToWhitelist('203.0.113.10', 'Trusted partner', 86400);
	 * echo "IPs added to whitelist";
	 * ```
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
	 *
	 * Adds an IP address or CIDR range to the blacklist with optional
	 * expiration time and logs the security event.
	 *
	 * @param string $ip       IP address or CIDR range to blacklist
	 * @param string $reason   Reason for blacklisting (optional)
	 * @param int    $duration Duration in seconds (0 = permanent)
	 * @return bool True on success
	 *
	 * Usage example:
	 * ```php
	 * $ipSec = new IPSecurity();
	 * // Temporary block for 1 hour
	 * $ipSec->addToBlacklist('203.0.113.50', 'Brute force attempt', 3600);
	 * // Permanent block
	 * $ipSec->addToBlacklist('198.51.100.25', 'Known malicious IP', 0);
	 * ```
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
	 *
	 * Removes all whitelist entries matching the specified IP address
	 * and refreshes the internal whitelist cache.
	 *
	 * @param string $ip IP address to remove from whitelist
	 * @return bool True if entries were removed, false if not found
	 *
	 * Usage example:
	 * ```php
	 * $ipSec = new IPSecurity();
	 * if ($ipSec->removeFromWhitelist('192.168.1.100')) {
	 *     echo "IP removed from whitelist";
	 * } else {
	 *     echo "IP not found in whitelist";
	 * }
	 * ```
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
	 *
	 * Removes all blacklist entries matching the specified IP address
	 * and refreshes the internal blacklist cache.
	 *
	 * @param string $ip IP address to remove from blacklist
	 * @return bool True if entries were removed, false if not found
	 *
	 * Usage example:
	 * ```php
	 * $ipSec = new IPSecurity();
	 * if ($ipSec->removeFromBlacklist('203.0.113.50')) {
	 *     echo "IP removed from blacklist - access restored";
	 * }
	 * ```
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
	 *
	 * Detects if a request is coming through a proxy or VPN by analyzing
	 * HTTP headers and checking against known proxy IP ranges.
	 *
	 * @param string $ip IP address to analyze for proxy usage
	 * @return array Proxy analysis with detection status, type, and confidence
	 *
	 * Usage example:
	 * ```php
	 * $proxyInfo = $this->analyzeProxy('203.0.113.10');
	 * if ($proxyInfo['is_proxy']) {
	 *     echo "Proxy detected: " . $proxyInfo['proxy_type'];
	 *     echo "Confidence: " . ($proxyInfo['confidence'] * 100) . "%";
	 * }
	 * ```
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
	 *
	 * Retrieves reputation information for an IP address including
	 * reputation score, violation history, and behavioral categories.
	 *
	 * @param string $ip IP address to get reputation for
	 * @return array Reputation data with score, violations, and categories
	 *
	 * Usage example:
	 * ```php
	 * $reputation = $this->getIPReputation('203.0.113.10');
	 * echo "Reputation Score: " . $reputation['score'];
	 * echo "Total Violations: " . $reputation['violation_count'];
	 * ```
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
	 *
	 * Modifies an IP's reputation score based on observed behavior.
	 * Positive actions increase score, negative actions decrease it.
	 *
	 * @param string $ip          IP address to update reputation for
	 * @param string $action      Action type that triggered the update
	 * @param float  $scoreChange Change in reputation score (-1.0 to 1.0)
	 * @return void
	 *
	 * Usage example:
	 * ```php
	 * $ipSec = new IPSecurity();
	 * // Decrease reputation for failed login
	 * $ipSec->updateReputation('203.0.113.10', 'failed_login', -0.1);
	 * // Increase reputation for successful verification
	 * $ipSec->updateReputation('192.168.1.100', 'successful_auth', 0.05);
	 * ```
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
	 *
	 * Retrieves security violations for an IP address within a specified
	 * time window for analysis and decision making.
	 *
	 * @param string $ip IP address to check violations for
	 * @return array Violation summary with count, types, and latest timestamp
	 *
	 * Usage example:
	 * ```php
	 * $violations = $this->getRecentViolations('203.0.113.10');
	 * if ($violations['count'] > 5) {
	 *     echo "High violation count: " . $violations['count'];
	 *     echo "Violation types: " . implode(', ', $violations['types']);
	 * }
	 * ```
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
	 *
	 * Retrieves or determines geographic location information for an IP address.
	 * Uses caching to avoid repeated lookups for the same IP.
	 *
	 * @param string $ip IP address to get geolocation for
	 * @return array Geolocation data with country, region, city, coordinates
	 *
	 * Usage example:
	 * ```php
	 * $location = $this->getGeolocation('203.0.113.10');
	 * echo "Country: " . $location['country_name'];
	 * echo "City: " . $location['city'];
	 * echo "Coordinates: " . $location['latitude'] . ", " . $location['longitude'];
	 * ```
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
	 *
	 * Provides sample geolocation data based on IP ranges.
	 * In production, replace with real geolocation service like MaxMind GeoIP2.
	 *
	 * @param string $ip IP address to generate mock data for
	 * @return array Mock geolocation data
	 *
	 * Usage example:
	 * ```php
	 * $mockData = $this->getMockGeolocation('203.0.113.10');
	 * // Replace this method with real geolocation service integration
	 * ```
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
	 *
	 * Determines if a geographic location is considered high-risk
	 * based on configured country codes and security policies.
	 *
	 * @param array $geolocation Geolocation data to check
	 * @return bool True if location is suspicious, false otherwise
	 *
	 * Usage example:
	 * ```php
	 * $geolocation = ['country' => 'CN', 'country_name' => 'China'];
	 * if ($this->isSuspiciousLocation($geolocation)) {
	 *     echo "Request from high-risk geographic location";
	 * }
	 * ```
	 */
	private function isSuspiciousLocation(array $geolocation): bool {
		$highRiskCountries = ['CN', 'RU', 'KP', 'IR']; // Example high-risk countries

		return in_array($geolocation['country'] ?? '', $highRiskCountries);
	}

	/**
	 * Generate security recommendations
	 *
	 * Analyzes security assessment results and provides actionable
	 * recommendations for handling the IP address.
	 *
	 * @param array $analysis Complete security analysis results
	 * @return array Array of security recommendations
	 *
	 * Usage example:
	 * ```php
	 * $recommendations = $this->generateRecommendations($analysisResults);
	 * foreach ($recommendations as $recommendation) {
	 *     echo "Recommendation: " . $recommendation . "\n";
	 * }
	 * ```
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
	 *
	 * Retrieves list of known proxy and VPN IP ranges from storage
	 * or creates default ranges if none exist.
	 *
	 * @return array Array of known proxy ranges with IP range and type
	 *
	 * Usage example:
	 * ```php
	 * $proxyRanges = $this->getKnownProxyRanges();
	 * foreach ($proxyRanges as $range) {
	 *     echo "Proxy range: " . $range['ip_range'] . " (Type: " . $range['type'] . ")";
	 * }
	 * ```
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
	 *
	 * Records security-related events to the security log for monitoring
	 * and analysis purposes with event details and context.
	 *
	 * @param string $eventType Type of security event
	 * @param array  $details   Event details and context information
	 * @return void
	 *
	 * Usage example:
	 * ```php
	 * $this->logSecurityEvent('suspicious_activity', [
	 *     'ip' => '203.0.113.10',
	 *     'action' => 'multiple_failed_logins',
	 *     'count' => 5
	 * ]);
	 * ```
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
	 *
	 * Loads IP whitelist entries from file storage and merges with
	 * configuration-based whitelist entries.
	 *
	 * @return void
	 *
	 * Usage example:
	 * ```php
	 * $this->loadWhitelist();
	 * // Whitelist cache is now refreshed with latest data
	 * ```
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
	 *
	 * Loads IP blacklist entries from file storage and merges with
	 * configuration-based blacklist entries.
	 *
	 * @return void
	 *
	 * Usage example:
	 * ```php
	 * $this->loadBlacklist();
	 * // Blacklist cache is now refreshed with latest data
	 * ```
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
	 *
	 * Loads list of trusted proxy IP ranges from configuration
	 * for handling legitimate proxy scenarios.
	 *
	 * @return void
	 *
	 * Usage example:
	 * ```php
	 * $this->loadTrustedProxies();
	 * // Trusted proxy list loaded from configuration
	 * ```
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
	 *
	 * Adds multiple IP addresses to the blacklist in a single operation
	 * with validation and error handling.
	 *
	 * @param array  $ips    Array of IP addresses to blacklist
	 * @param string $reason Reason for bulk blacklisting
	 * @return int Number of IPs successfully added to blacklist
	 *
	 * Usage example:
	 * ```php
	 * $ipSec = new IPSecurity();
	 * $maliciousIPs = ['203.0.113.10', '198.51.100.25', '192.0.2.50'];
	 * $added = $ipSec->bulkBlacklist($maliciousIPs, 'Threat intelligence feed');
	 * echo "Added {$added} IPs to blacklist";
	 * ```
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
	 *
	 * Returns comprehensive statistics about the IP security system
	 * including counts, averages, and top violators.
	 *
	 * @return array Security statistics with counts, reputation data, and violators
	 *
	 * Usage example:
	 * ```php
	 * $ipSec = new IPSecurity();
	 * $stats = $ipSec->getSecurityStats();
	 * echo "Blacklisted IPs: " . $stats['blacklist_count'];
	 * echo "Average reputation: " . $stats['avg_reputation_score'];
	 * echo "Recent events: " . $stats['recent_events'];
	 * foreach ($stats['top_violators'] as $violator) {
	 *     echo "IP: " . $violator['ip'] . " (Violations: " . $violator['violations'] . ")";
	 * }
	 * ```
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
	 *
	 * Computes the average reputation score across all tracked IP addresses
	 * for statistical analysis and reporting.
	 *
	 * @param array $reputations Array of reputation records
	 * @return float Average reputation score (0.0 to 1.0)
	 *
	 * Usage example:
	 * ```php
	 * $avgScore = $this->calculateAverageReputation($reputationData);
	 * echo "Average reputation score: " . $avgScore;
	 * ```
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
	 *
	 * Returns the IP addresses with the highest violation counts
	 * sorted by violation frequency for security monitoring.
	 *
	 * @param array $reputations Array of reputation records
	 * @param int   $limit       Maximum number of violators to return
	 * @return array Top violating IPs with violation counts and scores
	 *
	 * Usage example:
	 * ```php
	 * $topViolators = $this->getTopViolators($reputationData, 5);
	 * foreach ($topViolators as $violator) {
	 *     echo "IP: {$violator['ip']}, Violations: {$violator['violations']}";
	 * }
	 * ```
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
	 *
	 * Cleans up expired entries, old data, and refreshes caches
	 * to maintain optimal performance and data accuracy.
	 *
	 * @return array Summary of maintenance operations performed
	 *
	 * Usage example:
	 * ```php
	 * $ipSec = new IPSecurity();
	 * $results = $ipSec->performMaintenance();
	 * echo "Expired blacklist entries removed: " . $results['expired_blacklist'];
	 * echo "Old reputation records cleaned: " . $results['old_reputation'];
	 * // Run this periodically via cron job
	 * ```
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
	 *
	 * Returns the current enabled status of the IP security system
	 * based on configuration settings.
	 *
	 * @return bool True if IP security is enabled, false otherwise
	 *
	 * Usage example:
	 * ```php
	 * $ipSec = new IPSecurity();
	 * if ($ipSec->isEnabled()) {
	 *     $analysis = $ipSec->analyzeIP();
	 *     // Process security analysis
	 * } else {
	 *     echo "IP security is disabled";
	 * }
	 * ```
	 */
	public function isEnabled(): bool {
		return $this->enabled;
	}

	/**
	 * Export IP lists for backup
	 *
	 * Creates a comprehensive backup of all IP security data
	 * including whitelist, blacklist, and reputation information.
	 *
	 * @return array Complete export of IP security data
	 *
	 * Usage example:
	 * ```php
	 * $ipSec = new IPSecurity();
	 * $backup = $ipSec->exportIPLists();
	 * file_put_contents('ip_security_backup.json', json_encode($backup));
	 * echo "IP security data exported successfully";
	 * ```
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
	 *
	 * Restores IP security data from a backup file including
	 * whitelist, blacklist, and reputation information.
	 *
	 * @param array $data Backup data to import
	 * @return array Summary of import operations performed
	 *
	 * Usage example:
	 * ```php
	 * $ipSec = new IPSecurity();
	 * $backupData = json_decode(file_get_contents('backup.json'), true);
	 * $results = $ipSec->importIPLists($backupData);
	 * echo "Whitelist entries imported: " . $results['whitelist_imported'];
	 * echo "Blacklist entries imported: " . $results['blacklist_imported'];
	 * ```
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