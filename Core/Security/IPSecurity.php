<?php

namespace Yohns\Core\Security;

use Yohns\Core\Config;

/**
 * IPSecurity class for handling IP-related security functions.
 *
 * This class provides methods for validating, anonymizing, and checking IPs
 * against blacklists or trusted sources.
 *
 * Examples:
 * ```php
 * // Get the current user's IP address
 * $ipSecurity = new IPSecurity();
 * $userIp = $ipSecurity->getClientIp();
 *
 * // Check if the IP is on a blacklist
 * if ($ipSecurity->isBlacklisted($userIp)) {
 *     // Handle blacklisted IP
 * }
 *
 * // Anonymize an IP for logging purposes
 * $anonymizedIp = $ipSecurity->anonymizeIp($userIp);
 * ```
 */
class IPSecurity {
	/**
	 * @var array List of trusted proxy IPs
	 */
	private array $trustedProxies = [];

	/**
	 * @var array List of blacklisted IPs or CIDR ranges
	 */
	private array $blacklistedIps = [];

	/**
	 * @var array List of whitelisted IPs or CIDR ranges
	 */
	private array $whitelistedIps = [];

	/**
	 * Constructor for IPSecurity.
	 * Loads configured trusted proxies and blacklisted IPs from config.
	 */
	public function __construct() {
		// Load trusted proxies from config
		$this->trustedProxies = Config::get('trusted_proxies', 'security') ?: [];

		// Load blacklisted IPs from config
		$this->blacklistedIps = Config::get('blacklisted_ips', 'security') ?: [];

		// Load whitelisted IPs from config
		$this->whitelistedIps = Config::get('whitelisted_ips', 'security') ?: [];
	}

	/**
	 * Get the client's real IP address.
	 * Takes into account trusted proxies and common proxy headers.
	 *
	 * @return string The client's IP address
	 */
	public function getClientIp(): string {
		// Start with the remote address
		$ip = $_SERVER['REMOTE_ADDR'] ?? '0.0.0.0';

		// If the current IP is not a trusted proxy, return it directly
		if (!$this->isIpInList($ip, $this->trustedProxies)) {
			return $ip;
		}

		// Check for common proxy headers
		$headers = [
			'HTTP_X_FORWARDED_FOR',
			'HTTP_CLIENT_IP',
			'HTTP_X_REAL_IP',
			'HTTP_X_FORWARDED'
		];

		foreach ($headers as $header) {
			if (!empty($_SERVER[$header])) {
				// The header could contain multiple IPs (e.g., X-Forwarded-For: client, proxy1, proxy2)
				$ips = explode(',', $_SERVER[$header]);
				$clientIp = trim($ips[0]);

				// Validate as an IP address
				if (filter_var($clientIp, FILTER_VALIDATE_IP)) {
					return $clientIp;
				}
			}
		}

		// If no valid proxy headers found, return the original IP
		return $ip;
	}

	/**
	 * Check if an IP is in a list of IPs or CIDR ranges.
	 *
	 * @param string $ip The IP to check
	 * @param array $list List of IPs or CIDR ranges
	 * @return bool True if the IP is in the list, false otherwise
	 */
	private function isIpInList(string $ip, array $list): bool {
		if (empty($list)) {
			return false;
		}

		foreach ($list as $entry) {
			// Check for exact match
			if ($entry === $ip) {
				return true;
			}

			// Check for CIDR match
			if (strpos($entry, '/') !== false) {
				if ($this->isIpInCidr($ip, $entry)) {
					return true;
				}
			}
		}

		return false;
	}

	/**
	 * Check if an IP is within a CIDR range.
	 *
	 * @param string $ip The IP to check
	 * @param string $cidr The CIDR range (e.g., 192.168.1.0/24)
	 * @return bool True if the IP is in the CIDR range, false otherwise
	 */
	private function isIpInCidr(string $ip, string $cidr): bool {
		// Split CIDR into network and mask
		list($network, $mask) = explode('/', $cidr);

		// Convert IP and network to binary representation
		$ipBinary = ip2long($ip);
		$networkBinary = ip2long($network);

		// Calculate the binary mask
		$binaryMask = ~((1 << (32 - $mask)) - 1);

		// Check if IP is in the network
		return ($ipBinary & $binaryMask) === ($networkBinary & $binaryMask);
	}

	/**
	 * Check if an IP is blacklisted.
	 *
	 * @param string $ip The IP to check
	 * @return bool True if the IP is blacklisted, false otherwise
	 */
	public function isBlacklisted(string $ip): bool {
		// Whitelisted IPs override blacklist
		if ($this->isWhitelisted($ip)) {
			return false;
		}

		return $this->isIpInList($ip, $this->blacklistedIps);
	}

	/**
	 * Check if an IP is whitelisted.
	 *
	 * @param string $ip The IP to check
	 * @return bool True if the IP is whitelisted, false otherwise
	 */
	public function isWhitelisted(string $ip): bool {
		return $this->isIpInList($ip, $this->whitelistedIps);
	}

	/**
	 * Anonymize an IP address for privacy (e.g., for logging).
	 * IPv4: Keep first 3 octets, mask the last (e.g., 192.168.1.xxx)
	 * IPv6: Keep first 3 hextets, mask the rest (e.g., 2001:db8:85a3:xxxx:xxxx:xxxx:xxxx:xxxx)
	 *
	 * @param string $ip The IP to anonymize
	 * @return string The anonymized IP
	 */
	public function anonymizeIp(string $ip): string {
		// Check if it's a valid IPv4 address
		if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) {
			// Get the octets
			$octets = explode('.', $ip);
			// Mask the last octet
			$octets[3] = 'xxx';
			// Rebuild the IP
			return implode('.', $octets);
		}

		// Check if it's a valid IPv6 address
		if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6)) {
			// Get the hextets (note: this is simplified and may not handle all IPv6 formats)
			$hextets = explode(':', $ip);
			// Mask the last 5 hextets
			for ($i = 3; $i < count($hextets); $i++) {
				$hextets[$i] = 'xxxx';
			}
			// Rebuild the IP
			return implode(':', $hextets);
		}

		// If it's not a valid IP, return as is
		return $ip;
	}

	/**
	 * Add an IP to the blacklist.
	 *
	 * @param string $ip The IP to blacklist
	 * @return bool True if the IP was added, false if it was already blacklisted
	 */
	public function addToBlacklist(string $ip): bool {
		if ($this->isBlacklisted($ip)) {
			return false;
		}

		$this->blacklistedIps[] = $ip;

		// Update the config
		$this->saveBlacklist();

		return true;
	}

	/**
	 * Remove an IP from the blacklist.
	 *
	 * @param string $ip The IP to remove from the blacklist
	 * @return bool True if the IP was removed, false if it wasn't blacklisted
	 */
	public function removeFromBlacklist(string $ip): bool {
		if (!$this->isBlacklisted($ip)) {
			return false;
		}

		// Find and remove the IP from the blacklist
		foreach ($this->blacklistedIps as $key => $entry) {
			if ($entry === $ip || ($this->isIpInCidr($ip, $entry) && $entry === $ip)) {
				unset($this->blacklistedIps[$key]);
				break;
			}
		}

		// Reindex the array
		$this->blacklistedIps = array_values($this->blacklistedIps);

		// Update the config
		$this->saveBlacklist();

		return true;
	}

	/**
	 * Save the blacklist to the configuration.
	 *
	 * @return void
	 */
	private function saveBlacklist(): void {
		// Use ConfigEditor to update the security config
		$securityConfig = [
			'blacklisted_ips' => $this->blacklistedIps
		];

		// Add to config file
		\Yohns\Core\ConfigEditor::addToConfig($securityConfig, 'security');
	}

	/**
	 * Add an IP to the whitelist.
	 *
	 * @param string $ip The IP to whitelist
	 * @return bool True if the IP was added, false if it was already whitelisted
	 */
	public function addToWhitelist(string $ip): bool {
		if ($this->isWhitelisted($ip)) {
			return false;
		}

		$this->whitelistedIps[] = $ip;

		// Update the config
		$this->saveWhitelist();

		return true;
	}

	/**
	 * Remove an IP from the whitelist.
	 *
	 * @param string $ip The IP to remove from the whitelist
	 * @return bool True if the IP was removed, false if it wasn't whitelisted
	 */
	public function removeFromWhitelist(string $ip): bool {
		if (!$this->isWhitelisted($ip)) {
			return false;
		}

		// Find and remove the IP from the whitelist
		foreach ($this->whitelistedIps as $key => $entry) {
			if ($entry === $ip || ($this->isIpInCidr($ip, $entry) && $entry === $ip)) {
				unset($this->whitelistedIps[$key]);
				break;
			}
		}

		// Reindex the array
		$this->whitelistedIps = array_values($this->whitelistedIps);

		// Update the config
		$this->saveWhitelist();

		return true;
	}

	/**
	 * Save the whitelist to the configuration.
	 *
	 * @return void
	 */
	private function saveWhitelist(): void {
		// Use ConfigEditor to update the security config
		$securityConfig = [
			'whitelisted_ips' => $this->whitelistedIps
		];

		// Add to config file
		\Yohns\Core\ConfigEditor::addToConfig($securityConfig, 'security');
	}
}