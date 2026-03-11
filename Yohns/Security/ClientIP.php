<?php

namespace Yohns\Security;

use Yohns\Core\Config;

/**
 * ClientIP utility for determining the real client IP address
 *
 * Consolidates IP detection logic with trusted proxy awareness.
 * All classes that need client IP should use this instead of
 * reading $_SERVER headers directly.
 *
 * Usage example:
 * ```php
 * $ip = ClientIP::get();
 * ```
 */
class ClientIP {
	private static ?array $trustedProxies = null;

	/**
	 * Get the real client IP address.
	 *
	 * Checks headers in priority order, only trusting forwarded headers
	 * when the immediate connection comes from a trusted proxy.
	 *
	 * @return string Client IP address or '0.0.0.0' if unable to determine
	 */
	public static function get(): string {
		$remoteAddr = $_SERVER['REMOTE_ADDR'] ?? '0.0.0.0';
		$trustedProxies = self::getTrustedProxies();

		// Only trust forwarded headers if the direct connection is from a trusted proxy
		if (self::isFromTrustedProxy($remoteAddr, $trustedProxies)) {
			$forwardedHeaders = [
				'HTTP_CF_CONNECTING_IP',     // Cloudflare
				'HTTP_X_FORWARDED_FOR',      // Standard proxy header
				'HTTP_X_REAL_IP',            // Nginx proxy
				'HTTP_X_CLIENT_IP',          // Apache mod_remoteip
				'HTTP_X_CLUSTER_CLIENT_IP',  // Cluster environments
				'HTTP_FORWARDED',            // RFC 7239
			];

			foreach ($forwardedHeaders as $header) {
				if (!empty($_SERVER[$header])) {
					$ips = explode(',', $_SERVER[$header]);

					foreach ($ips as $ip) {
						$ip = trim($ip);

						// Return the first valid public IP
						if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE)) {
							return $ip;
						}
					}
				}
			}
		}

		return $remoteAddr;
	}

	/**
	 * Check if the direct connection comes from a trusted proxy.
	 *
	 * @param string $remoteAddr   The REMOTE_ADDR value
	 * @param array  $trustedProxies  List of trusted proxy IPs/CIDRs
	 * @return bool
	 */
	private static function isFromTrustedProxy(string $remoteAddr, array $trustedProxies): bool {
		foreach ($trustedProxies as $proxy) {
			if (self::ipInRange($remoteAddr, $proxy)) {
				return true;
			}
		}
		return false;
	}

	/**
	 * Check if an IP falls within a CIDR range.
	 *
	 * @param string $ip    IP address to check
	 * @param string $range IP or CIDR range
	 * @return bool
	 */
	private static function ipInRange(string $ip, string $range): bool {
		if (strpos($range, '/') === false) {
			return $ip === $range;
		}

		[$subnet, $bits] = explode('/', $range);
		$bits = (int) $bits;

		// IPv4
		if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) {
			$ip = ip2long($ip);
			$subnet = ip2long($subnet);
			if ($ip === false || $subnet === false) {
				return false;
			}
			$mask = -1 << (32 - $bits);
			return ($ip & $mask) === ($subnet & $mask);
		}

		// IPv6
		if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6)) {
			$ipBin = inet_pton($ip);
			$subnetBin = inet_pton($subnet);
			if ($ipBin === false || $subnetBin === false) {
				return false;
			}

			$fullBytes = intdiv($bits, 8);
			$remainingBits = $bits % 8;

			// Compare full bytes
			if (substr($ipBin, 0, $fullBytes) !== substr($subnetBin, 0, $fullBytes)) {
				return false;
			}

			// Compare remaining bits
			if ($remainingBits > 0 && $fullBytes < 16) {
				$mask = 0xFF << (8 - $remainingBits) & 0xFF;
				if ((ord($ipBin[$fullBytes]) & $mask) !== (ord($subnetBin[$fullBytes]) & $mask)) {
					return false;
				}
			}

			return true;
		}

		return false;
	}

	/**
	 * Get trusted proxy list from config.
	 *
	 * @return array
	 */
	private static function getTrustedProxies(): array {
		if (self::$trustedProxies === null) {
			self::$trustedProxies = Config::get('ip_security.trusted_proxies', 'security') ?: [
				'127.0.0.1',
				'::1',
				'10.0.0.0/8',
				'172.16.0.0/12',
				'192.168.0.0/16',
			];
		}
		return self::$trustedProxies;
	}

	/**
	 * Reset cached trusted proxies (useful for testing).
	 */
	public static function resetCache(): void {
		self::$trustedProxies = null;
	}
}