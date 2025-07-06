<?php

namespace Yohns\Core\Security;

use PDOChainer\PDOChainer;
use Yohns\Core\Config;

/**
 * SecurityManager class that acts as a facade for all security-related functionality.
 *
 * This class provides a centralized interface to all security features including
 * rate limiting, token management, IP security, and content validation.
 *
 * Examples:
 * ```php
 * // Initialize the security manager
 * $pdo = new PDOChainer([
 *     'host' => 'localhost',
 *     'dbname' => 'social_network',
 *     'user' => 'root',
 *     'pass' => 'password'
 * ]);
 * $security = new SecurityManager($pdo);
 *
 * // Check if a request should be rate limited
 * if ($security->isRateLimited('post')) {
 *     echo "You're posting too frequently. Please wait a moment.";
 *     exit;
 * }
 *
 * // Generate a CSRF token for a form
 * echo $security->csrfField();
 *
 * // Validate posted content
 * $cleanContent = $security->validateContent($_POST['message']);
 * ```
 */
class SecurityManager {
	/**
	 * @var RateLimiter Rate limiter component
	 */
	private RateLimiter $rateLimiter;

	/**
	 * @var TokenManager Token manager component
	 */
	private TokenManager $tokenManager;

	/**
	 * @var IPSecurity IP security component
	 */
	private IPSecurity $ipSecurity;

	/**
	 * @var ContentValidator Content validator component
	 */
	private ContentValidator $contentValidator;

	/**
	 * @var string Current client IP address
	 */
	private string $clientIp;

	/**
	 * @var int|null Current user ID (if authenticated)
	 */
	private ?int $userId = null;

	/**
	 * SecurityManager constructor.
	 *
	 * @param PDOChainer $pdo PDO chain wrapper instance
	 * @param int|null $userId Current user ID (if authenticated)
	 */
	public function __construct(PDOChainer $pdo, ?int $userId = null) {
		// Initialize components
		$this->rateLimiter = new RateLimiter($pdo);
		$this->tokenManager = new TokenManager($pdo);
		$this->ipSecurity = new IPSecurity();
		$this->contentValidator = new ContentValidator();

		// Get client IP
		$this->clientIp = $this->ipSecurity->getClientIp();

		// Set user ID
		$this->userId = $userId;
	}

	/**
	 * Set the current user ID.
	 *
	 * @param int|null $userId The user ID or null if not authenticated
	 * @return void
	 */
	public function setUserId(?int $userId): void {
		$this->userId = $userId;
	}

	/**
	 * Check if a request should be rate limited.
	 *
	 * @param string $actionType The type of action being performed
	 * @return bool True if the request should be limited, false otherwise
	 */
	public function isRateLimited(string $actionType): bool {
		// Whitelisted IPs are never rate limited
		if ($this->ipSecurity->isWhitelisted($this->clientIp)) {
			return false;
		}

		return $this->rateLimiter->isLimited($this->clientIp, $actionType, $this->userId);
	}

	/**
	 * Get information about remaining requests for rate limiting.
	 *
	 * @param string $actionType The type of action
	 * @return array Information about remaining requests
	 */
	public function getRateLimitInfo(string $actionType): array {
		$identifier = $this->userId ? "user:{$this->userId}" : "ip:{$this->clientIp}";
		return $this->rateLimiter->getRemainingRequests($identifier, $actionType);
	}

	/**
	 * Generate a CSRF token and return it.
	 *
	 * @param int $expiration Expiration time in seconds (default: 3600 = 1 hour)
	 * @return string The generated token
	 */
	public function generateCsrfToken(int $expiration = 3600): string {
		return $this->tokenManager->generateToken('csrf', $expiration);
	}

	/**
	 * Generate a CSRF token and output the HTML input field.
	 *
	 * @param int $expiration Expiration time in seconds (default: 3600 = 1 hour)
	 * @return string HTML input field with CSRF token
	 */
	public function csrfField(int $expiration = 3600): string {
		return $this->tokenManager->csrfField($expiration);
	}

	/**
	 * Validate a CSRF token from a request.
	 *
	 * @param array $request The request array ($_POST, $_GET, etc.)
	 * @param bool $consumeToken Whether to consume the token after validation
	 * @return bool True if the CSRF token is valid, false otherwise
	 */
	public function validateCsrfToken(array $request, bool $consumeToken = true): bool {
		return $this->tokenManager->validateCsrfToken($request, $consumeToken);
	}

	/**
	 * Generate a token for a specific context.
	 *
	 * @param string $context The context or purpose of the token
	 * @param int $expiration Expiration time in seconds
	 * @param array $data Additional data to associate with the token
	 * @return string The generated token
	 */
	public function generateToken(string $context, int $expiration = 3600, array $data = []): string {
		return $this->tokenManager->generateToken($context, $expiration, $data);
	}

	/**
	 * Validate a token.
	 *
	 * @param string $token The token to validate
	 * @param string $context The context or purpose of the token
	 * @param bool $consumeToken Whether to consume the token after validation
	 * @return bool True if the token is valid, false otherwise
	 */
	public function validateToken(string $token, string $context, bool $consumeToken = true): bool {
		return $this->tokenManager->validateToken($token, $context, $consumeToken);
	}

	/**
	 * Check if an IP is blacklisted.
	 *
	 * @param string|null $ip The IP to check, or null to use the current client IP
	 * @return bool True if the IP is blacklisted, false otherwise
	 */
	public function isIpBlacklisted(?string $ip = null): bool {
		$ip = $ip ?? $this->clientIp;
		return $this->ipSecurity->isBlacklisted($ip);
	}

	/**
	 * Add an IP to the blacklist.
	 *
	 * @param string $ip The IP to blacklist
	 * @return bool True if the IP was added, false if it was already blacklisted
	 */
	public function blacklistIp(string $ip): bool {
		return $this->ipSecurity->addToBlacklist($ip);
	}

	/**
	 * Validate and sanitize content.
	 *
	 * @param string $content The content to validate
	 * @param bool $allowHtml Whether to allow some HTML tags
	 * @param bool $filterProfanity Whether to filter profanity
	 * @return string The sanitized content
	 */
	public function validateContent(string $content, bool $allowHtml = false, bool $filterProfanity = true): string {
		$sanitized = $this->contentValidator->sanitizeText($content, $allowHtml);

		if ($filterProfanity) {
			$sanitized = $this->contentValidator->filterProfanity($sanitized);
		}

		return $sanitized;
	}

	/**
	 * Check if content contains potential spam.
	 *
	 * @param string $content The content to check
	 * @param float $threshold Spam threshold (0.0-1.0, higher = more strict)
	 * @return bool True if the content might be spam, false otherwise
	 */
	public function containsSpam(string $content, float $threshold = 0.5): bool {
		return $this->contentValidator->containsSpam($content, $threshold);
	}

	/**
	 * Check if an email address is valid.
	 *
	 * @param string $email The email address to validate
	 * @param bool $checkDns Whether to check DNS records for the domain
	 * @return bool True if the email is valid, false otherwise
	 */
	public function isValidEmail(string $email, bool $checkDns = false): bool {
		return $this->contentValidator->isValidEmail($email, $checkDns);
	}

	/**
	 * Get the current client IP address.
	 *
	 * @param bool $anonymize Whether to anonymize the IP address
	 * @return string The client IP address
	 */
	public function getClientIp(bool $anonymize = false): string {
		$ip = $this->ipSecurity->getClientIp();

		if ($anonymize) {
			return $this->ipSecurity->anonymizeIp($ip);
		}

		return $ip;
	}

	/**
	 * Run a full security check for a request.
	 * This combines multiple security checks into one method.
	 *
	 * @param string $actionType The type of action being performed
	 * @param array $request The request data ($_POST, $_GET, etc.)
	 * @param bool $checkCsrf Whether to check CSRF token
	 * @param float $spamThreshold Spam threshold for content
	 * @return array Result of the security check with reasons for failure if any
	 */
	public function securityCheck(
		string $actionType,
		array $request = [],
		bool $checkCsrf = true,
		float $spamThreshold = 0.5
	): array {
		$result = [
			'passed'  => true,
			'reason'  => '',
			'details' => []
		];

		// Check if IP is blacklisted
		if ($this->isIpBlacklisted()) {
			$result['passed'] = false;
			$result['reason'] = 'ip_blacklisted';
			$result['details'][] = 'Your IP address has been blocked.';
		}

		// Check rate limiting
		if ($result['passed'] && $this->isRateLimited($actionType)) {
			$result['passed'] = false;
			$result['reason'] = 'rate_limited';
			$result['details'][] = 'You are performing this action too frequently. Please try again later.';

			// Add rate limit info
			$result['rate_limit_info'] = $this->getRateLimitInfo($actionType);
		}

		// Check CSRF token if required
		if ($result['passed'] && $checkCsrf && !empty($request)) {
			if (!$this->validateCsrfToken($request)) {
				$result['passed'] = false;
				$result['reason'] = 'invalid_csrf';
				$result['details'][] = 'Security token validation failed. Please refresh the page and try again.';
			}
		}

		// Check content for spam if present
		if ($result['passed'] && isset($request['content']) && is_string($request['content'])) {
			if ($this->containsSpam($request['content'], $spamThreshold)) {
				$result['passed'] = false;
				$result['reason'] = 'spam_detected';
				$result['details'][] = 'Your content was flagged as potential spam. Please revise and try again.';
			}
		}

		return $result;
	}

	/**
	 * Clean up expired tokens and other temporary security data.
	 *
	 * @return array Cleanup results
	 */
	public function cleanupExpiredData(): array {
		$result = [
			'tokens_removed' => $this->tokenManager->cleanupExpiredTokens()
		];

		return $result;
	}
}