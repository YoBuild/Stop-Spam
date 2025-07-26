<?php

namespace Yohns\Security;

use Yohns\Core\Config;
use Yohns\AntiSpam\Honeypot;
use Yohns\AntiSpam\SpamDetector;

/**
 * SecurityManager class - Main security coordination class
 *
 * Coordinates all security components for comprehensive protection.
 * Provides a unified interface for CSRF protection, rate limiting,
 * honeypot anti-spam, content validation, and security monitoring.
 *
 * @package Yohns\Security
 * @version 1.0.0
 * @author  Yohns Framework
 *
 * Usage example:
 * ```php
 * $security = new SecurityManager($userId);
 *
 * // Initialize form security
 * $formSecurity = $security->initializeForm('contact_form');
 * echo $formSecurity['csrf_field'];
 * echo $formSecurity['honeypot_field'];
 *
 * // Validate form submission
 * $securityCheck = $security->securityCheck('contact', $_POST, true, 0.5, 'contact_form');
 * if (!$securityCheck['passed']) {
 *     die('Security validation failed: ' . $securityCheck['reason']);
 * }
 * ```
 */
class SecurityManager {
	private CSRFToken    $csrfToken;
	private RateLimiter  $rateLimiter;
	private Honeypot     $honeypot;
	private SpamDetector $spamDetector;
	private FileStorage  $storage;
	private ?int         $currentUserId;

	/**
	 * Constructor - Initialize security manager with all components
	 *
	 * Sets up all security components including CSRF protection, rate limiting,
	 * honeypot, spam detection, and file storage with optional user context.
	 *
	 * @param int|null $userId Current user ID for context-aware security (optional)
	 *
	 * Usage example:
	 * ```php
	 * // For logged-in user
	 * $security = new SecurityManager(123);
	 *
	 * // For anonymous user
	 * $security = new SecurityManager();
	 * ```
	 */
	public function __construct(?int $userId = null) {
		$this->currentUserId = $userId;
		$this->storage = new FileStorage();
		$this->csrfToken = new CSRFToken();
		$this->rateLimiter = new RateLimiter();
		$this->honeypot = new Honeypot();
		$this->spamDetector = new SpamDetector();
	}

	/**
	 * Comprehensive security check for form submissions
	 *
	 * Performs complete security validation including rate limiting, CSRF protection,
	 * honeypot validation, and spam detection. Returns detailed results for each check.
	 *
	 * @param string $actionType     Type of action being performed (for rate limiting)
	 * @param array  $postData       Form submission data to validate
	 * @param bool   $requireCSRF    Whether CSRF token validation is required
	 * @param float  $spamThreshold  Spam score threshold (0.0-1.0)
	 * @param string $formId         Form identifier for context-specific validation
	 * @return array Security validation result with pass/fail status and details
	 *
	 * Usage example:
	 * ```php
	 * $security = new SecurityManager($userId);
	 * $result = $security->securityCheck('login', $_POST, true, 0.3, 'login_form');
	 *
	 * if (!$result['passed']) {
	 *     error_log('Security check failed: ' . $result['reason']);
	 *     foreach ($result['details'] as $detail) {
	 *         echo "Issue: " . $detail . "\n";
	 *     }
	 *     http_response_code(403);
	 *     exit;
	 * }
	 *
	 * // Check individual security components
	 * if (!$result['security_checks']['csrf']) {
	 *     echo "CSRF validation failed";
	 * }
	 * echo "Spam score: " . $result['security_checks']['spam_detection']['score'];
	 * ```
	 */
	public function securityCheck(
		string $actionType,
		array $postData,
		bool $requireCSRF = true,
		float $spamThreshold = 0.5,
		string $formId = 'default'
	): array {
		$result = [
			'passed'          => true,
			'reason'          => '',
			'details'         => [],
			'security_checks' => [],
		];

		$clientIP = $this->getClientIP();

		// Rate limiting check
		if ($this->rateLimiter->isEnabled()) {
			$isLimited = $this->rateLimiter->isLimited($clientIP, $actionType, $this->currentUserId);
			$result['security_checks']['rate_limit'] = !$isLimited;

			if ($isLimited) {
				$remaining = $this->rateLimiter->getBlockTimeRemaining(
					$this->currentUserId ? "user_{$this->currentUserId}" : "ip_{$clientIP}",
					$actionType
				);
				$result['passed'] = false;
				$result['reason'] = 'Rate limit exceeded';
				$result['details'][] = "Too many requests. Try again in " . ceil($remaining / 60) . " minutes.";
				return $result;
			}
		}

		// CSRF token validation
		if ($requireCSRF && $this->csrfToken->isEnabled()) {
			$csrfValid = $this->csrfToken->validateRequest($formId);
			$result['security_checks']['csrf'] = $csrfValid;

			if (!$csrfValid) {
				$result['passed'] = false;
				$result['reason'] = 'CSRF token validation failed';
				$result['details'][] = 'Invalid or missing security token.';
				return $result;
			}
		}

		// Honeypot validation
		if ($this->honeypot->isEnabled()) {
			$honeypotResult = $this->honeypot->validate($postData, $formId);
			$result['security_checks']['honeypot'] = $honeypotResult['passed'];

			if (!$honeypotResult['passed']) {
				$result['passed'] = false;
				$result['reason'] = $honeypotResult['reason'];
				$result['details'] = array_merge($result['details'], $honeypotResult['details']);
				return $result;
			}
		}

		// Content spam detection
		if ($this->spamDetector->isEnabled()) {
			$content = $this->extractContentFromPost($postData);
			if (!empty($content)) {
				$spamAnalysis = $this->spamDetector->analyzeContent($content);
				$result['security_checks']['spam_detection'] = [
					'score'   => $spamAnalysis['spam_score'],
					'is_spam' => $spamAnalysis['is_spam'],
					'reasons' => $spamAnalysis['reasons'],
				];

				if ($spamAnalysis['spam_score'] >= $spamThreshold) {
					$result['passed'] = false;
					$result['reason'] = 'Content flagged as spam';
					$result['details'] = array_merge($result['details'], $spamAnalysis['reasons']);
					$result['details'][] = "Spam score: {$spamAnalysis['spam_score']}";
					return $result;
				}
			}
		}

		return $result;
	}

	/**
	 * Initialize security for a form
	 *
	 * Generates all necessary security tokens and fields for a form including
	 * CSRF tokens, honeypot fields, and associated CSS for proper rendering.
	 *
	 * @param string $formId Form identifier for context-specific tokens
	 * @return array Array containing HTML fields and meta tags for form security
	 *
	 * Usage example:
	 * ```php
	 * $security = new SecurityManager();
	 * $formSecurity = $security->initializeForm('contact_form');
	 *
	 * echo '<html><head>';
	 * echo $formSecurity['csrf_meta'];
	 * echo $formSecurity['honeypot_css'];
	 * echo '</head><body>';
	 *
	 * echo '<form method="post">';
	 * echo $formSecurity['csrf_field'];
	 * echo $formSecurity['honeypot_field'];
	 * echo '<input type="text" name="message">';
	 * echo '<button type="submit">Submit</button>';
	 * echo '</form></body></html>';
	 * ```
	 */
	public function initializeForm(string $formId = 'default'): array {
		$csrfToken = $this->csrfToken->generateToken($formId);

		return [
			'csrf_field'     => '<input type="hidden" name="csrf_token" value="' . htmlspecialchars($csrfToken) . '">',
			'csrf_meta'      => '<meta name="csrf-token" content="' . htmlspecialchars($csrfToken) . '">',
			'honeypot_field' => $this->honeypot->initialize($formId),
			'honeypot_css'   => $this->honeypot->getCSS(),
		];
	}

	/**
	 * Get security headers for responses
	 *
	 * Returns a comprehensive set of HTTP security headers including CSP,
	 * HSTS, XSS protection, and CORS settings based on configuration.
	 *
	 * @return array Associative array of security headers
	 *
	 * Usage example:
	 * ```php
	 * $security = new SecurityManager();
	 * $headers = $security->getSecurityHeaders();
	 *
	 * foreach ($headers as $name => $value) {
	 *     echo "Header: {$name}: {$value}\n";
	 * }
	 *
	 * // Output includes:
	 * // X-Content-Type-Options: nosniff
	 * // X-Frame-Options: DENY
	 * // Content-Security-Policy: default-src 'self'...
	 * // Strict-Transport-Security: max-age=31536000...
	 * ```
	 */
	public function getSecurityHeaders(): array {
		$baseUrl = Config::get('domain.base_url', 'security') ?: 'https://yoursite.com';
		$allowedOrigins = Config::get('domain.allowed_origins', 'security') ?: [$baseUrl];

		// CDN sources for CSP
		$cdnSources = Config::get('security.csp_cdn_sources', 'security') ?: [
			'https://cdn.jsdelivr.net',
			'https://cdnjs.cloudflare.com',
			'https://fonts.googleapis.com',
			'https://fonts.gstatic.com'
		];

		$cdnSourcesStr = implode(' ', $cdnSources);

		return [
			'X-Content-Type-Options'      => 'nosniff',
			'X-Frame-Options'             => 'DENY',
			'X-XSS-Protection'            => '1; mode=block',
			'Referrer-Policy'             => 'strict-origin-when-cross-origin',
			'Content-Security-Policy'     => "default-src 'self' {$cdnSourcesStr}; script-src 'self' 'unsafe-inline' {$cdnSourcesStr}; style-src 'self' 'unsafe-inline' {$cdnSourcesStr}; font-src 'self' {$cdnSourcesStr}; img-src 'self' data: {$cdnSourcesStr}",
			'Strict-Transport-Security'   => 'max-age=31536000; includeSubDomains',
			'Access-Control-Allow-Origin' => implode(', ', $allowedOrigins),
		];
	}

	/**
	 * Apply security headers to current response
	 *
	 * Automatically sends all security headers to the browser for the current
	 * HTTP response to enhance security posture.
	 *
	 * @return void
	 *
	 * Usage example:
	 * ```php
	 * $security = new SecurityManager();
	 *
	 * // Apply security headers before any output
	 * $security->applySecurityHeaders();
	 *
	 * // Now output content
	 * echo '<html><head><title>Secure Page</title></head>';
	 * echo '<body>Content with security headers applied</body></html>';
	 * ```
	 */
	public function applySecurityHeaders(): void {
		$headers = $this->getSecurityHeaders();

		foreach ($headers as $name => $value) {
			header("{$name}: {$value}");
		}
	}

	/**
	 * Validate and clean content
	 *
	 * Performs content sanitization including length truncation, HTML stripping,
	 * profanity filtering, and XSS protection based on specified options.
	 *
	 * @param string $content        Content to validate and clean
	 * @param bool   $allowHtml      Whether to allow HTML tags in content
	 * @param bool   $cleanProfanity Whether to filter profanity and spam
	 * @return string Cleaned and validated content safe for storage/display
	 *
	 * Usage example:
	 * ```php
	 * $security = new SecurityManager();
	 *
	 * // Clean user comment (no HTML)
	 * $cleanComment = $security->validateContent($userComment, false, true);
	 *
	 * // Clean blog post (allow HTML)
	 * $cleanPost = $security->validateContent($blogContent, true, false);
	 *
	 * // Clean with full restrictions
	 * $userInput = '<script>alert("xss")</script>Some bad words here';
	 * $cleaned = $security->validateContent($userInput);
	 * echo $cleaned; // Safe output without scripts or profanity
	 * ```
	 */
	public function validateContent(string $content, bool $allowHtml = false, bool $cleanProfanity = true): string {
		$maxLength = Config::get('content_validation.max_length', 'security') ?: 10000;

		// Truncate if too long
		if (strlen($content) > $maxLength) {
			$content = substr($content, 0, $maxLength);
		}

		// Strip tags if HTML not allowed
		if (!$allowHtml) {
			$content = strip_tags($content);
		}

		// Clean profanity and spam patterns
		if ($cleanProfanity && $this->spamDetector->isEnabled()) {
			$content = $this->spamDetector->cleanContent($content);
		}

		// Basic XSS protection
		$content = htmlspecialchars($content, ENT_QUOTES, 'UTF-8');

		return trim($content);
	}

	/**
	 * Check if IP is blocked or suspicious
	 *
	 * Analyzes IP address against blacklists, whitelists, and recent violation
	 * history to determine trustworthiness and security risk.
	 *
	 * @param string|null $ipAddress IP address to check (null uses client IP)
	 * @return array IP security analysis with block status, suspicion level, and trust score
	 *
	 * Usage example:
	 * ```php
	 * $security = new SecurityManager();
	 * $ipCheck = $security->checkIPSecurity('192.168.1.100');
	 *
	 * if ($ipCheck['blocked']) {
	 *     http_response_code(403);
	 *     die('Access denied: ' . $ipCheck['reason']);
	 * }
	 *
	 * if ($ipCheck['suspicious']) {
	 *     error_log('Suspicious IP detected: ' . $ipCheck['reason']);
	 *     // Apply additional verification
	 * }
	 *
	 * echo "Trust score: " . ($ipCheck['trust_score'] * 100) . "%";
	 * ```
	 */
	public function checkIPSecurity(string $ipAddress = null): array {
		$ip = $ipAddress ?: $this->getClientIP();

		$result = [
			'blocked'     => false,
			'suspicious'  => false,
			'reason'      => '',
			'trust_score' => 1.0,
		];

		// Check against blacklist
		$blacklist = Config::get('ip_security.blacklist', 'security') ?: [];
		if (in_array($ip, $blacklist)) {
			$result['blocked'] = true;
			$result['reason'] = 'IP in blacklist';
			$result['trust_score'] = 0.0;
			return $result;
		}

		// Check whitelist
		$whitelist = Config::get('ip_security.whitelist', 'security') ?: [];
		if (!empty($whitelist) && in_array($ip, $whitelist)) {
			$result['trust_score'] = 1.0;
			return $result;
		}

		// Check recent violations
		$violations = $this->storage->find('spam_log', ['ip_address' => $ip]);
		$recentViolations = array_filter($violations, function ($v) {
			return ($v['created_at'] ?? 0) > (time() - 3600); // Last hour
		});

		if (count($recentViolations) > 10) {
			$result['suspicious'] = true;
			$result['reason'] = 'Multiple recent violations';
			$result['trust_score'] = 0.3;
		} elseif (count($recentViolations) > 5) {
			$result['suspicious'] = true;
			$result['reason'] = 'Some recent violations';
			$result['trust_score'] = 0.6;
		}

		return $result;
	}

	/**
	 * Generate security token for API access
	 *
	 * Creates a secure API access token for a user with specified expiration
	 * and associates it with IP address for additional security.
	 *
	 * @param int $userId    User ID to generate token for
	 * @param int $expiresIn Token expiration time in seconds (default: 1 hour)
	 * @return string Generated API token
	 *
	 * Usage example:
	 * ```php
	 * $security = new SecurityManager();
	 *
	 * // Generate 24-hour API token
	 * $apiToken = $security->generateAPIToken(123, 86400);
	 *
	 * // Return to client
	 * echo json_encode([
	 *     'api_token' => $apiToken,
	 *     'expires_in' => 86400,
	 *     'token_type' => 'Bearer'
	 * ]);
	 * ```
	 */
	public function generateAPIToken(int $userId, int $expiresIn = 3600): string {
		$token = bin2hex(random_bytes(32));
		$expiresAt = time() + $expiresIn;

		$this->storage->insert('api_tokens', [
			'token'       => $token,
			'user_id'     => $userId,
			'ip_address'  => $this->getClientIP(),
			'expires_at'  => $expiresAt,
			'permissions' => ['api_access'],
		]);

		return $token;
	}

	/**
	 * Validate API token
	 *
	 * Verifies API token validity, expiration, and returns associated user data.
	 * Automatically cleans up expired tokens.
	 *
	 * @param string $token API token to validate
	 * @return array|null Token data if valid, null if invalid or expired
	 *
	 * Usage example:
	 * ```php
	 * $security = new SecurityManager();
	 *
	 * $authHeader = $_SERVER['HTTP_AUTHORIZATION'] ?? '';
	 * if (preg_match('/Bearer\s+(.*)$/i', $authHeader, $matches)) {
	 *     $token = $matches[1];
	 *     $tokenData = $security->validateAPIToken($token);
	 *
	 *     if ($tokenData) {
	 *         $userId = $tokenData['user_id'];
	 *         echo "Authenticated user: " . $userId;
	 *     } else {
	 *         http_response_code(401);
	 *         echo json_encode(['error' => 'Invalid or expired token']);
	 *     }
	 * }
	 * ```
	 */
	public function validateAPIToken(string $token): ?array {
		$tokenData = $this->storage->findOne('api_tokens', ['token' => $token]);

		if (!$tokenData) {
			return null;
		}

		if ($tokenData['expires_at'] < time()) {
			$this->storage->delete('api_tokens', $tokenData['id']);
			return null;
		}

		return $tokenData;
	}

	/**
	 * Log security event
	 *
	 * Records security-related events for monitoring, analysis, and audit trails
	 * with comprehensive context including user, IP, and request information.
	 *
	 * @param string $eventType Type of security event
	 * @param array  $details   Additional event details and context
	 * @return void
	 *
	 * Usage example:
	 * ```php
	 * $security = new SecurityManager(123);
	 *
	 * // Log successful login
	 * $security->logSecurityEvent('login_success', [
	 *     'method' => '2fa',
	 *     'severity' => 'info'
	 * ]);
	 *
	 * // Log security violation
	 * $security->logSecurityEvent('xss_attempt', [
	 *     'content_hash' => hash('sha256', $maliciousContent),
	 *     'severity' => 'high',
	 *     'blocked' => true
	 * ]);
	 * ```
	 */
	public function logSecurityEvent(string $eventType, array $details = []): void {
		$this->storage->insert('security_log', [
			'event_type'  => $eventType,
			'user_id'     => $this->currentUserId,
			'ip_address'  => $this->getClientIP(),
			'user_agent'  => $_SERVER['HTTP_USER_AGENT'] ?? '',
			'request_uri' => $_SERVER['REQUEST_URI'] ?? '',
			'details'     => json_encode($details),
			'severity'    => $details['severity'] ?? 'info',
		]);
	}

	/**
	 * Get comprehensive security statistics
	 *
	 * Returns detailed statistics from all security components for monitoring
	 * and reporting purposes.
	 *
	 * @return array Complete security statistics from all components
	 *
	 * Usage example:
	 * ```php
	 * $security = new SecurityManager();
	 * $stats = $security->getSecurityStats();
	 *
	 * echo "CSRF Tokens:\n";
	 * echo "- Active: " . $stats['csrf']['active'] . "\n";
	 * echo "- Expired: " . $stats['csrf']['expired'] . "\n";
	 *
	 * echo "Rate Limiting:\n";
	 * echo "- Requests blocked: " . $stats['rate_limiting']['blocked_requests'] . "\n";
	 *
	 * echo "Spam Detection:\n";
	 * echo "- Total detections: " . $stats['spam_detection']['total_detections'] . "\n";
	 * echo "- Average score: " . $stats['spam_detection']['average_spam_score'] . "\n";
	 *
	 * echo "Storage:\n";
	 * echo "- Total records: " . $stats['storage']['total_records'] . "\n";
	 * ```
	 */
	public function getSecurityStats(): array {
		return [
			'csrf'           => $this->csrfToken->getStats(),
			'rate_limiting'  => $this->rateLimiter->getStats(),
			'honeypot'       => $this->honeypot->getStats(),
			'spam_detection' => $this->spamDetector->getStats(),
			'storage'        => $this->storage->getStats(),
		];
	}

	/**
	 * Perform security maintenance
	 *
	 * Executes cleanup operations across all security components to remove
	 * expired tokens, old logs, and optimize performance.
	 *
	 * @return array Summary of maintenance operations performed
	 *
	 * Usage example:
	 * ```php
	 * $security = new SecurityManager();
	 * $maintenanceResults = $security->performMaintenance();
	 *
	 * echo "Maintenance completed:\n";
	 * echo "- CSRF tokens cleaned: " . $maintenanceResults['csrf_cleanup'] . "\n";
	 * echo "- Rate limit entries cleaned: " . $maintenanceResults['rate_limit_cleanup'] . "\n";
	 * echo "- Honeypot sessions cleaned: " . $maintenanceResults['honeypot_cleanup'] . "\n";
	 * echo "- Storage cleanup: " . ($maintenanceResults['storage_cleanup'] ? 'Done' : 'Failed') . "\n";
	 *
	 * // Run this periodically via cron job
	 * ```
	 */
	public function performMaintenance(): array {
		$results = [
			'csrf_cleanup'       => $this->csrfToken->cleanupExpiredTokens(),
			'rate_limit_cleanup' => $this->rateLimiter->cleanup(),
			'honeypot_cleanup'   => $this->honeypot->cleanup(),
			'storage_cleanup'    => 0,
		];

		// Perform storage cleanup
		$this->storage->cleanup();
		$results['storage_cleanup'] = 1;

		return $results;
	}

	/**
	 * Extract content from POST data for analysis
	 *
	 * Identifies and extracts user-generated content from form submissions
	 * for spam detection and content validation.
	 *
	 * @param array $postData Form submission data
	 * @return string Combined content from all content fields
	 *
	 * Usage example:
	 * ```php
	 * $postData = [
	 *     'name' => 'John',
	 *     'message' => 'Hello world',
	 *     'comment' => 'This is a comment',
	 *     'email' => 'john@example.com'
	 * ];
	 *
	 * $content = $this->extractContentFromPost($postData);
	 * // Returns: "Hello world This is a comment"
	 * ```
	 */
	private function extractContentFromPost(array $postData): string {
		$contentFields = ['content', 'message', 'text', 'body', 'comment', 'description'];
		$allContent = [];

		foreach ($contentFields as $field) {
			if (isset($postData[$field]) && !empty($postData[$field])) {
				$allContent[] = $postData[$field];
			}
		}

		return implode(' ', $allContent);
	}

	/**
	 * Get client IP address
	 *
	 * Determines the real client IP address by checking various headers
	 * in order of priority, handling proxy and load balancer scenarios.
	 *
	 * @return string Client IP address or '0.0.0.0' if unable to determine
	 *
	 * Usage example:
	 * ```php
	 * $clientIP = $this->getClientIP();
	 * // Returns actual client IP even behind Cloudflare, load balancers, etc.
	 * ```
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
	 * Get individual security components
	 *
	 * Provides access to individual security components for advanced usage
	 * and direct interaction when needed.
	 *
	 * @return CSRFToken CSRF token manager instance
	 *
	 * Usage example:
	 * ```php
	 * $security = new SecurityManager();
	 * $csrf = $security->getCSRFToken();
	 * $token = $csrf->generateToken('special_form');
	 * ```
	 */
	public function getCSRFToken(): CSRFToken {
		return $this->csrfToken;
	}

	/**
	 * Get rate limiter component
	 *
	 * @return RateLimiter Rate limiter instance
	 *
	 * Usage example:
	 * ```php
	 * $security = new SecurityManager();
	 * $rateLimiter = $security->getRateLimiter();
	 * $remaining = $rateLimiter->getRemainingRequests($identifier);
	 * ```
	 */
	public function getRateLimiter(): RateLimiter {
		return $this->rateLimiter;
	}

	/**
	 * Get honeypot component
	 *
	 * @return Honeypot Honeypot anti-spam instance
	 *
	 * Usage example:
	 * ```php
	 * $security = new SecurityManager();
	 * $honeypot = $security->getHoneypot();
	 * $stats = $honeypot->getStats();
	 * ```
	 */
	public function getHoneypot(): Honeypot {
		return $this->honeypot;
	}

	/**
	 * Get spam detector component
	 *
	 * @return SpamDetector Spam detection instance
	 *
	 * Usage example:
	 * ```php
	 * $security = new SecurityManager();
	 * $spamDetector = $security->getSpamDetector();
	 * $analysis = $spamDetector->analyzeContent($content);
	 * ```
	 */
	public function getSpamDetector(): SpamDetector {
		return $this->spamDetector;
	}

	/**
	 * Get file storage component
	 *
	 * @return FileStorage File storage instance
	 *
	 * Usage example:
	 * ```php
	 * $security = new SecurityManager();
	 * $storage = $security->getStorage();
	 * $records = $storage->find('security_log', ['severity' => 'high']);
	 * ```
	 */
	public function getStorage(): FileStorage {
		return $this->storage;
	}
}