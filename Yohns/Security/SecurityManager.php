<?php

namespace Yohns\Security;

use Yohns\Core\Config;
use Yohns\AntiSpam\Honeypot;
use Yohns\AntiSpam\SpamDetector;

/**
 * SecurityManager class - Main security coordination class
 *
 * Coordinates all security components for comprehensive protection.
 */
class SecurityManager {
	private CSRFToken    $csrfToken;
	private RateLimiter  $rateLimiter;
	private Honeypot     $honeypot;
	private SpamDetector $spamDetector;
	private FileStorage  $storage;
	private ?int         $currentUserId;

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
	 */
	public function applySecurityHeaders(): void {
		$headers = $this->getSecurityHeaders();

		foreach ($headers as $name => $value) {
			header("{$name}: {$value}");
		}
	}

	/**
	 * Validate and clean content
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
	 */
	public function getCSRFToken(): CSRFToken {
		return $this->csrfToken;
	}

	public function getRateLimiter(): RateLimiter {
		return $this->rateLimiter;
	}

	public function getHoneypot(): Honeypot {
		return $this->honeypot;
	}

	public function getSpamDetector(): SpamDetector {
		return $this->spamDetector;
	}

	public function getStorage(): FileStorage {
		return $this->storage;
	}
}