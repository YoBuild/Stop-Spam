<?php

namespace Yohns\Security;

use Yohns\Core\Config;
use Yohns\Security\FileStorage;

/**
 * ContentValidator class for sanitizing and validating user input
 *
 * Provides XSS protection, input sanitization, and content validation.
 * Supports HTML filtering, email validation, URL validation, and comprehensive
 * security threat detection with configurable rules and patterns.
 *
 * @package Yohns\Security
 * @version 1.0.0
 * @author  Yohns Framework
 *
 * Usage example:
 * ```php
 * $validator = new ContentValidator();
 * $result = $validator->validate($userInput, ['allow_html' => false]);
 * if ($result['is_valid']) {
 *     echo "Safe content: " . $result['sanitized_content'];
 * } else {
 *     echo "Validation errors: " . implode(', ', $result['errors']);
 * }
 * ```
 */
class ContentValidator {
	private FileStorage $storage;
	private bool        $enabled;
	private int         $maxLength;
	private bool        $allowHtml;
	private bool        $stripTags;
	private array       $allowedTags;
	private array       $allowedAttributes;
	private array       $xssPatterns;

	/**
	 * Constructor - Initialize content validator with configuration
	 *
	 * Sets up content validation system with configuration from Config class
	 * and loads allowed tags, attributes, and XSS patterns from storage.
	 *
	 * @throws \Exception If FileStorage initialization fails
	 *
	 * Usage example:
	 * ```php
	 * $validator = new ContentValidator();
	 * // Content validator is now ready for use
	 * ```
	 */
	public function __construct() {
		$this->storage = new FileStorage();
		$this->enabled = Config::get('content_validation.enabled', 'security') ?? true;
		$this->maxLength = Config::get('content_validation.max_length', 'security') ?: 10000;
		$this->allowHtml = Config::get('content_validation.allow_html', 'security') ?? false;
		$this->stripTags = Config::get('content_validation.strip_tags', 'security') ?? true;

		$this->loadAllowedTags();
		$this->loadAllowedAttributes();
		$this->loadXSSPatterns();
	}

	/**
	 * Validate and sanitize content
	 *
	 * Performs comprehensive content validation including XSS detection,
	 * HTML sanitization, length checking, and whitespace normalization.
	 * Returns detailed results with sanitized content and security analysis.
	 *
	 * @param string $content Content to validate and sanitize
	 * @param array  $options Validation options to override defaults
	 * @return array Validation result with sanitized content, errors, warnings, and security issues
	 *
	 * Usage example:
	 * ```php
	 * $validator = new ContentValidator();
	 * $result = $validator->validate($userInput, [
	 *     'allow_html' => true,
	 *     'max_length' => 5000,
	 *     'check_xss' => true
	 * ]);
	 *
	 * if ($result['is_valid']) {
	 *     $safeContent = $result['sanitized_content'];
	 *     if (!empty($result['security_issues'])) {
	 *         error_log('Security threats detected: ' . json_encode($result['security_issues']));
	 *     }
	 * } else {
	 *     foreach ($result['errors'] as $error) {
	 *         echo "Error: " . $error . "\n";
	 *     }
	 * }
	 * ```
	 */
	public function validate(string $content, array $options = []): array {
		$options = array_merge([
			'allow_html'           => $this->allowHtml,
			'max_length'           => $this->maxLength,
			'strip_tags'           => $this->stripTags,
			'check_xss'            => true,
			'normalize_whitespace' => true,
			'remove_control_chars' => true,
		], $options);

		$result = [
			'is_valid'          => true,
			'original_content'  => $content,
			'sanitized_content' => $content,
			'errors'            => [],
			'warnings'          => [],
			'changes_made'      => [],
			'security_issues'   => [],
		];

		if (!$this->enabled) {
			return $result;
		}

		// Check content length
		if (strlen($content) > $options['max_length']) {
			$result['errors'][] = "Content exceeds maximum length of {$options['max_length']} characters";
			$result['is_valid'] = false;
			$content = substr($content, 0, $options['max_length']);
			$result['changes_made'][] = 'Content truncated to maximum length';
		}

		// Remove control characters
		if ($options['remove_control_chars']) {
			$originalLength = strlen($content);
			$content = preg_replace('/[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]/', '', $content);
			if (strlen($content) !== $originalLength) {
				$result['changes_made'][] = 'Removed control characters';
			}
		}

		// Check for XSS attempts
		if ($options['check_xss']) {
			$xssCheck = $this->detectXSS($content);
			if (!$xssCheck['is_safe']) {
				$result['security_issues'] = array_merge($result['security_issues'], $xssCheck['threats']);
				$content = $xssCheck['sanitized_content'];
				$result['changes_made'][] = 'Removed XSS threats';
			}
		}

		// Handle HTML content
		if ($options['allow_html']) {
			$htmlResult = $this->sanitizeHTML($content);
			$content = $htmlResult['content'];
			$result['changes_made'] = array_merge($result['changes_made'], $htmlResult['changes']);
			$result['warnings'] = array_merge($result['warnings'], $htmlResult['warnings']);
		} elseif ($options['strip_tags']) {
			$originalLength = strlen($content);
			$content = strip_tags($content);
			if (strlen($content) !== $originalLength) {
				$result['changes_made'][] = 'Removed HTML tags';
			}
		}

		// Normalize whitespace
		if ($options['normalize_whitespace']) {
			$original = $content;
			$content = preg_replace('/\s+/', ' ', $content);
			$content = trim($content);
			if ($content !== $original) {
				$result['changes_made'][] = 'Normalized whitespace';
			}
		}

		// Final encoding for output safety
		$result['sanitized_content'] = $this->finalEncode($content);

		// Log security issues if found
		if (!empty($result['security_issues'])) {
			$this->logSecurityIssue($result);
		}

		return $result;
	}

	/**
	 * Detect XSS attempts in content
	 *
	 * Analyzes content for known XSS attack patterns and malicious code.
	 * Returns threat analysis and sanitized content with dangerous elements removed.
	 *
	 * @param string $content Content to analyze for XSS threats
	 * @return array XSS analysis with safety status, threats found, and sanitized content
	 *
	 * Usage example:
	 * ```php
	 * $validator = new ContentValidator();
	 * $xssCheck = $validator->detectXSS('<script>alert("XSS")</script>Hello World');
	 *
	 * if (!$xssCheck['is_safe']) {
	 *     echo "XSS threats detected:\n";
	 *     foreach ($xssCheck['threats'] as $threat) {
	 *         echo "- " . $threat['description'] . " (Severity: " . $threat['severity'] . ")\n";
	 *     }
	 *     echo "Sanitized: " . $xssCheck['sanitized_content'];
	 * }
	 * ```
	 */
	public function detectXSS(string $content): array {
		$result = [
			'is_safe'           => true,
			'threats'           => [],
			'sanitized_content' => $content,
		];

		$originalContent = $content;

		foreach ($this->xssPatterns as $patternName => $pattern) {
			if (preg_match($pattern['regex'], $content)) {
				$result['is_safe'] = false;
				$result['threats'][] = [
					'type'        => $patternName,
					'description' => $pattern['description'],
					'severity'    => $pattern['severity'],
				];

				// Remove the malicious content
				$content = preg_replace($pattern['regex'], $pattern['replacement'] ?? '', $content);
			}
		}

		$result['sanitized_content'] = $content;

		return $result;
	}

	/**
	 * Check if attribute is allowed for a tag
	 *
	 * Verifies whether a specific attribute is permitted for a given HTML tag
	 * based on global and tag-specific allowlists.
	 *
	 * @param string $tagName  HTML tag name to check
	 * @param string $attrName Attribute name to check
	 * @return bool True if attribute is allowed for the tag, false otherwise
	 *
	 * Usage example:
	 * ```php
	 * if ($this->isAttributeAllowed('a', 'href')) {
	 *     // href attribute is allowed on anchor tags
	 * }
	 * if ($this->isAttributeAllowed('img', 'onerror')) {
	 *     // This would return false for security
	 * }
	 * ```
	 */
	private function isAttributeAllowed(string $tagName, string $attrName): bool {
		// Global allowed attributes
		$globalAttrs = $this->allowedAttributes['*'] ?? [];
		if (in_array($attrName, $globalAttrs)) {
			return true;
		}

		// Tag-specific allowed attributes
		$tagAttrs = $this->allowedAttributes[$tagName] ?? [];
		return in_array($attrName, $tagAttrs);
	}

	/**
	 * Check if attribute value is dangerous
	 *
	 * Analyzes attribute values for potentially dangerous content such as
	 * JavaScript protocols, event handlers, and malicious data URLs.
	 *
	 * @param string $value Attribute value to check
	 * @return bool True if value is dangerous, false if safe
	 *
	 * Usage example:
	 * ```php
	 * if ($this->isDangerousAttributeValue('javascript:alert("XSS")')) {
	 *     // Returns true - dangerous JavaScript protocol
	 * }
	 * if ($this->isDangerousAttributeValue('https://example.com')) {
	 *     // Returns false - safe URL
	 * }
	 * ```
	 */
	private function isDangerousAttributeValue(string $value): bool {
		$dangerousPatterns = [
			'/javascript:/i',
			'/vbscript:/i',
			'/data:text\/html/i',
			'/data:application\/x-/i',
			'/on\w+\s*=/i', // Event handlers
		];

		foreach ($dangerousPatterns as $pattern) {
			if (preg_match($pattern, $value)) {
				return true;
			}
		}

		return false;
	}

	/**
	 * Final encoding for safe output
	 *
	 * Applies HTML entity encoding to content for safe output in HTML context.
	 * Uses comprehensive encoding to prevent XSS in various scenarios.
	 *
	 * @param string $content Content to encode
	 * @return string HTML-encoded content safe for output
	 *
	 * Usage example:
	 * ```php
	 * $safeOutput = $this->finalEncode('<script>alert("test")</script>');
	 * // Returns: &lt;script&gt;alert(&quot;test&quot;)&lt;/script&gt;
	 * ```
	 */
	private function finalEncode(string $content): string {
		// HTML encode special characters
		return htmlspecialchars($content, ENT_QUOTES | ENT_HTML5, 'UTF-8');
	}

	/**
	 * Validate specific input types
	 *
	 * Validates and sanitizes email addresses using comprehensive checks
	 * including format validation, length limits, and normalization.
	 *
	 * @param string $email Email address to validate
	 * @return array Validation result with sanitized email and error messages
	 *
	 * Usage example:
	 * ```php
	 * $validator = new ContentValidator();
	 * $emailResult = $validator->validateEmail('  USER@EXAMPLE.COM  ');
	 *
	 * if ($emailResult['is_valid']) {
	 *     echo "Valid email: " . $emailResult['sanitized_email']; // user@example.com
	 * } else {
	 *     foreach ($emailResult['errors'] as $error) {
	 *         echo "Email error: " . $error . "\n";
	 *     }
	 * }
	 * ```
	 */
	public function validateEmail(string $email): array {
		$result = [
			'is_valid'        => false,
			'sanitized_email' => trim($email),
			'errors'          => [],
		];

		$email = trim($email);

		if (empty($email)) {
			$result['errors'][] = 'Email address is required';
			return $result;
		}

		if (strlen($email) > 254) {
			$result['errors'][] = 'Email address is too long';
			return $result;
		}

		if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
			$result['errors'][] = 'Invalid email address format';
			return $result;
		}

		$result['is_valid'] = true;
		$result['sanitized_email'] = strtolower($email);

		return $result;
	}

	/**
	 * Validate URL
	 *
	 * Validates and sanitizes URLs with protocol checking, scheme validation,
	 * and security analysis for suspicious patterns.
	 *
	 * @param string $url URL to validate
	 * @return array Validation result with sanitized URL, errors, and warnings
	 *
	 * Usage example:
	 * ```php
	 * $validator = new ContentValidator();
	 * $urlResult = $validator->validateURL('example.com/path');
	 *
	 * if ($urlResult['is_valid']) {
	 *     echo "Valid URL: " . $urlResult['sanitized_url']; // http://example.com/path
	 *     foreach ($urlResult['warnings'] as $warning) {
	 *         echo "Warning: " . $warning . "\n";
	 *     }
	 * }
	 * ```
	 */
	public function validateURL(string $url): array {
		$result = [
			'is_valid'      => false,
			'sanitized_url' => trim($url),
			'errors'        => [],
			'warnings'      => [],
		];

		$url = trim($url);

		if (empty($url)) {
			$result['errors'][] = 'URL is required';
			return $result;
		}

		// Add protocol if missing
		if (!preg_match('/^https?:\/\//i', $url)) {
			$url = 'http://' . $url;
			$result['warnings'][] = 'Added http:// protocol';
		}

		if (!filter_var($url, FILTER_VALIDATE_URL)) {
			$result['errors'][] = 'Invalid URL format';
			return $result;
		}

		$parsedUrl = parse_url($url);

		// Check for suspicious schemes
		$allowedSchemes = ['http', 'https', 'ftp'];
		if (!in_array($parsedUrl['scheme'] ?? '', $allowedSchemes)) {
			$result['errors'][] = 'URL scheme not allowed';
			return $result;
		}

		// Check for IP addresses (potentially suspicious)
		if (filter_var($parsedUrl['host'] ?? '', FILTER_VALIDATE_IP)) {
			$result['warnings'][] = 'URL contains IP address instead of domain name';
		}

		$result['is_valid'] = true;
		$result['sanitized_url'] = $url;

		return $result;
	}

	/**
	 * Validate phone number
	 *
	 * Validates and formats phone numbers with digit extraction,
	 * length validation, and intelligent formatting for different regions.
	 *
	 * @param string $phone Phone number to validate
	 * @return array Validation result with sanitized and formatted phone numbers
	 *
	 * Usage example:
	 * ```php
	 * $validator = new ContentValidator();
	 * $phoneResult = $validator->validatePhone('(555) 123-4567');
	 *
	 * if ($phoneResult['is_valid']) {
	 *     echo "Digits only: " . $phoneResult['sanitized_phone']; // 5551234567
	 *     echo "Formatted: " . $phoneResult['formatted_phone'];   // (555) 123-4567
	 * }
	 * ```
	 */
	public function validatePhone(string $phone): array {
		$result = [
			'is_valid'        => false,
			'sanitized_phone' => '',
			'formatted_phone' => '',
			'errors'          => [],
		];

		// Remove all non-digit characters
		$digitsOnly = preg_replace('/[^0-9]/', '', $phone);
		$result['sanitized_phone'] = $digitsOnly;

		if (empty($digitsOnly)) {
			$result['errors'][] = 'Phone number is required';
			return $result;
		}

		$length = strlen($digitsOnly);

		// Check length (US format: 10 digits, international: 7-15 digits)
		if ($length < 7 || $length > 15) {
			$result['errors'][] = 'Phone number must be between 7 and 15 digits';
			return $result;
		}

		// Format US phone numbers
		if ($length === 10) {
			$result['formatted_phone'] = sprintf('(%s) %s-%s',
				substr($digitsOnly, 0, 3),
				substr($digitsOnly, 3, 3),
				substr($digitsOnly, 6, 4)
			);
		} elseif ($length === 11 && $digitsOnly[0] === '1') {
			$result['formatted_phone'] = sprintf('+1 (%s) %s-%s',
				substr($digitsOnly, 1, 3),
				substr($digitsOnly, 4, 3),
				substr($digitsOnly, 7, 4)
			);
		} else {
			$result['formatted_phone'] = '+' . $digitsOnly;
		}

		$result['is_valid'] = true;

		return $result;
	}

	/**
	 * Validate and sanitize filename
	 *
	 * Sanitizes filenames by removing dangerous characters, preventing
	 * directory traversal, and checking for malicious file extensions.
	 *
	 * @param string $filename Filename to validate and sanitize
	 * @return array Validation result with sanitized filename, errors, and warnings
	 *
	 * Usage example:
	 * ```php
	 * $validator = new ContentValidator();
	 * $fileResult = $validator->validateFilename('../../../etc/passwd.txt');
	 *
	 * if ($fileResult['is_valid']) {
	 *     echo "Safe filename: " . $fileResult['sanitized_filename']; // passwd.txt
	 * } else {
	 *     foreach ($fileResult['errors'] as $error) {
	 *         echo "Filename error: " . $error . "\n";
	 *     }
	 * }
	 * ```
	 */
	public function validateFilename(string $filename): array {
		$result = [
			'is_valid'           => false,
			'sanitized_filename' => '',
			'errors'             => [],
			'warnings'           => [],
		];

		if (empty($filename)) {
			$result['errors'][] = 'Filename is required';
			return $result;
		}

		// Remove directory traversal attempts
		$filename = basename($filename);

		// Remove dangerous characters
		$sanitized = preg_replace('/[^a-zA-Z0-9._-]/', '_', $filename);

		// Remove multiple dots/underscores
		$sanitized = preg_replace('/[._-]{2,}/', '_', $sanitized);

		// Ensure it doesn't start with a dot
		$sanitized = ltrim($sanitized, '.');

		if (empty($sanitized)) {
			$result['errors'][] = 'Filename contains only invalid characters';
			return $result;
		}

		// Check for dangerous extensions
		$extension = strtolower(pathinfo($sanitized, PATHINFO_EXTENSION));
		$dangerousExtensions = [
			'php', 'phtml', 'php3', 'php4', 'php5', 'phar',
			'exe', 'bat', 'cmd', 'com', 'scr', 'vbs', 'js'
		];

		if (in_array($extension, $dangerousExtensions)) {
			$result['errors'][] = 'File extension not allowed for security reasons';
			return $result;
		}

		// Limit length
		if (strlen($sanitized) > 255) {
			$sanitized = substr($sanitized, 0, 255);
			$result['warnings'][] = 'Filename truncated to 255 characters';
		}

		$result['is_valid'] = true;
		$result['sanitized_filename'] = $sanitized;

		if ($sanitized !== $filename) {
			$result['warnings'][] = 'Filename was sanitized';
		}

		return $result;
	}

	/**
	 * Load allowed HTML tags
	 *
	 * Loads the list of permitted HTML tags from storage or creates
	 * default safe tags if none exist.
	 *
	 * @return void
	 *
	 * Usage example:
	 * ```php
	 * $this->loadAllowedTags();
	 * // Allowed HTML tags are now loaded from storage
	 * ```
	 */
	private function loadAllowedTags(): void {
		$tags = $this->storage->findOne('allowed_html_tags', ['active' => true]);

		if ($tags && isset($tags['tags'])) {
			$this->allowedTags = $tags['tags'];
		} else {
			// Default safe tags
			$this->allowedTags = [
				'p', 'br', 'strong', 'b', 'em', 'i', 'u', 'span',
				'h1', 'h2', 'h3', 'h4', 'h5', 'h6',
				'ul', 'ol', 'li', 'blockquote',
				'a', 'img'
			];

			$this->storage->insert('allowed_html_tags', [
				'tags'        => $this->allowedTags,
				'active'      => true,
				'description' => 'Default safe HTML tags',
			]);
		}
	}

	/**
	 * Load allowed HTML attributes
	 *
	 * Loads the list of permitted HTML attributes per tag from storage
	 * or creates default safe attributes if none exist.
	 *
	 * @return void
	 *
	 * Usage example:
	 * ```php
	 * $this->loadAllowedAttributes();
	 * // Allowed HTML attributes configuration is now loaded
	 * ```
	 */
	private function loadAllowedAttributes(): void {
		$attrs = $this->storage->findOne('allowed_html_attributes', ['active' => true]);

		if ($attrs && isset($attrs['attributes'])) {
			$this->allowedAttributes = $attrs['attributes'];
		} else {
			// Default safe attributes
			$this->allowedAttributes = [
				'*'          => ['class', 'id'],
				'a'          => ['href', 'title', 'target'],
				'img'        => ['src', 'alt', 'title', 'width', 'height'],
				'blockquote' => ['cite'],
			];

			$this->storage->insert('allowed_html_attributes', [
				'attributes'  => $this->allowedAttributes,
				'active'      => true,
				'description' => 'Default safe HTML attributes',
			]);
		}
	}

	/**
	 * Load XSS patterns
	 *
	 * Loads XSS detection patterns from storage or creates default
	 * patterns for common XSS attack vectors.
	 *
	 * @return void
	 *
	 * Usage example:
	 * ```php
	 * $this->loadXSSPatterns();
	 * // XSS detection patterns are now loaded and ready for use
	 * ```
	 */
	private function loadXSSPatterns(): void {
		$patterns = $this->storage->findOne('xss_patterns', ['active' => true]);

		if ($patterns && isset($patterns['patterns'])) {
			$this->xssPatterns = $patterns['patterns'];
		} else {
			// Default XSS patterns
			$this->xssPatterns = [
				'script_tags'         => [
					'regex'       => '/<script[^>]*>.*?<\/script>/is',
					'replacement' => '',
					'description' => 'Script tag injection',
					'severity'    => 'high',
				],
				'javascript_protocol' => [
					'regex'       => '/javascript\s*:/i',
					'replacement' => 'blocked:',
					'description' => 'JavaScript protocol in URLs',
					'severity'    => 'high',
				],
				'event_handlers'      => [
					'regex'       => '/on\w+\s*=\s*["\']?[^"\']*["\']?/i',
					'replacement' => '',
					'description' => 'JavaScript event handlers',
					'severity'    => 'high',
				],
				'data_urls'           => [
					'regex'       => '/data\s*:\s*text\/html/i',
					'replacement' => 'blocked:',
					'description' => 'Data URL with HTML content',
					'severity'    => 'medium',
				],
				'vbscript'            => [
					'regex'       => '/vbscript\s*:/i',
					'replacement' => 'blocked:',
					'description' => 'VBScript protocol',
					'severity'    => 'high',
				],
			];

			$this->storage->insert('xss_patterns', [
				'patterns'    => $this->xssPatterns,
				'active'      => true,
				'description' => 'Default XSS detection patterns',
			]);
		}
	}

	/**
	 * Log security issue
	 *
	 * Records security issues found during content validation for
	 * monitoring and analysis purposes.
	 *
	 * @param array $result Validation result containing security issues
	 * @return void
	 *
	 * Usage example:
	 * ```php
	 * $this->logSecurityIssue([
	 *     'original_content' => '<script>alert("xss")</script>',
	 *     'security_issues' => [['type' => 'script_tags', 'severity' => 'high']],
	 *     'changes_made' => ['Removed script tags']
	 * ]);
	 * ```
	 */
	private function logSecurityIssue(array $result): void {
		$this->storage->insert('content_security_log', [
			'content_hash'    => hash('sha256', $result['original_content']),
			'content_length'  => strlen($result['original_content']),
			'security_issues' => json_encode($result['security_issues']),
			'changes_made'    => json_encode($result['changes_made']),
			'ip_address'      => $_SERVER['REMOTE_ADDR'] ?? '0.0.0.0',
			'user_agent'      => $_SERVER['HTTP_USER_AGENT'] ?? '',
			'severity'        => $this->calculateSeverity($result['security_issues']),
		]);
	}

	/**
	 * Calculate severity based on security issues
	 *
	 * Determines the overall severity level based on the highest severity
	 * of individual security issues found.
	 *
	 * @param array $securityIssues Array of security issues with severity levels
	 * @return string Overall severity level ('low', 'medium', 'high')
	 *
	 * Usage example:
	 * ```php
	 * $issues = [
	 *     ['severity' => 'low'],
	 *     ['severity' => 'high'],
	 *     ['severity' => 'medium']
	 * ];
	 * $severity = $this->calculateSeverity($issues); // Returns 'high'
	 * ```
	 */
	private function calculateSeverity(array $securityIssues): string {
		$maxSeverity = 'low';

		foreach ($securityIssues as $issue) {
			$severity = $issue['severity'] ?? 'low';

			if ($severity === 'high') {
				return 'high';
			} elseif ($severity === 'medium' && $maxSeverity !== 'high') {
				$maxSeverity = 'medium';
			}
		}

		return $maxSeverity;
	}

	/**
	 * Get validation statistics
	 *
	 * Returns comprehensive statistics about content validation including
	 * security issues found, severity breakdown, and common attack patterns.
	 *
	 * @return array Validation statistics with counts, breakdowns, and trends
	 *
	 * Usage example:
	 * ```php
	 * $validator = new ContentValidator();
	 * $stats = $validator->getValidationStats();
	 *
	 * echo "Total validations: " . $stats['total_validations'];
	 * echo "Security issues found: " . $stats['security_issues_found'];
	 * echo "Recent validations (24h): " . $stats['recent_validations'];
	 *
	 * foreach ($stats['severity_breakdown'] as $severity => $count) {
	 *     echo "Severity {$severity}: {$count} issues\n";
	 * }
	 *
	 * foreach ($stats['common_issues'] as $issue => $count) {
	 *     echo "Issue {$issue}: {$count} occurrences\n";
	 * }
	 * ```
	 */
	public function getValidationStats(): array {
		$logs = $this->storage->read('content_security_log');
		$recentCutoff = time() - 86400; // Last 24 hours

		$stats = [
			'total_validations'     => count($logs),
			'recent_validations'    => 0,
			'security_issues_found' => 0,
			'severity_breakdown'    => [
				'low'    => 0,
				'medium' => 0,
				'high'   => 0,
			],
			'common_issues'         => [],
		];

		$issueTypes = [];

		foreach ($logs as $log) {
			if (($log['created_at'] ?? 0) > $recentCutoff) {
				$stats['recent_validations']++;
			}

			$securityIssues = json_decode($log['security_issues'] ?? '[]', true);
			if (!empty($securityIssues)) {
				$stats['security_issues_found']++;

				$severity = $log['severity'] ?? 'low';
				$stats['severity_breakdown'][$severity]++;

				foreach ($securityIssues as $issue) {
					$type = $issue['type'] ?? 'unknown';
					$issueTypes[$type] = ($issueTypes[$type] ?? 0) + 1;
				}
			}
		}

		arsort($issueTypes);
		$stats['common_issues'] = array_slice($issueTypes, 0, 10, true);

		return $stats;
	}

	/**
	 * Add custom validation rule
	 *
	 * Registers a custom validation rule with a callable validator function
	 * for application-specific validation requirements.
	 *
	 * @param string   $name      Name of the validation rule
	 * @param callable $validator Validation function to execute
	 * @return void
	 *
	 * Usage example:
	 * ```php
	 * $validator = new ContentValidator();
	 * $validator->addValidationRule('custom_format', function($content) {
	 *     return preg_match('/^[A-Z]{3}-\d{4}$/', $content);
	 * });
	 * // Custom validation rule is now registered
	 * ```
	 */
	public function addValidationRule(string $name, callable $validator): void {
		// Store custom validation rules for future use
		$this->storage->insert('custom_validation_rules', [
			'name'        => $name,
			'description' => 'Custom validation rule',
			'active'      => true,
		]);
	}

	/**
	 * Check if content validator is enabled
	 *
	 * Returns the current enabled status of the content validation system
	 * based on configuration settings.
	 *
	 * @return bool True if content validator is enabled, false otherwise
	 *
	 * Usage example:
	 * ```php
	 * $validator = new ContentValidator();
	 * if ($validator->isEnabled()) {
	 *     $result = $validator->validate($userInput);
	 *     // Process validation results
	 * } else {
	 *     echo "Content validation is disabled";
	 * }
	 * ```
	 */
	public function isEnabled(): bool {
		return $this->enabled;
	}

	/**
	 * Sanitize HTML content
	 *
	 * Performs comprehensive HTML sanitization by removing disallowed tags
	 * and attributes while preserving safe content structure.
	 *
	 * @param string $content HTML content to sanitize
	 * @return array Sanitization result with cleaned content, changes, and warnings
	 *
	 * Usage example:
	 * ```php
	 * $validator = new ContentValidator();
	 * $htmlResult = $validator->sanitizeHTML('<p>Safe content</p><script>alert("xss")</script>');
	 *
	 * echo "Sanitized HTML: " . $htmlResult['content']; // <p>Safe content</p>
	 *
	 * foreach ($htmlResult['changes'] as $change) {
	 *     echo "Change made: " . $change . "\n";
	 * }
	 *
	 * foreach ($htmlResult['warnings'] as $warning) {
	 *     echo "Warning: " . $warning . "\n";
	 * }
	 * ```
	 */
	public function sanitizeHTML(string $content): array {
		$result = [
			'content'  => $content,
			'changes'  => [],
			'warnings' => [],
		];

		// Parse HTML
		$dom = new \DOMDocument();
		$dom->encoding = 'UTF-8';

		// Suppress warnings for malformed HTML
		libxml_use_internal_errors(true);
		$dom->loadHTML('<?xml encoding="UTF-8">' . $content, LIBXML_HTML_NOIMPLIED | LIBXML_HTML_NODEFDTD);
		libxml_clear_errors();

		$xpath = new \DOMXPath($dom);
		$changesCount = 0;

		// Remove disallowed tags
		$allElements = $xpath->query('//*');
		foreach ($allElements as $element) {
			if (!in_array(strtolower($element->tagName), $this->allowedTags)) {
				// Remove the tag but keep content
				$parent = $element->parentNode;
				while ($element->firstChild) {
					$parent->insertBefore($element->firstChild, $element);
				}
				$parent->removeChild($element);
				$changesCount++;
			}
		}

		if ($changesCount > 0) {
			$result['changes'][] = "Removed {$changesCount} disallowed HTML tags";
		}

		// Remove disallowed attributes
		$allElements = $xpath->query('//*[@*]');
		$removedAttrs = 0;

		foreach ($allElements as $element) {
			$attributesToRemove = [];

			foreach ($element->attributes as $attribute) {
				$attrName = strtolower($attribute->name);
				$tagName = strtolower($element->tagName);

				// Check if attribute is allowed for this tag
				if (!$this->isAttributeAllowed($tagName, $attrName)) {
					$attributesToRemove[] = $attrName;
				}

				// Check for dangerous attribute values
				if ($this->isDangerousAttributeValue($attribute->value)) {
					$attributesToRemove[] = $attrName;
					$result['warnings'][] = "Removed dangerous attribute: {$attrName}";
				}
			}

			foreach ($attributesToRemove as $attrName) {
				$element->removeAttribute($attrName);
				$removedAttrs++;
			}
		}

		if ($removedAttrs > 0) {
			$result['changes'][] = "Removed {$removedAttrs} disallowed attributes";
		}

		// Get cleaned HTML
		$result['content'] = $dom->saveHTML();

		// Remove the XML declaration that was added
		$result['content'] = preg_replace('/^<!DOCTYPE.+?>/', '', $result['content']);
		$result['content'] = str_replace(['<html>', '</html>', '<body>', '</body>'], '', $result['content']);
		$result['content'] = trim($result['content']);

		return $result;
	}
}