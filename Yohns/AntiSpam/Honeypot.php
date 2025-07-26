<?php

namespace Yohns\AntiSpam;

use Yohns\Core\Config;
use Yohns\Security\FileStorage;

/**
 * Honeypot class for detecting automated bot submissions
 *
 * Uses hidden form fields and timing analysis to catch spam bots.
 *
 * Usage example:
 * ```
 * $honeypot = new Honeypot();
 * // In your form:
 * echo $honeypot->getCSS();
 * echo $honeypot->initialize('contact_form');
 * // In your form handler:
 * $result = $honeypot->validate($_POST, 'contact_form');
 * if (!$result['passed']) {
 *     die('Spam detected: ' . $result['reason']);
 * }
 * ```
 */
class Honeypot {
	private FileStorage $storage;
	private bool        $enabled;
	private string      $fieldName;
	private int         $minTime;
	private int         $maxTime;
	private string      $sessionPrefix;

	/**
	 * Constructor - Initialize honeypot with configuration
	 *
	 * Sets up the honeypot system with configuration from Config class.
	 * Starts session if not already active.
	 *
	 * @throws \Exception If FileStorage initialization fails
	 *
	 * Usage example:
	 * ```php
	 * $honeypot = new Honeypot();
	 * ```
	 */
	public function __construct() {
		$this->storage = new FileStorage();
		$this->enabled = Config::get('honeypot.enabled', 'security') ?? true;
		$this->fieldName = Config::get('honeypot.field_name', 'security') ?: 'website';
		$this->minTime = Config::get('honeypot.min_time', 'security') ?: 2;
		$this->maxTime = Config::get('honeypot.max_time', 'security') ?: 3600;
		$this->sessionPrefix = Config::get('honeypot.session_prefix', 'security') ?: 'honeypot_';

		// Start session if not already started
		if (session_status() === PHP_SESSION_NONE) {
			session_start();
		}
	}

	/**
	 * Initialize honeypot for a form
	 *
	 * Creates a honeypot session for the specified form and returns
	 * the hidden field HTML to include in your form.
	 *
	 * @param string $formId Unique identifier for the form (default: 'default')
	 * @return string HTML for hidden honeypot field
	 *
	 * Usage example:
	 * ```php
	 * $honeypot = new Honeypot();
	 * echo $honeypot->initialize('contact_form');
	 * // Outputs: <input type="text" name="website" value="" style="display:none !important;...">
	 * ```
	 */
	public function initialize(string $formId = 'default'): string {
		if (!$this->enabled) {
			return '';
		}

		$timestamp = time();
		$sessionKey = $this->sessionPrefix . $formId;

		// Store timestamp in session
		$_SESSION[$sessionKey] = $timestamp;

		// Store in file storage as backup
		$this->storage->insert('honeypot_sessions', [
			'form_id'    => $formId,
			'timestamp'  => $timestamp,
			'ip_address' => $this->getClientIP(),
			'user_agent' => $_SERVER['HTTP_USER_AGENT'] ?? '',
			'expires_at' => $timestamp + $this->maxTime,
		]);

		// Return hidden field HTML
		return $this->getHiddenField();
	}

	/**
	 * Validate honeypot submission
	 *
	 * Performs comprehensive validation including honeypot field check,
	 * timing analysis, and bot behavior detection.
	 *
	 * @param array  $postData Form submission data ($_POST)
	 * @param string $formId   Form identifier used during initialization
	 * @return array Validation result with 'passed', 'reason', and 'details' keys
	 *
	 * Usage example:
	 * ```php
	 * $result = $honeypot->validate($_POST, 'contact_form');
	 * if (!$result['passed']) {
	 *     error_log('Spam detected: ' . $result['reason']);
	 *     die('Form submission rejected');
	 * }
	 * echo "Form validated successfully!";
	 * ```
	 */
	public function validate(array $postData, string $formId = 'default'): array {
		$result = [
			'passed'  => true,
			'reason'  => '',
			'details' => [],
		];

		if (!$this->enabled) {
			return $result;
		}

		// Check honeypot field
		$honeypotCheck = $this->checkHoneypotField($postData);
		if (!$honeypotCheck['passed']) {
			return $honeypotCheck;
		}

		// Check timing
		$timingCheck = $this->checkTiming($formId);
		if (!$timingCheck['passed']) {
			return $timingCheck;
		}

		// Check for bot behavior patterns
		$behaviorCheck = $this->checkBotBehavior($postData);
		if (!$behaviorCheck['passed']) {
			return $behaviorCheck;
		}

		return $result;
	}

	/**
	 * Check if honeypot field was filled (indicates bot)
	 *
	 * Verifies that the hidden honeypot field remains empty.
	 * Bots often fill all form fields automatically.
	 *
	 * @param array $postData Form submission data
	 * @return array Validation result array
	 *
	 * Usage example:
	 * ```php
	 * $result = $this->checkHoneypotField($_POST);
	 * if (!$result['passed']) {
	 *     // Bot detected - honeypot field was filled
	 * }
	 * ```
	 */
	private function checkHoneypotField(array $postData): array {
		$result = [
			'passed'  => true,
			'reason'  => '',
			'details' => [],
		];

		// Check if honeypot field exists and is filled
		if (isset($postData[$this->fieldName]) && !empty($postData[$this->fieldName])) {
			$result['passed'] = false;
			$result['reason'] = 'Honeypot field filled';
			$result['details'][] = 'Hidden field was filled, indicating automated submission';

			$this->logSpamAttempt('honeypot_field', [
				'field_name'  => $this->fieldName,
				'field_value' => $postData[$this->fieldName],
			]);
		}

		return $result;
	}

	/**
	 * Check submission timing (too fast or too slow indicates bot)
	 *
	 * Validates that form submission time falls within acceptable range.
	 * Too fast suggests automated submission, too slow suggests stale form.
	 *
	 * @param string $formId Form identifier to check timing for
	 * @return array Validation result array
	 *
	 * Usage example:
	 * ```php
	 * $result = $this->checkTiming('contact_form');
	 * if (!$result['passed']) {
	 *     // Form submitted too quickly or too slowly
	 * }
	 * ```
	 */
	private function checkTiming(string $formId): array {
		$result = [
			'passed'  => true,
			'reason'  => '',
			'details' => [],
		];

		$sessionKey = $this->sessionPrefix . $formId;
		$startTime = $_SESSION[$sessionKey] ?? null;

		if (!$startTime) {
			// Try to find in file storage
			$honeypotSession = $this->storage->findOne('honeypot_sessions', [
				'form_id'    => $formId,
				'ip_address' => $this->getClientIP(),
			]);

			if ($honeypotSession && $honeypotSession['expires_at'] > time()) {
				$startTime = $honeypotSession['timestamp'];
			}
		}

		if (!$startTime) {
			$result['passed'] = false;
			$result['reason'] = 'No honeypot session found';
			$result['details'][] = 'Form submission without proper initialization';
			return $result;
		}

		$submissionTime = time() - $startTime;

		// Too fast (likely bot)
		if ($submissionTime < $this->minTime) {
			$result['passed'] = false;
			$result['reason'] = 'Submission too fast';
			$result['details'][] = "Form submitted in {$submissionTime} seconds (minimum: {$this->minTime})";

			$this->logSpamAttempt('timing_too_fast', [
				'submission_time' => $submissionTime,
				'min_time'        => $this->minTime,
			]);
		}

		// Too slow (form might be stale)
		if ($submissionTime > $this->maxTime) {
			$result['passed'] = false;
			$result['reason'] = 'Submission too slow';
			$result['details'][] = "Form submitted after {$submissionTime} seconds (maximum: {$this->maxTime})";

			$this->logSpamAttempt('timing_too_slow', [
				'submission_time' => $submissionTime,
				'max_time'        => $this->maxTime,
			]);
		}

		// Clean up session
		unset($_SESSION[$sessionKey]);

		return $result;
	}

	/**
	 * Check for bot behavior patterns
	 *
	 * Analyzes submission data for patterns typically associated with
	 * automated spam bots, including content analysis and submission frequency.
	 *
	 * @param array $postData Form submission data to analyze
	 * @return array Validation result array
	 *
	 * Usage example:
	 * ```php
	 * $result = $this->checkBotBehavior($_POST);
	 * if (!$result['passed']) {
	 *     // Suspicious bot behavior detected
	 * }
	 * ```
	 */
	private function checkBotBehavior(array $postData): array {
		$result = [
			'passed'  => true,
			'reason'  => '',
			'details' => [],
		];

		$suspiciousPatterns = 0;
		$reasons = [];

		// Check for missing common fields
		$commonFields = ['email', 'name', 'message', 'content', 'subject'];
		$foundFields = 0;
		foreach ($commonFields as $field) {
			if (isset($postData[$field]) && !empty($postData[$field])) {
				$foundFields++;
			}
		}

		if ($foundFields === 0) {
			$suspiciousPatterns++;
			$reasons[] = 'No common form fields found';
		}

		// Check for extremely short content
		$allContent = implode(' ', array_values($postData));
		if (strlen(trim($allContent)) < 3) {
			$suspiciousPatterns++;
			$reasons[] = 'Extremely short content';
		}

		// Check for excessive URLs
		$urlCount = preg_match_all('/https?:\/\//', $allContent);
		if ($urlCount > 5) {
			$suspiciousPatterns++;
			$reasons[] = "Too many URLs found ({$urlCount})";
		}

		// Check for repeated submissions from same IP
		$recentSubmissions = $this->getRecentSubmissions($this->getClientIP(), 300); // 5 minutes
		if (count($recentSubmissions) > 10) {
			$suspiciousPatterns++;
			$reasons[] = 'Too many recent submissions from IP';
		}

		// Fail if too many suspicious patterns
		if ($suspiciousPatterns >= 2) {
			$result['passed'] = false;
			$result['reason'] = 'Suspicious bot behavior';
			$result['details'] = $reasons;

			$this->logSpamAttempt('bot_behavior', [
				'suspicious_patterns' => $suspiciousPatterns,
				'reasons'             => $reasons,
			]);
		}

		return $result;
	}

	/**
	 * Get hidden field HTML
	 *
	 * Returns the HTML input element for the honeypot field.
	 * This field should be hidden from users but visible to bots.
	 *
	 * @return string HTML input element for honeypot field
	 *
	 * Usage example:
	 * ```php
	 * $honeypot = new Honeypot();
	 * echo $honeypot->getHiddenField();
	 * // Outputs: <input type="text" name="website" value="" style="display:none !important;...">
	 * ```
	 */
	public function getHiddenField(): string {
		if (!$this->enabled) {
			return '';
		}

		return '<input type="text" name="' . htmlspecialchars($this->fieldName) . '" value="" style="display:none !important; position:absolute; left:-9999px;" tabindex="-1" autocomplete="off">';
	}

	/**
	 * Get CSS to hide honeypot field
	 *
	 * Returns CSS styles to ensure honeypot field remains hidden
	 * from legitimate users while remaining accessible to bots.
	 *
	 * @return string CSS style block for hiding honeypot field
	 *
	 * Usage example:
	 * ```php
	 * $honeypot = new Honeypot();
	 * echo $honeypot->getCSS();
	 * // Place this in your HTML <head> section
	 * ```
	 */
	public function getCSS(): string {
		if (!$this->enabled) {
			return '';
		}

		return "
		<style>
		.honeypot, input[name='{$this->fieldName}'] {
			display: none !important;
			position: absolute !important;
			left: -9999px !important;
			top: -9999px !important;
			visibility: hidden !important;
		}
		</style>";
	}

	/**
	 * Log spam attempt
	 *
	 * Records detected spam attempts to the spam log for analysis
	 * and monitoring purposes.
	 *
	 * @param string $type    Type of spam detection (e.g., 'honeypot_field', 'timing_too_fast')
	 * @param array  $details Additional details about the spam attempt
	 * @return void
	 *
	 * Usage example:
	 * ```php
	 * $this->logSpamAttempt('custom_rule', [
	 *     'rule_name' => 'excessive_links',
	 *     'link_count' => 15
	 * ]);
	 * ```
	 */
	private function logSpamAttempt(string $type, array $details): void {
		$this->storage->insert('spam_log', [
			'detection_type' => 'honeypot_' . $type,
			'ip_address'     => $this->getClientIP(),
			'user_agent'     => $_SERVER['HTTP_USER_AGENT'] ?? '',
			'user_id'        => $_SESSION['user_id'] ?? null,
			'request_uri'    => $_SERVER['REQUEST_URI'] ?? '',
			'request_method' => $_SERVER['REQUEST_METHOD'] ?? '',
			'details'        => json_encode($details),
			'severity'       => 'medium',
		]);
	}

	/**
	 * Get recent submissions from IP
	 *
	 * Retrieves spam log entries from a specific IP address within
	 * the specified time window for rate limiting analysis.
	 *
	 * @param string $ipAddress  IP address to check
	 * @param int    $timeWindow Time window in seconds to check
	 * @return array Array of recent submission records
	 *
	 * Usage example:
	 * ```php
	 * $recentSubmissions = $this->getRecentSubmissions('192.168.1.1', 300);
	 * if (count($recentSubmissions) > 10) {
	 *     // Too many submissions from this IP
	 * }
	 * ```
	 */
	private function getRecentSubmissions(string $ipAddress, int $timeWindow): array {
		$cutoff = time() - $timeWindow;
		$submissions = $this->storage->find('spam_log', ['ip_address' => $ipAddress]);

		return array_filter($submissions, function ($submission) use ($cutoff) {
			return ($submission['created_at'] ?? 0) > $cutoff;
		});
	}

	/**
	 * Get client IP address
	 *
	 * Determines the real IP address of the client, handling various
	 * proxy and forwarding scenarios (CloudFlare, load balancers, etc.).
	 *
	 * @return string Client IP address or '0.0.0.0' if unable to determine
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
	 * Clean up old honeypot sessions
	 *
	 * Removes expired honeypot sessions from storage to prevent
	 * database bloat and maintain performance.
	 *
	 * @return int Number of sessions cleaned up
	 *
	 * Usage example:
	 * ```php
	 * $honeypot = new Honeypot();
	 * $cleaned = $honeypot->cleanup();
	 * echo "Cleaned up {$cleaned} expired sessions";
	 * ```
	 */
	public function cleanup(): int {
		$sessions = $this->storage->read('honeypot_sessions');
		$now = time();
		$deleted = 0;

		foreach ($sessions as $id => $session) {
			if (($session['expires_at'] ?? 0) < $now) {
				$this->storage->delete('honeypot_sessions', $id);
				$deleted++;
			}
		}

		return $deleted;
	}

	/**
	 * Get honeypot statistics
	 *
	 * Returns comprehensive statistics about honeypot performance
	 * including total attempts, detection types, and recent activity.
	 *
	 * @return array Statistics array with 'total_attempts', 'detection_types', 'recent_attempts'
	 *
	 * Usage example:
	 * ```php
	 * $honeypot = new Honeypot();
	 * $stats = $honeypot->getStats();
	 * echo "Total spam attempts: " . $stats['total_attempts'];
	 * echo "Recent attempts (24h): " . $stats['recent_attempts'];
	 * print_r($stats['detection_types']);
	 * ```
	 */
	public function getStats(): array {
		$spamLog = $this->storage->find('spam_log');
		$honeypotAttempts = array_filter($spamLog, function ($log) {
			return strpos($log['detection_type'] ?? '', 'honeypot_') === 0;
		});

		$stats = [
			'total_attempts'  => count($honeypotAttempts),
			'detection_types' => [],
			'recent_attempts' => 0,
		];

		$recentCutoff = time() - 86400; // Last 24 hours

		foreach ($honeypotAttempts as $attempt) {
			$type = $attempt['detection_type'] ?? 'unknown';
			$stats['detection_types'][$type] = ($stats['detection_types'][$type] ?? 0) + 1;

			if (($attempt['created_at'] ?? 0) > $recentCutoff) {
				$stats['recent_attempts']++;
			}
		}

		return $stats;
	}

	/**
	 * Check if honeypot is enabled
	 *
	 * Returns the current enabled status of the honeypot system
	 * based on configuration settings.
	 *
	 * @return bool True if honeypot is enabled, false otherwise
	 *
	 * Usage example:
	 * ```php
	 * $honeypot = new Honeypot();
	 * if ($honeypot->isEnabled()) {
	 *     echo $honeypot->initialize('my_form');
	 * } else {
	 *     echo "Honeypot protection is disabled";
	 * }
	 * ```
	 */
	public function isEnabled(): bool {
		return $this->enabled;
	}
}