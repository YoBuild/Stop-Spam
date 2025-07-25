<?php

namespace Yohns\AntiSpam;

use Yohns\Core\Config;
use Yohns\Security\FileStorage;

/**
 * Honeypot class for detecting automated bot submissions
 *
 * Uses hidden form fields and timing analysis to catch spam bots.
 */
class Honeypot {
	private FileStorage $storage;
	private bool        $enabled;
	private string      $fieldName;
	private int         $minTime;
	private int         $maxTime;
	private string      $sessionPrefix;

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
	 */
	public function getHiddenField(): string {
		if (!$this->enabled) {
			return '';
		}

		return '<input type="text" name="' . htmlspecialchars($this->fieldName) . '" value="" style="display:none !important; position:absolute; left:-9999px;" tabindex="-1" autocomplete="off">';
	}

	/**
	 * Get CSS to hide honeypot field
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
	 */
	public function isEnabled(): bool {
		return $this->enabled;
	}
}