<?php

namespace Yohns\Security;

use Yohns\Core\Config;

/**
 * SpamDetector class for detecting and preventing spam submissions.
 *
 * This class combines multiple spam detection techniques including
 * honeypot fields, timing analysis, and JavaScript-based bot detection.
 *
 * Examples:
 * ```php
 * // Initialize the spam detector
 * $detector = new SpamDetector();
 *
 * // Add protection to a form
 * echo $detector->protectForm('registration');
 *
 * // Validate a form submission
 * if ($detector->validateRequest($_POST, 'registration')) {
 *     // Process the form
 * } else {
 *     // Reject the submission
 * }
 * ```
 */
class SpamDetector {
	/**
	 * @var array Default configuration options
	 */
	private array $config = [
		'use_honeypot' => true,
		'use_timing' => true,
		'use_csrf' => true,
		'use_challenge' => false,
		'log_detections' => true,
		'min_time' => 2,
		'max_time' => 3600
	];

	/**
	 * @var string Log file path for spam detections
	 */
	private string $logFile;

	/**
	 * Create a new SpamDetector instance.
	 *
	 * @param array $options Configuration options
	 */
	public function __construct(array $options = []) {
		// Initialize dependencies
		CSRFToken::init();
		Honeypot::init();

		// Merge options with defaults
		$this->config = array_merge($this->config, $options);

		// Set log file path
		$this->logFile = $options['log_file'] ?? __DIR__ . '/../../logs/spam_detection.log';
	}

	/**
	 * Add security measures to a form.
	 *
	 * @param string $formId Unique identifier for the form
	 * @return string HTML fields to add to the form
	 */
	public function protectForm(string $formId): string {
		$output = '';

		// Add CSRF protection
		if ($this->config['use_csrf']) {
			$output .= CSRFToken::tokenField($formId);
		}

		// Add honeypot field
		if ($this->config['use_honeypot']) {
			$output .= Honeypot::field();
		}

		// Add timing analysis
		if ($this->config['use_timing']) {
			$output .= Honeypot::startTiming($formId);
		}

		// Add challenge question if enabled
		if ($this->config['use_challenge']) {
			$challenge = Honeypot::challengeQuestion();
			$output .= '<div class="form-group challenge-question">';
			$output .= '<label for="challenge_response">' . htmlspecialchars($challenge['question']) . '</label>';
			$output .= '<input type="text" name="challenge_response" id="challenge_response" class="form-control" required>';
			$output .= '<input type="hidden" name="challenge_question" value="' . htmlspecialchars($challenge['question']) . '">';
			$output .= '</div>';
		}

		// Add JavaScript protection
		$output .= $this->getJavaScriptProtection($formId);

		return $output;
	}

	/**
	 * Validate a form submission.
	 *
	 * @param array $data Form data to validate
	 * @param string $formId Unique identifier for the form
	 * @return bool True if the submission passes all checks
	 */
	public function validateRequest(array $data, string $formId): bool {
		$valid = true;
		$failedChecks = [];

		// Validate CSRF token
		if ($this->config['use_csrf']) {
			$token = $data['csrf_token'] ?? '';
			if (!CSRFToken::validate($token, $formId)) {
				$valid = false;
				$failedChecks[] = 'csrf';
			}
		}

		// Validate honeypot field
		if ($this->config['use_honeypot'] && !Honeypot::validate($data)) {
			$valid = false;
			$failedChecks[] = 'honeypot';
		}

		// Validate timing
		if ($this->config['use_timing'] && !Honeypot::validateTiming($data, $formId)) {
			$valid = false;
			$failedChecks[] = 'timing';
		}

		// Validate challenge question
		if ($this->config['use_challenge'] &&
			isset($data['challenge_response'], $data['challenge_question'])) {

			if (!Honeypot::validateChallenge(
				$data['challenge_response'],
				$data['challenge_question']
			)) {
				$valid = false;
				$failedChecks[] = 'challenge';
			}
		}

		// Check JavaScript token
		if (isset($data['js_token'])) {
			if ($data['js_token'] !== $this->calculateExpectedJsToken($formId)) {
				$valid = false;
				$failedChecks[] = 'js_token';
			}
		} else {
			// No JavaScript token - might be a bot or JavaScript is disabled
			$failedChecks[] = 'js_token_missing';
		}

		// Log failed attempts
		if (!$valid && $this->config['log_detections']) {
			$this->logSpamDetection($failedChecks, $data);
		}

		return $valid;
	}

	/**
	 * Generate JavaScript protection code for a form.
	 *
	 * @param string $formId Unique identifier for the form
	 * @return string HTML script tag with JavaScript protection
	 */
	private function getJavaScriptProtection(string $formId): string {
		// Generate a unique token for this form
		$expectedToken = $this->calculateExpectedJsToken($formId);

		// JavaScript to validate form before submission
		return <<<HTML
		<input type="hidden" name="js_token" id="js_token" value="">
		<script>
		(function() {
			// Set token on page load
			document.getElementById('js_token').value = '$expectedToken';

			// Check for common bot behaviors
			let botDetected = false;

			// Function to detect if user is browsing with JavaScript
			function detectJS() {
				return true;
			}

			// Check if the user interacts with the page
			let hasInteracted = false;
			const interactionEvents = ['mousemove', 'click', 'scroll', 'keydown'];

			interactionEvents.forEach(function(event) {
				document.addEventListener(event, function() {
					hasInteracted = true;
				}, {once: true});
			});

			// Find all forms that may have our protection
			document.addEventListener('DOMContentLoaded', function() {
				const forms = document.querySelectorAll('form');

				forms.forEach(function(form) {
					if (form.querySelector('[name="js_token"]')) {
						form.addEventListener('submit', function(e) {
							// Prevent submission if bot behavior detected
							if (botDetected) {
								e.preventDefault();
								console.log('Form submission blocked due to suspicious behavior');
								return false;
							}

							// Check for user interaction before submission
							if (!hasInteracted) {
								e.preventDefault();
								console.log('Form submission blocked due to lack of user interaction');
								return false;
							}

							// Verify CSRF token exists
							const csrfToken = form.querySelector('[name="csrf_token"]');
							if (!csrfToken || !csrfToken.value) {
								e.preventDefault();
								console.log('Form submission blocked due to missing CSRF token');
								return false;
							}

							return true;
						});
					}
				});
			});

			// Additional bot detection techniques

			// Check for automation frameworks
			if (window.navigator.webdriver ||
				window.callPhantom ||
				window._phantom ||
				window.__nightmare ||
				window.Buffer ||
				window.emit ||
				window.spawn) {
				botDetected = true;
			}

			// Check for headless browser
			if (/HeadlessChrome/.test(window.navigator.userAgent)) {
				botDetected = true;
			}

			// Check plugins length (most bots have 0)
			if (navigator.plugins.length === 0 && !navigator.mimeTypes.length) {
				// This might be a bot, but also might be a privacy-focused browser
				// So we don't set botDetected = true immediately
			}
		})();
		</script>
		HTML;
	}

	/**
	 * Calculate the expected JavaScript token value for a form.
	 *
	 * @param string $formId Unique identifier for the form
	 * @return string The expected token
	 */
	private function calculateExpectedJsToken(string $formId): string {
		// Use the form ID, user agent, and a secret to generate the token
		$userAgent = $_SERVER['HTTP_USER_AGENT'] ?? '';
		$secret = Config::get('js_token_secret', 'security') ?? 'default-security-secret';

		return hash('sha256', $formId . $userAgent . $secret);
	}

	/**
	 * Log a spam detection event.
	 *
	 * @param array $failedChecks List of checks that failed
	 * @param array $data Form data
	 * @return void
	 */
	private function logSpamDetection(array $failedChecks, array $data): void {
		// Ensure log directory exists
		$logDir = dirname($this->logFile);
		if (!is_dir($logDir)) {
			mkdir($logDir, 0755, true);
		}

		// Prepare log entry
		$logEntry = [
			'timestamp' => date('Y-m-d H:i:s'),
			'ip' => $_SERVER['REMOTE_ADDR'] ?? 'unknown',
			'user_agent' => $_SERVER['HTTP_USER_AGENT'] ?? 'unknown',
			'failed_checks' => implode(', ', $failedChecks),
			'request_data' => $this->sanitizeDataForLogging($data)
		];

		// Convert to string
		$logString = json_encode($logEntry) . PHP_EOL;

		// Append to log file
		file_put_contents($this->logFile, $logString, FILE_APPEND);
	}

	/**
	 * Sanitize form data for logging to remove sensitive information.
	 *
	 * @param array $data Form data
	 * @return array Sanitized data
	 */
	private function sanitizeDataForLogging(array $data): array {
		// List of fields that may contain sensitive information
		$sensitiveFields = [
			'password', 'pass', 'pwd', 'secret', 'token', 'api_key', 'credit_card',
			'card_number', 'cvv', 'ssn', 'social_security', 'auth', 'authorization'
		];

		$sanitized = [];

		foreach ($data as $key => $value) {
			// Check if field name contains any sensitive keywords
			$isSensitive = false;
			foreach ($sensitiveFields as $field) {
				if (stripos($key, $field) !== false) {
					$isSensitive = true;
					break;
				}
			}

			// Replace sensitive values with a placeholder
			if ($isSensitive) {
				$sanitized[$key] = '[REDACTED]';
			} else {
				// Truncate long values
				if (is_string($value) && strlen($value) > 100) {
					$sanitized[$key] = substr($value, 0, 100) . '...';
				} else {
					$sanitized[$key] = $value;
				}
			}
		}

		return $sanitized;
	}
}