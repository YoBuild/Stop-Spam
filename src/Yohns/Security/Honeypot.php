<?php

namespace Yohns\Security;

use Yohns\Core\Config;

/**
 * Honeypot class for detecting and preventing automated form submissions.
 *
 * This class provides methods for adding and validating honeypot fields to forms,
 * as well as timing analysis to detect bot submissions.
 *
 * Examples:
 * ```php
 * // Add honeypot field to a form
 * echo Honeypot::field();
 *
 * // Validate a form submission
 * if (Honeypot::validate($_POST)) {
 *     // Process the form
 * } else {
 *     // Reject the submission
 * }
 *
 * // Start timing analysis for a form
 * echo Honeypot::startTiming('registration_form');
 *
 * // Validate timing when form is submitted
 * if (Honeypot::validateTiming($_POST)) {
 *     // Process the form
 * }
 * ```
 */
class Honeypot {
	/**
	 * @var string Session key prefix for storing timing data
	 */
	private static string $sessionPrefix = 'honeypot_';

	/**
	 * @var string Default honeypot field name
	 */
	private static string $fieldName = 'website';

	/**
	 * @var int Minimum time (in seconds) a form should take to complete
	 */
	private static int $minTime = 2;

	/**
	 * @var int Maximum time (in seconds) a form should be valid for
	 */
	private static int $maxTime = 3600; // 1 hour

	/**
	 * Initialize the honeypot system.
	 *
	 * @param string|null $configFile Optional configuration file to load settings from
	 * @return void
	 */
	public static function init(?string $configFile = null): void {
		if (session_status() === PHP_SESSION_NONE) {
			session_start();
		}

		// Load configuration if provided
		if ($configFile !== null) {
			$fieldName = Config::get('honeypot_field_name', $configFile);
			if ($fieldName !== null && is_string($fieldName)) {
				self::$fieldName = $fieldName;
			}

			$minTime = Config::get('honeypot_min_time', $configFile);
			if ($minTime !== null && is_numeric($minTime)) {
				self::$minTime = (int)$minTime;
			}

			$maxTime = Config::get('honeypot_max_time', $configFile);
			if ($maxTime !== null && is_numeric($maxTime)) {
				self::$maxTime = (int)$maxTime;
			}

			$prefix = Config::get('honeypot_session_prefix', $configFile);
			if ($prefix !== null && is_string($prefix)) {
				self::$sessionPrefix = $prefix;
			}
		}
	}

	/**
	 * Generate a hidden honeypot field for a form.
	 *
	 * @param string|null $fieldName Custom field name (optional)
	 * @return string HTML for the honeypot field
	 */
	public static function field(?string $fieldName = null): string {
		$name = $fieldName ?? self::$fieldName;

		return <<<HTML
		<div style="display:none !important;">
			<label for="$name">$name</label>
			<input type="text" name="$name" id="$name" autocomplete="off">
		</div>
		HTML;
	}

	/**
	 * Validate a form submission against honeypot traps.
	 *
	 * @param array $data Form data to validate
	 * @param string|null $fieldName Custom field name (optional)
	 * @return bool True if the submission passes validation
	 */
	public static function validate(array $data, ?string $fieldName = null): bool {
		$name = $fieldName ?? self::$fieldName;

		// If the honeypot field is not empty, it's likely a bot
		return !isset($data[$name]) || empty($data[$name]);
	}

	/**
	 * Start timing analysis for a form.
	 *
	 * @param string $formId Unique identifier for the form
	 * @return string HTML for the timing field
	 */
	public static function startTiming(string $formId): string {
		$timestamp = time();
		$token = bin2hex(random_bytes(16)); // 32 character random token

		// Store timing data in session
		$_SESSION[self::$sessionPrefix . $formId] = [
			'token' => $token,
			'timestamp' => $timestamp
		];

		return sprintf(
			'<input type="hidden" name="timing_token" value="%s">',
			htmlspecialchars($token, ENT_QUOTES, 'UTF-8')
		);
	}

	/**
	 * Validate the timing of a form submission.
	 *
	 * @param array $data Form data to validate
	 * @param string $formId Unique identifier for the form
	 * @return bool True if the timing passes validation
	 */
	public static function validateTiming(array $data, string $formId): bool {
		if (!isset($data['timing_token'])) {
			return false;
		}

		$sessionKey = self::$sessionPrefix . $formId;

		// Check if timing data exists in session
		if (!isset($_SESSION[$sessionKey]) ||
			!isset($_SESSION[$sessionKey]['token']) ||
			!isset($_SESSION[$sessionKey]['timestamp'])) {
			return false;
		}

		$storedToken = $_SESSION[$sessionKey]['token'];
		$startTimestamp = $_SESSION[$sessionKey]['timestamp'];
		$currentTimestamp = time();
		$elapsedTime = $currentTimestamp - $startTimestamp;

		// Clean up session data
		unset($_SESSION[$sessionKey]);

		// Validate token
		if (!hash_equals($storedToken, $data['timing_token'])) {
			return false;
		}

		// Check if the form was submitted too quickly (likely a bot)
		if ($elapsedTime < self::$minTime) {
			return false;
		}

		// Check if the form has expired
		if ($elapsedTime > self::$maxTime) {
			return false;
		}

		return true;
	}

	/**
	 * Get a random question with a simple answer to confuse bots.
	 *
	 * @return array Array with 'question' and 'answer' keys
	 */
	public static function challengeQuestion(): array {
		$challenges = [
			['question' => 'What is two plus three?', 'answer' => '5'],
			['question' => 'Type the word "human" below:', 'answer' => 'human'],
			['question' => 'What is the color of the sky on a clear day?', 'answer' => 'blue'],
			['question' => 'Type the third letter of the alphabet:', 'answer' => 'c'],
			['question' => 'What is the name of our planet?', 'answer' => 'earth']
		];

		// Select a random challenge
		$challenge = $challenges[array_rand($challenges)];

		// Store the expected answer in session
		$key = 'honeypot_challenge_' . md5($challenge['question']);
		$_SESSION[$key] = $challenge['answer'];

		return ['question' => $challenge['question'], 'input_name' => 'challenge_response'];
	}

	/**
	 * Validate a challenge response.
	 *
	 * @param string $response User's response to the challenge
	 * @param string $question The question that was asked
	 * @return bool True if the response is correct
	 */
	public static function validateChallenge(string $response, string $question): bool {
		$key = 'honeypot_challenge_' . md5($question);

		if (!isset($_SESSION[$key])) {
			return false;
		}

		$expectedAnswer = $_SESSION[$key];

		// Clean up session data
		unset($_SESSION[$key]);

		// Case-insensitive comparison for user convenience
		return strtolower(trim($response)) === strtolower($expectedAnswer);
	}
}