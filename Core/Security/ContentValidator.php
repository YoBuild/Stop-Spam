<?php

namespace Yohns\Core\Security;

use Yohns\Core\Config;

/**
 * ContentValidator class for validating and sanitizing user input.
 *
 * This class provides methods for checking and cleaning user-submitted content
 * to prevent XSS, SQL injection, and other content-based attacks.
 *
 * Examples:
 * ```php
 * // Validate and sanitize a text input
 * $validator = new ContentValidator();
 * $cleanContent = $validator->sanitizeText($_POST['message']);
 *
 * // Validate an email address
 * if ($validator->isValidEmail($_POST['email'])) {
 *     // Email is valid
 * }
 *
 * // Check content for spam patterns
 * if ($validator->containsSpam($_POST['comment'])) {
 *     // Content might be spam
 * }
 * ```
 */
class ContentValidator {
	/**
	 * @var array List of spam keywords to check for
	 */
	private array $spamKeywords = [];

	/**
	 * @var array List of profanity words to filter
	 */
	private array $profanityList = [];

	/**
	 * @var array Regex patterns for common spam structures
	 */
	private array $spamPatterns = [];

	/**
	 * @var bool Whether to use the profanity filter
	 */
	private bool $useProfanityFilter = true;

	/**
	 * Constructor for ContentValidator.
	 * Loads configured spam keywords and patterns from config.
	 */
	public function __construct() {
		// Load spam keywords from config
		$this->spamKeywords = Config::get('spam_keywords', 'security') ?: [];

		// Load profanity list from config
		$this->profanityList = Config::get('profanity_list', 'security') ?: [];

		// Load spam patterns from config
		$this->spamPatterns = Config::get('spam_patterns', 'security') ?: [];

		// Set from config whether to use profanity filter
		$this->useProfanityFilter = Config::get('use_profanity_filter', 'security') ?? true;

		// Add default spam patterns if none are configured
		if (empty($this->spamPatterns)) {
			$this->spamPatterns = [
				// URLs with suspicious TLDs
				'/https?:\/\/.*\.(xyz|top|loan|work|click|gq|ml|ga|cf|tk)\b/i',
				// Too many URLs
				'/((https?:\/\/|www\.)[^\s<>"\']+){5,}/i',
				// Excessive use of keywords like "free", "discount", "offer"
				'/\b(free|discount|offer|buy|sell|promotion|deal|limited\s+time|special\s+offer)\b.*\1.*\1.*\1/i',
				// Hidden text using CSS tricks (style="display:none")
				'/style\s*=\s*["\'].*display\s*:\s*none/i'
			];
		}
	}

	/**
	 * Sanitize text input to prevent XSS attacks.
	 *
	 * @param string $text The text to sanitize
	 * @param bool $allowHtml Whether to allow some HTML tags
	 * @return string The sanitized text
	 */
	public function sanitizeText(string $text, bool $allowHtml = false): string {
		// Trim whitespace
		$text = trim($text);

		if ($allowHtml) {
			// Allow a subset of HTML tags, but encode everything else
			$allowedTags = '<p><br><b><i><strong><em><u><a><ul><ol><li><blockquote><h1><h2><h3><h4><h5><h6>';
			return strip_tags($text, $allowedTags);
		} else {
			// Encode all HTML tags
			return htmlspecialchars($text, ENT_QUOTES, 'UTF-8');
		}
	}

	/**
	 * Check if content contains potential spam.
	 *
	 * @param string $content The content to check
	 * @param float $threshold Spam threshold (0.0-1.0, higher = more strict)
	 * @return bool True if the content might be spam, false otherwise
	 */
	public function containsSpam(string $content, float $threshold = 0.5): bool {
		$spamScore = 0;
		$maxScore = 0;

		// Check for spam keywords
		foreach ($this->spamKeywords as $keyword) {
			$count = substr_count(strtolower($content), strtolower($keyword));
			if ($count > 0) {
				$spamScore += $count;
				$maxScore += $count;
			}
		}

		// Check for spam patterns
		foreach ($this->spamPatterns as $pattern) {
			if (preg_match($pattern, $content)) {
				$spamScore += 2; // Patterns are weighted more heavily
				$maxScore += 2;
			}
		}

		// Check for excessive capitalization
		if (strlen($content) > 20) {
			$upperCount = strlen(preg_replace('/[^A-Z]/', '', $content));
			$textLength = strlen(preg_replace('/[^a-zA-Z]/', '', $content));

			if ($textLength > 0 && $upperCount / $textLength > 0.6) {
				$spamScore += 1;
				$maxScore += 1;
			}
		}

		// Check for excessive exclamation points
		$exclamationCount = substr_count($content, '!');
		if ($exclamationCount > 3) {
			$spamScore += min($exclamationCount / 2, 3); // Cap at 3 points
			$maxScore += 3;
		}

		// Get final spam probability
		$spamProbability = $maxScore > 0 ? $spamScore / $maxScore : 0;

		return $spamProbability >= $threshold;
	}

	/**
	 * Check if an email address is valid.
	 *
	 * @param string $email The email address to validate
	 * @param bool $checkDns Whether to check DNS records for the domain
	 * @return bool True if the email is valid, false otherwise
	 */
	public function isValidEmail(string $email, bool $checkDns = false): bool {
		// Basic email validation
		if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
			return false;
		}

		// Extract the domain
		$domain = substr(strrchr($email, "@"), 1);

		// Check DNS records if requested
		if ($checkDns) {
			return checkdnsrr($domain, 'MX') || checkdnsrr($domain, 'A');
		}

		return true;
	}

	/**
	 * Filter profanity from text.
	 *
	 * @param string $text The text to filter
	 * @param string $replacement The replacement string (default: '****')
	 * @return string The filtered text
	 */
	public function filterProfanity(string $text, string $replacement = '****'): string {
		if (!$this->useProfanityFilter || empty($this->profanityList)) {
			return $text;
		}

		// Create a regex pattern for all profanity words
		$pattern = '/\b(' . implode('|', array_map('preg_quote', $this->profanityList)) . ')\b/i';

		// Replace profanity with the replacement string
		return preg_replace($pattern, $replacement, $text);
	}

	/**
	 * Check if text contains profanity.
	 *
	 * @param string $text The text to check
	 * @return bool True if the text contains profanity, false otherwise
	 */
	public function containsProfanity(string $text): bool {
		if (empty($this->profanityList)) {
			return false;
		}

		// Create a regex pattern for all profanity words
		$pattern = '/\b(' . implode('|', array_map('preg_quote', $this->profanityList)) . ')\b/i';

		// Check if the text contains any profanity
		return preg_match($pattern, $text) === 1;
	}

	/**
	 * Validate that a URL is safe.
	 *
	 * @param string $url The URL to validate
	 * @param array $allowedSchemes Allowed URL schemes (default: ['http', 'https'])
	 * @return bool True if the URL is safe, false otherwise
	 */
	public function isValidUrl(string $url, array $allowedSchemes = ['http', 'https']): bool {
		// Basic URL validation
		if (filter_var($url, FILTER_VALIDATE_URL) === false) {
			return false;
		}

		// Check that the scheme is allowed
		$parsedUrl = parse_url($url);
		if (!isset($parsedUrl['scheme']) || !in_array($parsedUrl['scheme'], $allowedSchemes)) {
			return false;
		}

		return true;
	}

	/**
	 * Add a keyword to the spam keyword list.
	 *
	 * @param string $keyword The keyword to add
	 * @return bool True if the keyword was added, false if it already exists
	 */
	public function addSpamKeyword(string $keyword): bool {
		$keyword = strtolower(trim($keyword));

		if (in_array($keyword, $this->spamKeywords)) {
			return false;
		}

		$this->spamKeywords[] = $keyword;

		// Update the config
		$this->saveSpamKeywords();

		return true;
	}

	/**
	 * Remove a keyword from the spam keyword list.
	 *
	 * @param string $keyword The keyword to remove
	 * @return bool True if the keyword was removed, false if it wasn't in the list
	 */
	public function removeSpamKeyword(string $keyword): bool {
		$keyword = strtolower(trim($keyword));

		$key = array_search($keyword, $this->spamKeywords);
		if ($key === false) {
			return false;
		}

		unset($this->spamKeywords[$key]);
		$this->spamKeywords = array_values($this->spamKeywords);

		// Update the config
		$this->saveSpamKeywords();

		return true;
	}

	/**
	 * Save the spam keywords to the configuration.
	 *
	 * @return void
	 */
	private function saveSpamKeywords(): void {
		// Use ConfigEditor to update the security config
		$securityConfig = [
			'spam_keywords' => $this->spamKeywords
		];

		// Add to config file
		\Yohns\Core\ConfigEditor::addToConfig($securityConfig, 'security');
	}

	/**
	 * Add a word to the profanity list.
	 *
	 * @param string $word The word to add
	 * @return bool True if the word was added, false if it already exists
	 */
	public function addProfanityWord(string $word): bool {
		$word = strtolower(trim($word));

		if (in_array($word, $this->profanityList)) {
			return false;
		}

		$this->profanityList[] = $word;

		// Update the config
		$this->saveProfanityList();

		return true;
	}

	/**
	 * Remove a word from the profanity list.
	 *
	 * @param string $word The word to remove
	 * @return bool True if the word was removed, false if it wasn't in the list
	 */
	public function removeProfanityWord(string $word): bool {
		$word = strtolower(trim($word));

		$key = array_search($word, $this->profanityList);
		if ($key === false) {
			return false;
		}

		unset($this->profanityList[$key]);
		$this->profanityList = array_values($this->profanityList);

		// Update the config
		$this->saveProfanityList();

		return true;
	}

	/**
	 * Save the profanity list to the configuration.
	 *
	 * @return void
	 */
	private function saveProfanityList(): void {
		// Use ConfigEditor to update the security config
		$securityConfig = [
			'profanity_list' => $this->profanityList
		];

		// Add to config file
		\Yohns\Core\ConfigEditor::addToConfig($securityConfig, 'security');
	}

	/**
	 * Add a regex pattern to the spam pattern list.
	 *
	 * @param string $pattern The regex pattern to add
	 * @return bool True if the pattern was added, false if it's invalid or already exists
	 */
	public function addSpamPattern(string $pattern): bool {
		// Validate the regex pattern
		if (@preg_match($pattern, '') === false) {
			return false;
		}

		if (in_array($pattern, $this->spamPatterns)) {
			return false;
		}

		$this->spamPatterns[] = $pattern;

		// Update the config
		$this->saveSpamPatterns();

		return true;
	}

	/**
	 * Remove a regex pattern from the spam pattern list.
	 *
	 * @param string $pattern The regex pattern to remove
	 * @return bool True if the pattern was removed, false if it wasn't in the list
	 */
	public function removeSpamPattern(string $pattern): bool {
		$key = array_search($pattern, $this->spamPatterns);
		if ($key === false) {
			return false;
		}

		unset($this->spamPatterns[$key]);
		$this->spamPatterns = array_values($this->spamPatterns);

		// Update the config
		$this->saveSpamPatterns();

		return true;
	}

	/**
	 * Save the spam patterns to the configuration.
	 *
	 * @return void
	 */
	private function saveSpamPatterns(): void {
		// Use ConfigEditor to update the security config
		$securityConfig = [
			'spam_patterns' => $this->spamPatterns
		];

		// Add to config file
		\Yohns\Core\ConfigEditor::addToConfig($securityConfig, 'security');
	}
}