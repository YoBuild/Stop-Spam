<?php

namespace Yohns\AntiSpam;

use Yohns\Core\Config;
use Yohns\Security\FileStorage;

/**
 * SpamDetector class for comprehensive content spam detection
 *
 * Analyzes content for spam patterns, keywords, and suspicious behavior.
 * Uses machine learning-style scoring to determine spam likelihood.
 *
 * @package Yohns\AntiSpam
 * @version 1.0.0
 * @author  Yohns Framework
 *
 * Usage example:
 * ```php
 * $detector = new SpamDetector();
 * $result = $detector->analyzeContent("Buy cheap viagra now!!!");
 * if ($result['is_spam']) {
 *     echo "Spam detected with score: " . $result['spam_score'];
 *     echo "Reasons: " . implode(', ', $result['reasons']);
 * }
 * ```
 */
class SpamDetector {
	private FileStorage $storage;
	private bool        $enabled;
	private array       $spamKeywords;
	private array       $profanityList;
	private int         $maxLinks;
	private int         $maxCapitalsPercent;
	private int         $maxRepeatedChars;

	/**
	 * Constructor - Initialize spam detector with configuration
	 *
	 * Loads configuration settings and initializes spam keywords and profanity lists
	 * from storage or creates default lists if none exist.
	 *
	 * @throws \Exception If FileStorage initialization fails
	 *
	 * Usage example:
	 * ```php
	 * $detector = new SpamDetector();
	 * // Detector is now ready to analyze content
	 * ```
	 */
	public function __construct() {
		$this->storage = new FileStorage();
		$this->enabled = Config::get('spam_detection.enabled', 'security') ?? true;
		$this->maxLinks = Config::get('spam_detection.max_links', 'security') ?: 3;
		$this->maxCapitalsPercent = Config::get('spam_detection.max_capitals_percent', 'security') ?: 70;
		$this->maxRepeatedChars = Config::get('spam_detection.max_repeated_chars', 'security') ?: 5;

		$this->loadSpamKeywords();
		$this->loadProfanityList();
	}

	/**
	 * Analyze content for spam indicators
	 *
	 * Performs comprehensive analysis including keyword detection, profanity check,
	 * link counting, capital letter analysis, and pattern recognition.
	 * Returns a detailed analysis with spam score and reasons.
	 *
	 * @param string $content Content to analyze for spam
	 * @return array Analysis result with 'is_spam', 'spam_score', 'reasons', 'severity' keys
	 *
	 * Usage example:
	 * ```php
	 * $detector = new SpamDetector();
	 * $result = $detector->analyzeContent("CLICK HERE FOR FREE MONEY!!!");
	 *
	 * if ($result['is_spam']) {
	 *     echo "Spam detected! Score: " . $result['spam_score'];
	 *     echo "Severity: " . $result['severity'];
	 *     foreach ($result['reasons'] as $reason) {
	 *         echo "- " . $reason . "\n";
	 *     }
	 * }
	 * ```
	 */
	public function analyzeContent(string $content): array {
		$result = [
			'is_spam'    => false,
			'spam_score' => 0.0,
			'reasons'    => [],
			'severity'   => 'low',
		];

		if (!$this->enabled || empty(trim($content))) {
			return $result;
		}

		$score = 0.0;
		$reasons = [];

		// Check spam keywords
		$keywordScore = $this->checkSpamKeywords($content);
		if ($keywordScore > 0) {
			$score += $keywordScore;
			$reasons[] = 'Contains spam keywords';
		}

		// Check profanity
		$profanityScore = $this->checkProfanity($content);
		if ($profanityScore > 0) {
			$score += $profanityScore;
			$reasons[] = 'Contains profanity';
		}

		// Check excessive links
		$linkScore = $this->checkExcessiveLinks($content);
		if ($linkScore > 0) {
			$score += $linkScore;
			$reasons[] = 'Too many links';
		}

		// Check excessive capitals
		$capitalScore = $this->checkExcessiveCapitals($content);
		if ($capitalScore > 0) {
			$score += $capitalScore;
			$reasons[] = 'Excessive capital letters';
		}

		// Check repeated characters
		$repeatScore = $this->checkRepeatedCharacters($content);
		if ($repeatScore > 0) {
			$score += $repeatScore;
			$reasons[] = 'Excessive repeated characters';
		}

		// Check suspicious patterns
		$patternScore = $this->checkSuspiciousPatterns($content);
		if ($patternScore > 0) {
			$score += $patternScore;
			$reasons[] = 'Suspicious patterns detected';
		}

		// Determine if content is spam
		$result['spam_score'] = round($score, 2);
		$result['reasons'] = $reasons;

		if ($score >= 0.8) {
			$result['is_spam'] = true;
			$result['severity'] = 'high';
		} elseif ($score >= 0.5) {
			$result['is_spam'] = true;
			$result['severity'] = 'medium';
		} elseif ($score >= 0.3) {
			$result['severity'] = 'low';
		}

		// Log if spam detected
		if ($result['is_spam']) {
			$this->logSpamDetection($content, $result);
		}

		return $result;
	}

	/**
	 * Check for spam keywords
	 *
	 * Searches content for known spam keywords and calculates a score
	 * based on the number of matches. Score is capped at 0.6.
	 *
	 * @param string $content Content to check for spam keywords
	 * @return float Spam score from keyword matches (0.0 to 0.6)
	 *
	 * Usage example:
	 * ```php
	 * $score = $this->checkSpamKeywords("Buy viagra now!");
	 * // Returns score based on spam keywords found
	 * ```
	 */
	private function checkSpamKeywords(string $content): float {
		$content = strtolower($content);
		$score = 0.0;
		$foundKeywords = [];

		foreach ($this->spamKeywords as $keyword) {
			if (strpos($content, strtolower($keyword)) !== false) {
				$foundKeywords[] = $keyword;
				$score += 0.2; // Each keyword adds to score
			}
		}

		// Cap the score from keywords
		return min($score, 0.6);
	}

	/**
	 * Check for profanity
	 *
	 * Searches content for profanity words and calculates a score
	 * based on the number of matches. Score is capped at 0.4.
	 *
	 * @param string $content Content to check for profanity
	 * @return float Profanity score (0.0 to 0.4)
	 *
	 * Usage example:
	 * ```php
	 * $score = $this->checkProfanity("This is damn stupid content");
	 * // Returns score based on profanity words found
	 * ```
	 */
	private function checkProfanity(string $content): float {
		$content = strtolower($content);
		$score = 0.0;

		foreach ($this->profanityList as $word) {
			if (strpos($content, strtolower($word)) !== false) {
				$score += 0.15;
			}
		}

		return min($score, 0.4);
	}

	/**
	 * Check for excessive links
	 *
	 * Counts HTTP/HTTPS links in content and returns a score if the count
	 * exceeds the maximum allowed links threshold.
	 *
	 * @param string $content Content to check for links
	 * @return float Link spam score (0.0 to 0.5)
	 *
	 * Usage example:
	 * ```php
	 * $score = $this->checkExcessiveLinks("Check http://spam.com and https://more-spam.com");
	 * // Returns score if too many links found
	 * ```
	 */
	private function checkExcessiveLinks(string $content): float {
		$linkCount = preg_match_all('/https?:\/\/[^\s]+/i', $content);

		if ($linkCount > $this->maxLinks) {
			return min(($linkCount - $this->maxLinks) * 0.2, 0.5);
		}

		return 0.0;
	}

	/**
	 * Check for excessive capital letters
	 *
	 * Calculates the percentage of capital letters in alphabetic content
	 * and returns a score if it exceeds the maximum threshold.
	 *
	 * @param string $content Content to check for excessive capitals
	 * @return float Capital letters spam score (0.0 to 0.4)
	 *
	 * Usage example:
	 * ```php
	 * $score = $this->checkExcessiveCapitals("THIS IS ALL CAPS SPAM!!!");
	 * // Returns score if too many capitals found
	 * ```
	 */
	private function checkExcessiveCapitals(string $content): float {
		$totalChars = strlen(preg_replace('/[^a-zA-Z]/', '', $content));
		$capitalChars = strlen(preg_replace('/[^A-Z]/', '', $content));

		if ($totalChars === 0) {
			return 0.0;
		}

		$capitalPercent = ($capitalChars / $totalChars) * 100;

		if ($capitalPercent > $this->maxCapitalsPercent) {
			return min(($capitalPercent - $this->maxCapitalsPercent) / 100, 0.4);
		}

		return 0.0;
	}

	/**
	 * Check for excessive repeated characters
	 *
	 * Detects patterns of repeated characters that exceed the maximum threshold
	 * and calculates a spam score based on the number of occurrences.
	 *
	 * @param string $content Content to check for repeated characters
	 * @return float Repeated characters spam score (0.0 to 0.3)
	 *
	 * Usage example:
	 * ```php
	 * $score = $this->checkRepeatedCharacters("Hellooooooo!!!!!!");
	 * // Returns score if excessive repeated characters found
	 * ```
	 */
	private function checkRepeatedCharacters(string $content): float {
		$pattern = '/(.)\1{' . ($this->maxRepeatedChars - 1) . ',}/';
		$matches = preg_match_all($pattern, $content);

		if ($matches > 0) {
			return min($matches * 0.1, 0.3);
		}

		return 0.0;
	}

	/**
	 * Check for suspicious patterns
	 *
	 * Analyzes content for various suspicious patterns including common spam phrases,
	 * excessive punctuation, and non-ASCII characters. Returns a combined score.
	 *
	 * @param string $content Content to check for suspicious patterns
	 * @return float Suspicious patterns spam score (0.0 to 0.4)
	 *
	 * Usage example:
	 * ```php
	 * $score = $this->checkSuspiciousPatterns("Click here!!! Buy now!!!");
	 * // Returns score based on suspicious patterns found
	 * ```
	 */
	private function checkSuspiciousPatterns(string $content): float {
		$score = 0.0;

		// Check for common spam phrases
		$spamPhrases = [
			'click here', 'buy now', 'limited time', 'act now',
			'free money', 'make money fast', 'work from home',
			'weight loss', 'lose weight fast', 'miracle cure',
		];

		$content_lower = strtolower($content);
		foreach ($spamPhrases as $phrase) {
			if (strpos($content_lower, $phrase) !== false) {
				$score += 0.15;
			}
		}

		// Check for excessive punctuation
		$punctuationCount = preg_match_all('/[!?]{2,}/', $content);
		if ($punctuationCount > 0) {
			$score += $punctuationCount * 0.1;
		}

		// Check for suspicious character patterns
		if (preg_match('/[^\x00-\x7F]/', $content)) {
			// Contains non-ASCII characters (could be spam in other languages)
			$score += 0.1;
		}

		return min($score, 0.4);
	}

	/**
	 * Load spam keywords from storage
	 *
	 * Retrieves spam keywords from file storage or creates default list
	 * if none exists. Automatically saves default keywords to storage.
	 *
	 * @return void
	 *
	 * Usage example:
	 * ```php
	 * $this->loadSpamKeywords();
	 * // Spam keywords are now loaded and ready for use
	 * ```
	 */
	private function loadSpamKeywords(): void {
		$keywords = $this->storage->findOne('spam_keywords', ['active' => true]);

		if ($keywords && isset($keywords['keywords'])) {
			$this->spamKeywords = $keywords['keywords'];
		} else {
			// Default spam keywords
			$this->spamKeywords = [
				'viagra', 'cialis', 'buy now', 'click here', 'free money',
				'work from home', 'make money fast', 'lose weight fast',
				'miracle cure', 'limited time offer', 'act now', 'discount',
				'casino', 'poker', 'gambling', 'lottery', 'winner',
				'congratulations', 'prize', 'inheritance', 'urgent',
				'cheap', 'deal', 'offer expires', 'risk free',
			];

			// Save default keywords to storage
			$this->storage->insert('spam_keywords', [
				'keywords'    => $this->spamKeywords,
				'active'      => true,
				'description' => 'Default spam keywords',
			]);
		}
	}

	/**
	 * Load profanity list from storage
	 *
	 * Retrieves profanity words from file storage or creates default list
	 * if none exists. Automatically saves default list to storage.
	 *
	 * @return void
	 *
	 * Usage example:
	 * ```php
	 * $this->loadProfanityList();
	 * // Profanity list is now loaded and ready for filtering
	 * ```
	 */
	private function loadProfanityList(): void {
		$profanity = $this->storage->findOne('profanity_list', ['active' => true]);

		if ($profanity && isset($profanity['words'])) {
			$this->profanityList = $profanity['words'];
		} else {
			// Default profanity list (basic examples)
			$this->profanityList = [
				'damn', 'hell', 'crap', 'stupid', 'idiot',
			];

			// Save default list to storage
			$this->storage->insert('profanity_list', [
				'words'       => $this->profanityList,
				'active'      => true,
				'description' => 'Default profanity filter',
			]);
		}
	}

	/**
	 * Add spam keyword
	 *
	 * Adds a new keyword to the spam detection list if it doesn't already exist.
	 * Updates the storage with the new keyword list.
	 *
	 * @param string $keyword Keyword to add to spam detection list
	 * @return bool True if keyword was added, false if it already exists
	 *
	 * Usage example:
	 * ```php
	 * $detector = new SpamDetector();
	 * if ($detector->addSpamKeyword('new spam word')) {
	 *     echo "Keyword added successfully";
	 * } else {
	 *     echo "Keyword already exists";
	 * }
	 * ```
	 */
	public function addSpamKeyword(string $keyword): bool {
		$keyword = strtolower(trim($keyword));

		if (in_array($keyword, $this->spamKeywords)) {
			return false;
		}

		$this->spamKeywords[] = $keyword;
		$this->updateSpamKeywords();
		return true;
	}

	/**
	 * Remove spam keyword
	 *
	 * Removes a keyword from the spam detection list if it exists.
	 * Updates the storage with the modified keyword list.
	 *
	 * @param string $keyword Keyword to remove from spam detection list
	 * @return bool True if keyword was removed, false if it doesn't exist
	 *
	 * Usage example:
	 * ```php
	 * $detector = new SpamDetector();
	 * if ($detector->removeSpamKeyword('old keyword')) {
	 *     echo "Keyword removed successfully";
	 * } else {
	 *     echo "Keyword not found";
	 * }
	 * ```
	 */
	public function removeSpamKeyword(string $keyword): bool {
		$keyword = strtolower(trim($keyword));
		$key = array_search($keyword, $this->spamKeywords);

		if ($key === false) {
			return false;
		}

		unset($this->spamKeywords[$key]);
		$this->spamKeywords = array_values($this->spamKeywords);
		$this->updateSpamKeywords();
		return true;
	}

	/**
	 * Update spam keywords in storage
	 *
	 * Saves the current spam keywords list to file storage, either updating
	 * existing record or creating a new one if none exists.
	 *
	 * @return void
	 *
	 * Usage example:
	 * ```php
	 * $this->updateSpamKeywords();
	 * // Spam keywords are now saved to storage
	 * ```
	 */
	private function updateSpamKeywords(): void {
		$existing = $this->storage->findOne('spam_keywords', ['active' => true]);

		if ($existing) {
			$this->storage->update('spam_keywords', $existing['id'], [
				'keywords' => $this->spamKeywords,
			]);
		} else {
			$this->storage->insert('spam_keywords', [
				'keywords'    => $this->spamKeywords,
				'active'      => true,
				'description' => 'Updated spam keywords',
			]);
		}
	}

	/**
	 * Add profanity word
	 *
	 * Adds a new word to the profanity filter list if it doesn't already exist.
	 * Updates the storage with the new profanity list.
	 *
	 * @param string $word Word to add to profanity filter
	 * @return bool True if word was added, false if it already exists
	 *
	 * Usage example:
	 * ```php
	 * $detector = new SpamDetector();
	 * if ($detector->addProfanityWord('badword')) {
	 *     echo "Profanity word added successfully";
	 * } else {
	 *     echo "Word already in profanity list";
	 * }
	 * ```
	 */
	public function addProfanityWord(string $word): bool {
		$word = strtolower(trim($word));

		if (in_array($word, $this->profanityList)) {
			return false;
		}

		$this->profanityList[] = $word;
		$this->updateProfanityList();
		return true;
	}

	/**
	 * Remove profanity word
	 *
	 * Removes a word from the profanity filter list if it exists.
	 * Updates the storage with the modified profanity list.
	 *
	 * @param string $word Word to remove from profanity filter
	 * @return bool True if word was removed, false if it doesn't exist
	 *
	 * Usage example:
	 * ```php
	 * $detector = new SpamDetector();
	 * if ($detector->removeProfanityWord('oldword')) {
	 *     echo "Profanity word removed successfully";
	 * } else {
	 *     echo "Word not found in profanity list";
	 * }
	 * ```
	 */
	public function removeProfanityWord(string $word): bool {
		$word = strtolower(trim($word));
		$key = array_search($word, $this->profanityList);

		if ($key === false) {
			return false;
		}

		unset($this->profanityList[$key]);
		$this->profanityList = array_values($this->profanityList);
		$this->updateProfanityList();
		return true;
	}

	/**
	 * Update profanity list in storage
	 *
	 * Saves the current profanity list to file storage, either updating
	 * existing record or creating a new one if none exists.
	 *
	 * @return void
	 *
	 * Usage example:
	 * ```php
	 * $this->updateProfanityList();
	 * // Profanity list is now saved to storage
	 * ```
	 */
	private function updateProfanityList(): void {
		$existing = $this->storage->findOne('profanity_list', ['active' => true]);

		if ($existing) {
			$this->storage->update('profanity_list', $existing['id'], [
				'words' => $this->profanityList,
			]);
		} else {
			$this->storage->insert('profanity_list', [
				'words'       => $this->profanityList,
				'active'      => true,
				'description' => 'Updated profanity list',
			]);
		}
	}

	/**
	 * Clean content by removing spam and profanity
	 *
	 * Sanitizes content by replacing profanity with asterisks, reducing
	 * excessive punctuation, and normalizing repeated characters and whitespace.
	 *
	 * @param string $content Content to clean and sanitize
	 * @return string Cleaned content with profanity and spam patterns removed
	 *
	 * Usage example:
	 * ```php
	 * $detector = new SpamDetector();
	 * $cleaned = $detector->cleanContent("This is damn stupid!!!! content");
	 * echo $cleaned; // Outputs: "This is **** stupid!!! content"
	 * ```
	 */
	public function cleanContent(string $content): string {
		$cleaned = $content;

		// Remove or replace profanity
		foreach ($this->profanityList as $word) {
			$pattern = '/\b' . preg_quote($word, '/') . '\b/i';
			$cleaned = preg_replace($pattern, str_repeat('*', strlen($word)), $cleaned);
		}

		// Remove excessive punctuation
		$cleaned = preg_replace('/[!?]{3,}/', '!!!', $cleaned);
		$cleaned = preg_replace('/\.{4,}/', '...', $cleaned);

		// Remove excessive repeated characters
		$cleaned = preg_replace('/(.)\1{4,}/', '$1$1$1', $cleaned);

		// Remove excessive whitespace
		$cleaned = preg_replace('/\s+/', ' ', $cleaned);

		return trim($cleaned);
	}

	/**
	 * Check if content should be auto-blocked
	 *
	 * Determines if content should be automatically blocked based on
	 * spam analysis. Content is auto-blocked if spam score is 0.8 or higher.
	 *
	 * @param string $content Content to check for auto-blocking
	 * @return bool True if content should be auto-blocked, false otherwise
	 *
	 * Usage example:
	 * ```php
	 * $detector = new SpamDetector();
	 * if ($detector->shouldAutoBlock("Buy cheap viagra now!!!")) {
	 *     // Block this content automatically
	 *     die("Content blocked for spam");
	 * }
	 * ```
	 */
	public function shouldAutoBlock(string $content): bool {
		$analysis = $this->analyzeContent($content);
		return $analysis['is_spam'] && $analysis['spam_score'] >= 0.8;
	}

	/**
	 * Log spam detection
	 *
	 * Records spam detection events to the spam log with detailed information
	 * including content sample, analysis results, and user context.
	 *
	 * @param string $content  Original content that was analyzed
	 * @param array  $analysis Analysis result from spam detection
	 * @return void
	 *
	 * Usage example:
	 * ```php
	 * $this->logSpamDetection($content, [
	 *     'is_spam' => true,
	 *     'spam_score' => 0.85,
	 *     'reasons' => ['Contains spam keywords', 'Too many links'],
	 *     'severity' => 'high'
	 * ]);
	 * ```
	 */
	private function logSpamDetection(string $content, array $analysis): void {
		$this->storage->insert('spam_log', [
			'detection_type' => 'content_analysis',
			'ip_address'     => $this->getClientIP(),
			'user_agent'     => $_SERVER['HTTP_USER_AGENT'] ?? '',
			'user_id'        => $_SESSION['user_id'] ?? null,
			'content_length' => strlen($content),
			'spam_score'     => $analysis['spam_score'],
			'reasons'        => json_encode($analysis['reasons']),
			'severity'       => $analysis['severity'],
			'content_sample' => substr($content, 0, 200), // Store sample for analysis
		]);
	}

	/**
	 * Get client IP address
	 *
	 * Determines the real IP address of the client, handling various
	 * proxy and forwarding scenarios (CloudFlare, load balancers, etc.).
	 *
	 * @return string Client IP address or '0.0.0.0' if unable to determine
	 *
	 * Usage example:
	 * ```php
	 * $clientIP = $this->getClientIP();
	 * echo "Request from IP: " . $clientIP;
	 * // Outputs: Request from IP: 192.168.1.100
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
	 * Get spam detection statistics
	 *
	 * Returns comprehensive statistics about spam detection performance
	 * including total detections, severity breakdown, top reasons, and averages.
	 *
	 * @return array Statistics array with detection counts, severity breakdown, and analysis data
	 *
	 * Usage example:
	 * ```php
	 * $detector = new SpamDetector();
	 * $stats = $detector->getStats();
	 * echo "Total detections: " . $stats['total_detections'];
	 * echo "Average spam score: " . $stats['average_spam_score'];
	 * echo "Recent detections (24h): " . $stats['recent_detections'];
	 * print_r($stats['severity_breakdown']);
	 * print_r($stats['top_reasons']);
	 * ```
	 */
	public function getStats(): array {
		$spamLogs = $this->storage->find('spam_log', ['detection_type' => 'content_analysis']);
		$recentCutoff = time() - 86400; // Last 24 hours

		$stats = [
			'total_detections'      => count($spamLogs),
			'recent_detections'     => 0,
			'severity_breakdown'    => [
				'low'    => 0,
				'medium' => 0,
				'high'   => 0,
			],
			'average_spam_score'    => 0.0,
			'top_reasons'           => [],
			'spam_keywords_count'   => count($this->spamKeywords),
			'profanity_words_count' => count($this->profanityList),
		];

		$totalScore = 0;
		$allReasons = [];

		foreach ($spamLogs as $log) {
			$severity = $log['severity'] ?? 'low';
			$stats['severity_breakdown'][$severity]++;

			$score = $log['spam_score'] ?? 0;
			$totalScore += $score;

			if (($log['created_at'] ?? 0) > $recentCutoff) {
				$stats['recent_detections']++;
			}

			// Collect reasons
			$reasons = json_decode($log['reasons'] ?? '[]', true);
			if (is_array($reasons)) {
				foreach ($reasons as $reason) {
					$allReasons[] = $reason;
				}
			}
		}

		if (count($spamLogs) > 0) {
			$stats['average_spam_score'] = round($totalScore / count($spamLogs), 2);
		}

		// Count top reasons
		$reasonCounts = array_count_values($allReasons);
		arsort($reasonCounts);
		$stats['top_reasons'] = array_slice($reasonCounts, 0, 5, true);

		return $stats;
	}

	/**
	 * Get spam keywords
	 *
	 * Returns the current list of spam keywords used for detection.
	 * This includes both default keywords and any custom additions.
	 *
	 * @return array Array of spam keywords
	 *
	 * Usage example:
	 * ```php
	 * $detector = new SpamDetector();
	 * $keywords = $detector->getSpamKeywords();
	 * echo "Total keywords: " . count($keywords);
	 * foreach ($keywords as $keyword) {
	 *     echo "- " . $keyword . "\n";
	 * }
	 * ```
	 */
	public function getSpamKeywords(): array {
		return $this->spamKeywords;
	}

	/**
	 * Get profanity list
	 *
	 * Returns the current list of profanity words used for content filtering.
	 * This includes both default words and any custom additions.
	 *
	 * @return array Array of profanity words
	 *
	 * Usage example:
	 * ```php
	 * $detector = new SpamDetector();
	 * $profanity = $detector->getProfanityList();
	 * echo "Total profanity words: " . count($profanity);
	 * // Note: Be careful when displaying profanity words
	 * ```
	 */
	public function getProfanityList(): array {
		return $this->profanityList;
	}

	/**
	 * Check if spam detection is enabled
	 *
	 * Returns the current enabled status of the spam detection system
	 * based on configuration settings.
	 *
	 * @return bool True if spam detection is enabled, false otherwise
	 *
	 * Usage example:
	 * ```php
	 * $detector = new SpamDetector();
	 * if ($detector->isEnabled()) {
	 *     $result = $detector->analyzeContent($userInput);
	 *     // Process spam detection results
	 * } else {
	 *     // Spam detection is disabled, skip analysis
	 * }
	 * ```
	 */
	public function isEnabled(): bool {
		return $this->enabled;
	}

	/**
	 * Train the spam detector with user feedback
	 *
	 * Collects user feedback about whether content is spam or legitimate
	 * to improve future detection accuracy. Stores training data for analysis.
	 *
	 * @param string $content Content to provide feedback on
	 * @param bool   $isSpam  True if content is spam, false if legitimate
	 * @return void
	 *
	 * Usage example:
	 * ```php
	 * $detector = new SpamDetector();
	 *
	 * // User reports content as spam
	 * $detector->trainWithFeedback($suspiciousContent, true);
	 *
	 * // User reports content as legitimate (false positive)
	 * $detector->trainWithFeedback($falsePositiveContent, false);
	 *
	 * echo "Feedback recorded for machine learning improvement";
	 * ```
	 */
	public function trainWithFeedback(string $content, bool $isSpam): void {
		$this->storage->insert('spam_training', [
			'content_hash'   => hash('sha256', $content),
			'content_sample' => substr($content, 0, 200),
			'is_spam'        => $isSpam,
			'user_id'        => $_SESSION['user_id'] ?? null,
			'ip_address'     => $this->getClientIP(),
		]);
	}
}