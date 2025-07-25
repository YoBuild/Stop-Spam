<?php

namespace Yohns\AntiSpam;

use Yohns\Core\Config;
use Yohns\Security\FileStorage;

/**
 * SpamDetector class for comprehensive content spam detection
 *
 * Analyzes content for spam patterns, keywords, and suspicious behavior.
 */
class SpamDetector {
	private FileStorage $storage;
	private bool        $enabled;
	private array       $spamKeywords;
	private array       $profanityList;
	private int         $maxLinks;
	private int         $maxCapitalsPercent;
	private int         $maxRepeatedChars;

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
	 */
	public function shouldAutoBlock(string $content): bool {
		$analysis = $this->analyzeContent($content);
		return $analysis['is_spam'] && $analysis['spam_score'] >= 0.8;
	}

	/**
	 * Log spam detection
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
	 */
	public function getSpamKeywords(): array {
		return $this->spamKeywords;
	}

	/**
	 * Get profanity list
	 */
	public function getProfanityList(): array {
		return $this->profanityList;
	}

	/**
	 * Check if spam detection is enabled
	 */
	public function isEnabled(): bool {
		return $this->enabled;
	}

	/**
	 * Train the spam detector with user feedback
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