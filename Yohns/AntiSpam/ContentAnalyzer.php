<?php

namespace Yohns\AntiSpam;

use Yohns\Core\Config;
use Yohns\Security\FileStorage;

/**
 * ContentAnalyzer class for advanced content analysis and pattern detection
 *
 * Provides detailed content analysis including language detection,
 * sentiment analysis, and advanced spam pattern recognition.
 */
class ContentAnalyzer {
	private FileStorage $storage;
	private bool        $enabled;
	private array       $suspiciousPatterns;
	private array       $languagePatterns;
	private array       $sentimentKeywords;

	public function __construct() {
		$this->storage = new FileStorage();
		$this->enabled = Config::get('spam_detection.enabled', 'security') ?? true;

		$this->loadSuspiciousPatterns();
		$this->loadLanguagePatterns();
		$this->loadSentimentKeywords();
	}

	/**
	 * Perform comprehensive content analysis
	 */
	public function analyzeContent(string $content): array {
		$result = [
			'content_length'   => strlen($content),
			'word_count'       => str_word_count($content),
			'language'         => $this->detectLanguage($content),
			'sentiment'        => $this->analyzeSentiment($content),
			'readability'      => $this->calculateReadability($content),
			'patterns'         => $this->detectPatterns($content),
			'links'            => $this->analyzeLinks($content),
			'formatting'       => $this->analyzeFormatting($content),
			'suspicious_score' => 0.0,
			'recommendations'  => [],
		];

		// Calculate overall suspicious score
		$result['suspicious_score'] = $this->calculateSuspiciousScore($result);

		// Generate recommendations
		$result['recommendations'] = $this->generateRecommendations($result);

		return $result;
	}

	/**
	 * Detect the primary language of the content
	 */
	public function detectLanguage(string $content): array {
		$content = strtolower($content);
		$languageScores = [];

		foreach ($this->languagePatterns as $language => $patterns) {
			$score = 0;
			$totalPatterns = count($patterns);

			foreach ($patterns['common_words'] as $word) {
				if (strpos($content, $word) !== false) {
					$score += 2;
				}
			}

			foreach ($patterns['character_patterns'] as $pattern) {
				$matches = preg_match_all($pattern, $content);
				$score += $matches * 0.5;
			}

			// Normalize score
			$languageScores[$language] = $totalPatterns > 0 ? $score / $totalPatterns : 0;
		}

		arsort($languageScores);
		$primaryLanguage = key($languageScores);
		$confidence = $languageScores[$primaryLanguage] ?? 0;

		return [
			'primary'    => $primaryLanguage ?: 'unknown',
			'confidence' => round($confidence, 2),
			'all_scores' => $languageScores,
		];
	}

	/**
	 * Analyze sentiment of the content
	 */
	public function analyzeSentiment(string $content): array {
		$content = strtolower($content);
		$positiveScore = 0;
		$negativeScore = 0;
		$neutralScore = 0;

		// Count positive words
		foreach ($this->sentimentKeywords['positive'] as $word) {
			$matches = substr_count($content, $word);
			$positiveScore += $matches;
		}

		// Count negative words
		foreach ($this->sentimentKeywords['negative'] as $word) {
			$matches = substr_count($content, $word);
			$negativeScore += $matches;
		}

		// Count neutral/objective words
		foreach ($this->sentimentKeywords['neutral'] as $word) {
			$matches = substr_count($content, $word);
			$neutralScore += $matches;
		}

		$totalScore = $positiveScore + $negativeScore + $neutralScore;

		if ($totalScore === 0) {
			return [
				'sentiment'  => 'neutral',
				'confidence' => 0.0,
				'scores'     => [
					'positive' => 0,
					'negative' => 0,
					'neutral'  => 0,
				],
			];
		}

		$positiveRatio = $positiveScore / $totalScore;
		$negativeRatio = $negativeScore / $totalScore;

		if ($positiveRatio > 0.6) {
			$sentiment = 'positive';
			$confidence = $positiveRatio;
		} elseif ($negativeRatio > 0.6) {
			$sentiment = 'negative';
			$confidence = $negativeRatio;
		} else {
			$sentiment = 'neutral';
			$confidence = 1 - abs($positiveRatio - $negativeRatio);
		}

		return [
			'sentiment'  => $sentiment,
			'confidence' => round($confidence, 2),
			'scores'     => [
				'positive' => $positiveScore,
				'negative' => $negativeScore,
				'neutral'  => $neutralScore,
			],
		];
	}

	/**
	 * Calculate readability score (simplified Flesch Reading Ease)
	 */
	public function calculateReadability(string $content): array {
		$sentences = preg_split('/[.!?]+/', $content, -1, PREG_SPLIT_NO_EMPTY);
		$words = str_word_count($content);
		$syllables = $this->countSyllables($content);

		$sentenceCount = count($sentences);

		if ($sentenceCount === 0 || $words === 0) {
			return [
				'score'                  => 0,
				'level'                  => 'unreadable',
				'avg_sentence_length'    => 0,
				'avg_syllables_per_word' => 0,
			];
		}

		$avgSentenceLength = $words / $sentenceCount;
		$avgSyllablesPerWord = $syllables / $words;

		// Simplified Flesch Reading Ease formula
		$score = 206.835 - (1.015 * $avgSentenceLength) - (84.6 * $avgSyllablesPerWord);
		$score = max(0, min(100, $score)); // Clamp between 0-100

		// Determine reading level
		if ($score >= 90) {
			$level = 'very_easy';
		} elseif ($score >= 80) {
			$level = 'easy';
		} elseif ($score >= 70) {
			$level = 'fairly_easy';
		} elseif ($score >= 60) {
			$level = 'standard';
		} elseif ($score >= 50) {
			$level = 'fairly_difficult';
		} elseif ($score >= 30) {
			$level = 'difficult';
		} else {
			$level = 'very_difficult';
		}

		return [
			'score'                  => round($score, 1),
			'level'                  => $level,
			'avg_sentence_length'    => round($avgSentenceLength, 1),
			'avg_syllables_per_word' => round($avgSyllablesPerWord, 1),
		];
	}

	/**
	 * Detect suspicious patterns in content
	 */
	public function detectPatterns(string $content): array {
		$detectedPatterns = [];

		foreach ($this->suspiciousPatterns as $patternName => $pattern) {
			$matches = preg_match_all($pattern['regex'], $content, $matchData);

			if ($matches > 0) {
				$detectedPatterns[$patternName] = [
					'count'       => $matches,
					'severity'    => $pattern['severity'],
					'description' => $pattern['description'],
					'matches'     => array_slice($matchData[0] ?? [], 0, 5), // First 5 matches
				];
			}
		}

		return $detectedPatterns;
	}

	/**
	 * Analyze links in content
	 */
	public function analyzeLinks(string $content): array {
		$linkPattern = '/https?:\/\/[^\s<>"\']+/i';
		preg_match_all($linkPattern, $content, $matches);

		$links = $matches[0] ?? [];
		$analysis = [
			'count'              => count($links),
			'domains'            => [],
			'suspicious_domains' => [],
			'shortened_urls'     => [],
			'ip_addresses'       => [],
		];

		foreach ($links as $link) {
			$domain = parse_url($link, PHP_URL_HOST);

			if ($domain) {
				$analysis['domains'][] = $domain;

				// Check for suspicious domains
				if ($this->isSuspiciousDomain($domain)) {
					$analysis['suspicious_domains'][] = $domain;
				}

				// Check for URL shorteners
				if ($this->isUrlShortener($domain)) {
					$analysis['shortened_urls'][] = $link;
				}

				// Check if domain is an IP address
				if (filter_var($domain, FILTER_VALIDATE_IP)) {
					$analysis['ip_addresses'][] = $domain;
				}
			}
		}

		$analysis['domains'] = array_unique($analysis['domains']);
		$analysis['unique_domains'] = count($analysis['domains']);

		return $analysis;
	}

	/**
	 * Analyze formatting patterns
	 */
	public function analyzeFormatting(string $content): array {
		return [
			'uppercase_ratio'     => $this->calculateUppercaseRatio($content),
			'punctuation_density' => $this->calculatePunctuationDensity($content),
			'whitespace_ratio'    => $this->calculateWhitespaceRatio($content),
			'special_characters'  => $this->countSpecialCharacters($content),
			'repeated_characters' => $this->findRepeatedCharacters($content),
			'line_breaks'         => substr_count($content, "\n"),
			'paragraphs'          => count(preg_split('/\n\s*\n/', trim($content))),
		];
	}

	/**
	 * Calculate overall suspicious score
	 */
	private function calculateSuspiciousScore(array $analysis): float {
		$score = 0.0;

		// Language detection suspicion
		if ($analysis['language']['confidence'] < 0.3) {
			$score += 0.2;
		}

		// Too many links
		if ($analysis['links']['count'] > 5) {
			$score += min(0.3, $analysis['links']['count'] * 0.05);
		}

		// Suspicious domains
		if (!empty($analysis['links']['suspicious_domains'])) {
			$score += 0.4;
		}

		// IP address links
		if (!empty($analysis['links']['ip_addresses'])) {
			$score += 0.3;
		}

		// Formatting issues
		if ($analysis['formatting']['uppercase_ratio'] > 0.7) {
			$score += 0.2;
		}

		if ($analysis['formatting']['punctuation_density'] > 0.2) {
			$score += 0.15;
		}

		// Detected patterns
		foreach ($analysis['patterns'] as $pattern) {
			switch ($pattern['severity']) {
				case 'high':
					$score += 0.3;
					break;
				case 'medium':
					$score += 0.2;
					break;
				case 'low':
					$score += 0.1;
					break;
			}
		}

		// Readability extremes
		$readabilityScore = $analysis['readability']['score'];
		if ($readabilityScore < 10 || $readabilityScore > 95) {
			$score += 0.1;
		}

		return min(1.0, $score);
	}

	/**
	 * Generate content improvement recommendations
	 */
	private function generateRecommendations(array $analysis): array {
		$recommendations = [];

		if ($analysis['suspicious_score'] > 0.5) {
			$recommendations[] = 'Content appears suspicious - review before publishing';
		}

		if ($analysis['links']['count'] > 5) {
			$recommendations[] = 'Consider reducing the number of links';
		}

		if (!empty($analysis['links']['suspicious_domains'])) {
			$recommendations[] = 'Remove links to suspicious domains';
		}

		if ($analysis['formatting']['uppercase_ratio'] > 0.5) {
			$recommendations[] = 'Reduce excessive use of capital letters';
		}

		if ($analysis['readability']['score'] < 30) {
			$recommendations[] = 'Improve readability by using shorter sentences';
		}

		if ($analysis['sentiment']['sentiment'] === 'negative' && $analysis['sentiment']['confidence'] > 0.8) {
			$recommendations[] = 'Consider using more positive language';
		}

		if (empty($recommendations)) {
			$recommendations[] = 'Content looks good!';
		}

		return $recommendations;
	}

	/**
	 * Count syllables in text (simplified)
	 */
	private function countSyllables(string $text): int {
		$text = strtolower($text);
		$text = preg_replace('/[^a-z]/', '', $text);

		if (strlen($text) <= 3) {
			return 1;
		}

		$syllables = 0;
		$previousWasVowel = false;

		for ($i = 0; $i < strlen($text); $i++) {
			$isVowel = in_array($text[$i], ['a', 'e', 'i', 'o', 'u', 'y']);

			if ($isVowel && !$previousWasVowel) {
				$syllables++;
			}

			$previousWasVowel = $isVowel;
		}

		// Handle silent 'e'
		if (substr($text, -1) === 'e') {
			$syllables--;
		}

		return max(1, $syllables);
	}

	/**
	 * Calculate uppercase ratio
	 */
	private function calculateUppercaseRatio(string $content): float {
		$letters = preg_replace('/[^a-zA-Z]/', '', $content);
		$totalLetters = strlen($letters);

		if ($totalLetters === 0) {
			return 0.0;
		}

		$uppercaseLetters = strlen(preg_replace('/[^A-Z]/', '', $letters));
		return $uppercaseLetters / $totalLetters;
	}

	/**
	 * Calculate punctuation density
	 */
	private function calculatePunctuationDensity(string $content): float {
		$totalChars = strlen($content);

		if ($totalChars === 0) {
			return 0.0;
		}

		$punctuation = preg_match_all('/[.!?,:;]/', $content);
		return $punctuation / $totalChars;
	}

	/**
	 * Calculate whitespace ratio
	 */
	private function calculateWhitespaceRatio(string $content): float {
		$totalChars = strlen($content);

		if ($totalChars === 0) {
			return 0.0;
		}

		$whitespace = preg_match_all('/\s/', $content);
		return $whitespace / $totalChars;
	}

	/**
	 * Count special characters
	 */
	private function countSpecialCharacters(string $content): int {
		return preg_match_all('/[^a-zA-Z0-9\s.!?,:;]/', $content);
	}

	/**
	 * Find repeated character patterns
	 */
	private function findRepeatedCharacters(string $content): array {
		$patterns = [];

		// Find 3+ repeated characters
		if (preg_match_all('/(.)\1{2,}/', $content, $matches)) {
			foreach ($matches[0] as $match) {
				$char = $match[0];
				$count = strlen($match);
				$patterns[] = [
					'character' => $char,
					'count'     => $count,
					'pattern'   => $match,
				];
			}
		}

		return $patterns;
	}

	/**
	 * Check if domain is suspicious
	 */
	private function isSuspiciousDomain(string $domain): bool {
		$suspiciousTlds = ['.tk', '.ml', '.ga', '.cf', '.top', '.click'];
		$suspiciousKeywords = ['free', 'click', 'win', 'prize', 'offer'];

		// Check TLD
		foreach ($suspiciousTlds as $tld) {
			if (str_ends_with($domain, $tld)) {
				return true;
			}
		}

		// Check keywords in domain
		foreach ($suspiciousKeywords as $keyword) {
			if (strpos($domain, $keyword) !== false) {
				return true;
			}
		}

		return false;
	}

	/**
	 * Check if domain is a URL shortener
	 */
	private function isUrlShortener(string $domain): bool {
		$shorteners = [
			'bit.ly', 'tinyurl.com', 'short.link', 't.co', 'goo.gl',
			'ow.ly', 'is.gd', 'buff.ly', 'adf.ly', 'tiny.cc'
		];

		return in_array($domain, $shorteners);
	}

	/**
	 * Load suspicious patterns
	 */
	private function loadSuspiciousPatterns(): void {
		$patterns = $this->storage->findOne('suspicious_patterns', ['active' => true]);

		if ($patterns && isset($patterns['patterns'])) {
			$this->suspiciousPatterns = $patterns['patterns'];
		} else {
			// Default patterns
			$this->suspiciousPatterns = [
				'phone_numbers'         => [
					'regex'       => '/\b\d{3}[-.]?\d{3}[-.]?\d{4}\b/',
					'severity'    => 'medium',
					'description' => 'Phone numbers detected',
				],
				'email_addresses'       => [
					'regex'       => '/[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/',
					'severity'    => 'low',
					'description' => 'Email addresses detected',
				],
				'excessive_punctuation' => [
					'regex'       => '/[!?]{3,}/',
					'severity'    => 'medium',
					'description' => 'Excessive punctuation',
				],
				'all_caps_words'        => [
					'regex'       => '/\b[A-Z]{4,}\b/',
					'severity'    => 'low',
					'description' => 'All caps words',
				],
			];

			$this->storage->insert('suspicious_patterns', [
				'patterns'    => $this->suspiciousPatterns,
				'active'      => true,
				'description' => 'Default suspicious patterns',
			]);
		}
	}

	/**
	 * Load language patterns
	 */
	private function loadLanguagePatterns(): void {
		$this->languagePatterns = [
			'english' => [
				'common_words'       => ['the', 'and', 'is', 'in', 'to', 'of', 'a', 'that', 'it', 'with'],
				'character_patterns' => ['/\bthe\b/i', '/\band\b/i', '/ing\b/i'],
			],
			'spanish' => [
				'common_words'       => ['el', 'la', 'de', 'que', 'y', 'a', 'en', 'un', 'es', 'se'],
				'character_patterns' => ['/ñ/i', '/\bel\b/i', '/\bla\b/i'],
			],
			'french'  => [
				'common_words'       => ['le', 'de', 'et', 'à', 'un', 'il', 'être', 'et', 'en', 'avoir'],
				'character_patterns' => ['/[àâäéèêëïîôöùûüÿç]/i', '/\ble\b/i'],
			],
		];
	}

	/**
	 * Load sentiment keywords
	 */
	private function loadSentimentKeywords(): void {
		$this->sentimentKeywords = [
			'positive' => [
				'good', 'great', 'excellent', 'amazing', 'wonderful', 'fantastic',
				'love', 'like', 'enjoy', 'happy', 'pleased', 'satisfied'
			],
			'negative' => [
				'bad', 'terrible', 'awful', 'horrible', 'hate', 'dislike',
				'angry', 'frustrated', 'disappointed', 'sad', 'upset'
			],
			'neutral'  => [
				'okay', 'fine', 'average', 'normal', 'standard', 'typical',
				'usual', 'regular', 'common', 'ordinary'
			],
		];
	}

	/**
	 * Get content analysis statistics
	 */
	public function getAnalysisStats(): array {
		$analyses = $this->storage->read('content_analyses');

		$stats = [
			'total_analyses'           => count($analyses),
			'average_suspicious_score' => 0.0,
			'language_distribution'    => [],
			'sentiment_distribution'   => [],
			'common_patterns'          => [],
		];

		if (empty($analyses)) {
			return $stats;
		}

		$totalScore = 0;
		$languages = [];
		$sentiments = [];
		$patterns = [];

		foreach ($analyses as $analysis) {
			$data = json_decode($analysis['analysis_data'] ?? '{}', true);

			if (isset($data['suspicious_score'])) {
				$totalScore += $data['suspicious_score'];
			}

			if (isset($data['language']['primary'])) {
				$lang = $data['language']['primary'];
				$languages[$lang] = ($languages[$lang] ?? 0) + 1;
			}

			if (isset($data['sentiment']['sentiment'])) {
				$sentiment = $data['sentiment']['sentiment'];
				$sentiments[$sentiment] = ($sentiments[$sentiment] ?? 0) + 1;
			}

			if (isset($data['patterns'])) {
				foreach (array_keys($data['patterns']) as $pattern) {
					$patterns[$pattern] = ($patterns[$pattern] ?? 0) + 1;
				}
			}
		}

		$stats['average_suspicious_score'] = round($totalScore / count($analyses), 2);
		$stats['language_distribution'] = $languages;
		$stats['sentiment_distribution'] = $sentiments;

		arsort($patterns);
		$stats['common_patterns'] = array_slice($patterns, 0, 10, true);

		return $stats;
	}

	/**
	 * Store analysis results
	 */
	public function storeAnalysis(string $content, array $analysis): string {
		return $this->storage->insert('content_analyses', [
			'content_hash'     => hash('sha256', $content),
			'content_length'   => strlen($content),
			'analysis_data'    => json_encode($analysis),
			'suspicious_score' => $analysis['suspicious_score'],
			'language'         => $analysis['language']['primary'] ?? 'unknown',
			'sentiment'        => $analysis['sentiment']['sentiment'] ?? 'neutral',
		]);
	}
}