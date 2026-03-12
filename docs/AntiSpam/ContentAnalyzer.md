# Yohns\AntiSpam\ContentAnalyzer

Advanced content analysis providing sentiment analysis, readability scoring (Flesch Reading Ease), language detection, suspicious pattern detection, link analysis, and formatting metrics. Returns a comprehensive breakdown with an overall suspicious score from 0.0 to 1.0.

This is a **standalone class** -- it is not part of the `SecurityManager` orchestration. Use it independently for content moderation, quality assessment, or pre-publish review.

## Configuration

Uses `spam_detection.enabled` from `config/security.php` (default: `true`). When disabled, the constructor still initializes but all analysis methods remain functional.

## Methods

### `analyzeContent(string $content): array`

Runs all analysis methods and returns a comprehensive result with an overall suspicious score and recommendations.

```php
<?php
use Yohns\AntiSpam\ContentAnalyzer;

$analyzer = new ContentAnalyzer();

$result = $analyzer->analyzeContent(
	'The quick brown fox jumps over the lazy dog. ' .
	'This is a great example of a simple English sentence. ' .
	'I really enjoy writing good content for readers.'
);

// $result = [
//     'content_length'   => 137,
//     'word_count'       => 25,
//     'language'         => [
//         'primary'    => 'english',
//         'confidence' => 1.85,
//         'all_scores' => [
//             'english' => 1.85,
//             'spanish' => 0.12,
//             'french'  => 0.08,
//         ],
//     ],
//     'sentiment'        => [
//         'sentiment'  => 'positive',
//         'confidence' => 0.67,
//         'scores'     => [
//             'positive' => 3,    // 'great', 'enjoy', 'good'
//             'negative' => 0,
//             'neutral'  => 0,
//         ],
//     ],
//     'readability'      => [
//         'score'                  => 82.3,    // Flesch Reading Ease (0-100)
//         'level'                  => 'easy',
//         'avg_sentence_length'    => 8.3,
//         'avg_syllables_per_word' => 1.2,
//     ],
//     'patterns'         => [],    // no suspicious patterns found
//     'links'            => [
//         'count'              => 0,
//         'domains'            => [],
//         'suspicious_domains' => [],
//         'shortened_urls'     => [],
//         'ip_addresses'       => [],
//         'unique_domains'     => 0,
//     ],
//     'formatting'       => [
//         'uppercase_ratio'     => 0.03,
//         'punctuation_density' => 0.02,
//         'whitespace_ratio'    => 0.18,
//         'special_characters'  => 0,
//         'repeated_characters' => [],
//         'line_breaks'         => 0,
//         'paragraphs'          => 1,
//     ],
//     'suspicious_score' => 0.0,
//     'recommendations'  => ['Content looks good!'],
// ]
```

**Suspicious content example:**

```php
$result = $analyzer->analyzeContent(
	'CLICK HERE NOW!!! Visit http://free-prizes.tk ' .
	'http://win-money.click http://bit.ly/scam123 ' .
	'http://192.168.1.1/payload http://get-rich.ml ' .
	'http://bonus.ga Call 555-123-4567!!!'
);

// $result['suspicious_score'] = 1.0  (capped at 1.0)
// $result['links'] = [
//     'count'              => 6,
//     'domains'            => ['free-prizes.tk', 'win-money.click', 'bit.ly', '192.168.1.1', 'get-rich.ml', 'bonus.ga'],
//     'suspicious_domains' => ['free-prizes.tk', 'win-money.click', 'get-rich.ml', 'bonus.ga'],
//     'shortened_urls'     => ['http://bit.ly/scam123'],
//     'ip_addresses'       => ['192.168.1.1'],
//     'unique_domains'     => 6,
// ]
// $result['patterns'] = [
//     'phone_numbers' => [
//         'count'       => 1,
//         'severity'    => 'medium',
//         'description' => 'Phone numbers detected',
//         'matches'     => ['555-123-4567'],
//     ],
//     'excessive_punctuation' => [
//         'count'       => 2,
//         'severity'    => 'medium',
//         'description' => 'Excessive punctuation',
//         'matches'     => ['!!!', '!!!'],
//     ],
//     'all_caps_words' => [
//         'count'       => 3,
//         'severity'    => 'low',
//         'description' => 'All caps words',
//         'matches'     => ['CLICK', 'HERE', 'NOW'],  // first 5 shown
//     ],
// ]
// $result['recommendations'] = [
//     'Content appears suspicious - review before publishing',
//     'Consider reducing the number of links',
//     'Remove links to suspicious domains',
//     'Reduce excessive use of capital letters',
// ]
```

### `detectLanguage(string $content): array`

Detects English, Spanish, or French by matching common words and character patterns. Returns the primary language, a confidence score, and scores for all three languages.

```php
$lang = $analyzer->detectLanguage('El gato está en la casa y el perro también.');
// [
//     'primary'    => 'spanish',
//     'confidence' => 2.1,
//     'all_scores' => [
//         'spanish' => 2.1,
//         'english' => 0.15,
//         'french'  => 0.08,
//     ],
// ]

$lang = $analyzer->detectLanguage('Le chat est dans la maison avec les enfants.');
// [
//     'primary'    => 'french',
//     'confidence' => 1.9,
//     'all_scores' => [
//         'french'  => 1.9,
//         'spanish' => 0.35,
//         'english' => 0.12,
//     ],
// ]
```

### `analyzeSentiment(string $content): array`

Counts positive, negative, and neutral keyword occurrences. Classifies as `positive`, `negative`, or `neutral` based on a 60% threshold.

**Positive words:** good, great, excellent, amazing, wonderful, fantastic, love, like, enjoy, happy, pleased, satisfied
**Negative words:** bad, terrible, awful, horrible, hate, dislike, angry, frustrated, disappointed, sad, upset
**Neutral words:** okay, fine, average, normal, standard, typical, usual, regular, common, ordinary

```php
$sentiment = $analyzer->analyzeSentiment('This product is terrible and I hate it.');
// [
//     'sentiment'  => 'negative',
//     'confidence' => 0.67,
//     'scores'     => [
//         'positive' => 0,
//         'negative' => 2,    // 'terrible', 'hate'
//         'neutral'  => 0,
//     ],
// ]

$sentiment = $analyzer->analyzeSentiment('It was an average, ordinary day.');
// [
//     'sentiment'  => 'neutral',
//     'confidence' => 1.0,
//     'scores'     => [
//         'positive' => 0,
//         'negative' => 0,
//         'neutral'  => 2,    // 'average', 'ordinary'
//     ],
// ]
```

### `calculateReadability(string $content): array`

Calculates the Flesch Reading Ease score (0-100). Higher scores mean easier reading.

| Score range | Level              |
|-------------|--------------------|
| 90 -- 100   | `very_easy`        |
| 80 -- 89    | `easy`             |
| 70 -- 79    | `fairly_easy`      |
| 60 -- 69    | `standard`         |
| 50 -- 59    | `fairly_difficult` |
| 30 -- 49    | `difficult`        |
| 0 -- 29     | `very_difficult`   |

```php
$readability = $analyzer->calculateReadability(
	'The cat sat on the mat. The dog ran in the park. Birds fly in the sky.'
);
// [
//     'score'                  => 92.4,
//     'level'                  => 'very_easy',
//     'avg_sentence_length'    => 6.3,
//     'avg_syllables_per_word' => 1.1,
// ]

$readability = $analyzer->calculateReadability(
	'The epistemological ramifications of phenomenological consciousness ' .
	'necessitate a comprehensive methodological investigation.'
);
// [
//     'score'                  => 0.0,       // clamped to 0
//     'level'                  => 'very_difficult',
//     'avg_sentence_length'    => 8.0,
//     'avg_syllables_per_word' => 4.9,
// ]
```

### `detectPatterns(string $content): array`

Scans for predefined suspicious patterns. Returns only patterns that matched.

**Default patterns:**

| Pattern name             | Regex                                              | Severity |
|--------------------------|-----------------------------------------------------|----------|
| `phone_numbers`          | `\b\d{3}[-.]?\d{3}[-.]?\d{4}\b`                    | medium   |
| `email_addresses`        | `[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}`  | low      |
| `excessive_punctuation`  | `[!?]{3,}`                                          | medium   |
| `all_caps_words`         | `\b[A-Z]{4,}\b`                                    | low      |

```php
$patterns = $analyzer->detectPatterns(
	'Contact us at support@example.com or call 800-555-1234!!! URGENT DEAL'
);
// [
//     'email_addresses' => [
//         'count'       => 1,
//         'severity'    => 'low',
//         'description' => 'Email addresses detected',
//         'matches'     => ['support@example.com'],
//     ],
//     'phone_numbers' => [
//         'count'       => 1,
//         'severity'    => 'medium',
//         'description' => 'Phone numbers detected',
//         'matches'     => ['800-555-1234'],
//     ],
//     'excessive_punctuation' => [
//         'count'       => 1,
//         'severity'    => 'medium',
//         'description' => 'Excessive punctuation',
//         'matches'     => ['!!!'],
//     ],
//     'all_caps_words' => [
//         'count'       => 2,
//         'severity'    => 'low',
//         'description' => 'All caps words',
//         'matches'     => ['URGENT', 'DEAL'],
//     ],
// ]
```

### `analyzeLinks(string $content): array`

Extracts all HTTP/HTTPS URLs and classifies their domains.

**Suspicious domain detection** -- flagged TLDs: `.tk`, `.ml`, `.ga`, `.cf`, `.top`, `.click`. Flagged keywords in domain: `free`, `click`, `win`, `prize`, `offer`.

**URL shortener detection:** `bit.ly`, `tinyurl.com`, `short.link`, `t.co`, `goo.gl`, `ow.ly`, `is.gd`, `buff.ly`, `adf.ly`, `tiny.cc`.

**IP address detection:** Domains that are raw IP addresses (e.g., `http://192.168.1.1/path`).

```php
$links = $analyzer->analyzeLinks(
	'Check https://example.com and http://free-stuff.tk/offer ' .
	'also http://bit.ly/abc123 and http://10.0.0.1/admin'
);
// [
//     'count'              => 4,
//     'domains'            => ['example.com', 'free-stuff.tk', 'bit.ly', '10.0.0.1'],
//     'suspicious_domains' => ['free-stuff.tk'],    // .tk TLD + 'free' keyword
//     'shortened_urls'     => ['http://bit.ly/abc123'],
//     'ip_addresses'       => ['10.0.0.1'],
//     'unique_domains'     => 4,
// ]
```

### `analyzeFormatting(string $content): array`

Returns formatting metrics useful for content quality assessment.

```php
$formatting = $analyzer->analyzeFormatting("HELLO WORLD!!!\n\nThis is normal.\n\nAnother paragraph.");
// [
//     'uppercase_ratio'     => 0.42,       // ratio of uppercase to total letters
//     'punctuation_density' => 0.06,       // ratio of punctuation to total chars
//     'whitespace_ratio'    => 0.16,       // ratio of whitespace to total chars
//     'special_characters'  => 0,          // count of non-alphanumeric, non-whitespace, non-punctuation
//     'repeated_characters' => [
//         ['character' => '!', 'count' => 3, 'pattern' => '!!!'],
//     ],
//     'line_breaks'         => 4,
//     'paragraphs'          => 3,
// ]
```

### `storeAnalysis(string $content, array $result): string`

Persists an analysis result to the `content_analyses` storage table. Returns the inserted record ID. Stores a SHA-256 hash of the content (not the full content).

```php
$analyzer = new ContentAnalyzer();
$result = $analyzer->analyzeContent($userPost);
$recordId = $analyzer->storeAnalysis($userPost, $result);
// $recordId = 'a1b2c3d4...'  (storage-assigned ID)
```

### `getAnalysisStats(): array`

Returns aggregate statistics from all stored analyses.

```php
$stats = $analyzer->getAnalysisStats();
// [
//     'total_analyses'           => 250,
//     'average_suspicious_score' => 0.23,
//     'language_distribution'    => [
//         'english' => 210,
//         'spanish' => 30,
//         'french'  => 10,
//     ],
//     'sentiment_distribution'   => [
//         'positive' => 120,
//         'neutral'  => 95,
//         'negative' => 35,
//     ],
//     'common_patterns'          => [
//         'email_addresses'       => 45,
//         'phone_numbers'         => 22,
//         'all_caps_words'        => 18,
//         'excessive_punctuation' => 12,
//     ],
// ]
```

## Suspicious Score Calculation

The overall `suspicious_score` (0.0 -- 1.0) is calculated from these factors:

| Condition                          | Score added |
|------------------------------------|-------------|
| Language confidence < 0.3          | +0.2        |
| More than 5 links                  | +0.05 per link (max 0.3) |
| Any suspicious domains found       | +0.4        |
| Any IP address links found         | +0.3        |
| Uppercase ratio > 0.7             | +0.2        |
| Punctuation density > 0.2         | +0.15       |
| Each high-severity pattern match   | +0.3        |
| Each medium-severity pattern match | +0.2        |
| Each low-severity pattern match    | +0.1        |
| Readability score < 10 or > 95    | +0.1        |

**Recommendations are generated when:**
- `suspicious_score > 0.5` -- "Content appears suspicious - review before publishing"
- More than 5 links -- "Consider reducing the number of links"
- Any suspicious domains -- "Remove links to suspicious domains"
- Uppercase ratio > 0.5 -- "Reduce excessive use of capital letters"
- Readability score < 30 -- "Improve readability by using shorter sentences"
- Negative sentiment with confidence > 0.8 -- "Consider using more positive language"
- No issues found -- "Content looks good!"

## Complete Workflow Example

```php
<?php
use Yohns\AntiSpam\ContentAnalyzer;

$analyzer = new ContentAnalyzer();
$content  = $_POST['article_body'] ?? '';

// Run full analysis
$result = $analyzer->analyzeContent($content);

// Store for later review
$analyzer->storeAnalysis($content, $result);

// Decision logic
if ($result['suspicious_score'] > 0.7) {
	// Flag for manual moderation
	$status = 'pending_review';
} elseif ($result['suspicious_score'] > 0.4) {
	// Publish but notify moderators
	$status = 'published_flagged';
} else {
	// Auto-publish
	$status = 'published';
}

// Show recommendations to the author
if ($result['recommendations'][0] !== 'Content looks good!') {
	echo "Suggestions for improvement:\n";
	foreach ($result['recommendations'] as $rec) {
		echo "  - {$rec}\n";
	}
}

// Check readability for content guidelines
if ($result['readability']['level'] === 'very_difficult') {
	echo "Warning: content may be too difficult for general audiences.\n";
	echo "Average sentence length: {$result['readability']['avg_sentence_length']} words\n";
}
```

## Gotchas

- **Language detection is basic.** It uses common word frequency and character patterns for English, Spanish, and French only. Short content (a few words) will have low confidence scores and may misidentify the language.
- **Sentiment is keyword-based.** It counts exact substring matches from a fixed list of ~33 words. It does not understand negation ("not good" counts as positive due to "good"), sarcasm, or context.
- **Syllable counting is approximate.** The simplified algorithm counts vowel groups and adjusts for silent 'e'. It works reasonably for English but will be inaccurate for other languages.
- **Suspicious patterns are persisted.** Like `SpamDetector`, the default patterns are saved to `FileStorage` on first run. Subsequent runs use the stored version. To modify patterns, update them in storage directly.
- **Not part of SecurityManager.** Unlike `Honeypot` and `SpamDetector`, this class is not composed by `SecurityManager`. You must instantiate and use it independently.
- **`storeAnalysis()` stores a hash, not the content.** The full content is not persisted -- only a SHA-256 hash and metadata. You cannot retrieve the original content from stored analyses.