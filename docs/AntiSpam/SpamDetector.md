# Yohns\AntiSpam\SpamDetector

Content spam scoring via keywords, profanity, link analysis, and suspicious pattern detection. Assigns a score from 0.0 to 1.0 and flags content as spam when the score reaches 0.5 or higher.

Uses `\Yohns\Security\ClientIP::get()` for IP detection.
Logs detected spam to the `spam_log` storage table.
Persists keyword and profanity lists in `FileStorage` (`spam_keywords` and `profanity_list` tables).

## Configuration

All values come from the `spam_detection` section in `config/security.php`:

| Key                    | Default | Description                                          |
|------------------------|---------|------------------------------------------------------|
| `enabled`              | `true`  | Master switch for spam detection                     |
| `log_enabled`          | `true`  | Whether to log detected spam to `spam_log`           |
| `max_links`            | `3`     | URLs allowed before link score kicks in              |
| `max_capitals_percent` | `70`    | Percentage of capital letters before capitals score kicks in |
| `max_repeated_chars`   | `5`     | Consecutive identical characters before repeated-chars score kicks in |

## Methods

### `analyzeContent(string $content): array`

Runs all checks against the content and returns a detailed result.

**Checks performed (each contributes to the total score):**

| Check                | Max score | What it catches                                       |
|----------------------|-----------|-------------------------------------------------------|
| Spam keywords        | 0.6       | +0.2 per matched keyword from the keywords list       |
| Profanity            | 0.4       | +0.15 per matched profanity word                      |
| Excessive links      | 0.5       | +0.2 per link beyond `max_links` (3)                  |
| Excessive capitals   | 0.4       | Score based on how far above `max_capitals_percent` (70%) |
| Repeated characters  | 0.3       | +0.1 per occurrence of 5+ identical chars in a row    |
| Suspicious patterns  | 0.4       | Excessive punctuation (`!!`, `???`) and Cyrillic+Latin mixed script |

**Severity thresholds:**

| Score range | `is_spam` | `severity` |
|-------------|-----------|------------|
| 0.0 -- 0.29 | `false`  | `low`      |
| 0.3 -- 0.49 | `false`  | `low`      |
| 0.5 -- 0.79 | `true`   | `medium`   |
| 0.8 -- 1.0  | `true`   | `high`     |

**Return value:**

```php
[
	'is_spam'    => false,     // bool
	'spam_score' => 0.0,      // float 0.0-1.0
	'reasons'    => [],       // array of human-readable reason strings
	'severity'   => 'low',    // 'low', 'medium', or 'high'
]
```

**Example -- clean content:**

```php
<?php
use Yohns\AntiSpam\SpamDetector;

$detector = new SpamDetector();

$result = $detector->analyzeContent('Hello, I would like to ask about your services.');
// $result = [
//     'is_spam'    => false,
//     'spam_score' => 0.0,
//     'reasons'    => [],
//     'severity'   => 'low',
// ]
```

**Example -- obvious spam:**

```php
$result = $detector->analyzeContent(
	'BUY CHEAP VIAGRA NOW!!! Click here for FREE MONEY!!! ' .
	'Visit http://spam1.com http://spam2.com http://spam3.com http://spam4.com http://spam5.com'
);
// $result = [
//     'is_spam'    => true,
//     'spam_score' => 0.8,    // or higher
//     'reasons'    => [
//         'Contains spam keywords',       // 'viagra', 'click here', 'free money', 'cheap'
//         'Too many links',               // 5 links, max is 3
//         'Excessive capital letters',     // well above 70%
//         'Suspicious patterns detected',  // '!!!' excessive punctuation
//     ],
//     'severity'   => 'high',
// ]
```

### `cleanContent(string $content): string`

Sanitizes content by replacing profanity with asterisks, collapsing repeated punctuation, and normalizing repeated characters.

```php
$detector = new SpamDetector();

$cleaned = $detector->cleanContent("This is damn stupid!!!! Check it ouuuuuuut...........");
// "This is **** ****** !!! Check it ouuut..."
//
// What happened:
//   'damn'   -> '****'     (profanity replaced)
//   'stupid' -> '******'   (profanity replaced)
//   '!!!!'   -> '!!!'      (4+ punctuation collapsed to 3)
//   'uuuuuuut' -> 'uuut'  (5+ repeated chars collapsed to 3)
//   '..........' -> '...'  (4+ dots collapsed to 3)
```

### `addSpamKeyword(string $keyword): bool`

Adds a keyword to the spam detection list. Returns `false` if it already exists. Persisted to `FileStorage`.

```php
$detector = new SpamDetector();

$detector->addSpamKeyword('crypto airdrop');  // returns true
$detector->addSpamKeyword('nft giveaway');    // returns true
$detector->addSpamKeyword('viagra');          // returns false (already in default list)
```

### `removeSpamKeyword(string $keyword): bool`

Removes a keyword from the list. Returns `false` if not found.

```php
$detector->removeSpamKeyword('discount');  // returns true  (was in default list)
$detector->removeSpamKeyword('foobar');    // returns false (not in list)
```

### `addProfanityWord(string $word): bool`

Adds a word to the profanity filter. Returns `false` if it already exists.

```php
$detector->addProfanityWord('jerk');   // returns true
$detector->addProfanityWord('damn');   // returns false (already in default list)
```

### `removeProfanityWord(string $word): bool`

Removes a word from the profanity filter. Returns `false` if not found.

```php
$detector->removeProfanityWord('hell');    // returns true
$detector->removeProfanityWord('xyz');     // returns false
```

### `getStats(): array`

Returns detection statistics from the `spam_log` table (entries with `detection_type = 'content_analysis'`).

```php
$stats = $detector->getStats();

// $stats = [
//     'total_detections'      => 134,
//     'recent_detections'     => 12,           // last 24 hours
//     'severity_breakdown'    => [
//         'low'    => 20,
//         'medium' => 78,
//         'high'   => 36,
//     ],
//     'average_spam_score'    => 0.67,
//     'top_reasons'           => [
//         'Contains spam keywords'        => 98,
//         'Too many links'                => 45,
//         'Excessive capital letters'     => 32,
//         'Suspicious patterns detected'  => 28,
//         'Contains profanity'            => 15,
//     ],
//     'spam_keywords_count'   => 26,
//     'profanity_words_count' => 5,
// ]
```

### `shouldAutoBlock(string $content): bool`

Shortcut that calls `analyzeContent()` and returns `true` if `spam_score >= 0.8`.

```php
if ($detector->shouldAutoBlock($userComment)) {
	http_response_code(403);
	exit('Content blocked.');
}
```

### `trainWithFeedback(string $content, bool $isSpam): void`

Stores user feedback (spam or not-spam) in the `spam_training` table for future analysis. Content is stored as a SHA-256 hash plus a 200-character sample.

```php
// Moderator marks content as spam
$detector->trainWithFeedback($flaggedComment, true);

// Moderator marks false positive as legitimate
$detector->trainWithFeedback($legitimateComment, false);
```

### `isEnabled(): bool`

Returns the `spam_detection.enabled` config value. When disabled, `analyzeContent()` returns a zero-score result without running any checks.

### `getSpamKeywords(): array` / `getProfanityList(): array`

Return the current keyword and profanity arrays.

```php
$keywords  = $detector->getSpamKeywords();
// ['viagra', 'cialis', 'buy now', 'click here', 'free money', ...]

$profanity = $detector->getProfanityList();
// ['damn', 'hell', 'crap', 'stupid', 'idiot']
```

## Security Features

### Text Normalization (Evasion Defeat)

The internal `normalizeText()` method runs before keyword matching to defeat common spam evasion techniques:

| Evasion technique       | Input             | Normalized to |
|------------------------|-------------------|---------------|
| Leetspeak              | `v1@gr@`          | `viagra`      |
| Character insertion    | `v.i.a.g.r.a`     | `viagra`      |
| Zero-width characters  | `vi\u200Bagra`    | `viagra`      |
| Mixed case             | `ViAgRa`          | `viagra`      |

### Keyword Matching Strategy

- **Single-word keywords** (e.g., `viagra`): matched with `\b` word boundaries via regex, so `"viagra"` matches but `"extravaganza"` does not.
- **Multi-word phrases** (e.g., `buy now`): matched with `strpos` substring search on the normalized text.

### Homoglyph Detection

Content containing both Cyrillic characters (`\x{0400}-\x{04FF}`) and Latin characters is flagged as a suspicious pattern. This catches attacks where visually similar Cyrillic letters replace Latin ones to bypass keyword filters.

## Gotchas

- **Keywords and profanity are persisted.** On first run, default lists are saved to `FileStorage`. After that, the stored versions are used. If you edit `loadSpamKeywords()` defaults in the source code, existing stored lists will not be updated. Use `addSpamKeyword()` / `removeSpamKeyword()` to modify the live list.
- **Score can exceed individual check caps.** Each check has its own cap (0.3-0.6), but the total score is the sum of all checks. A message hitting multiple checks can easily reach 1.0+, though the severity mapping only distinguishes up to 0.8.
- **Empty or whitespace-only content returns zero score.** The method short-circuits before running any checks.
- **`cleanContent()` does not check spam keywords.** It only replaces profanity words, normalizes punctuation, and collapses repeated characters. Spam keywords are left intact -- use `analyzeContent()` to detect them.