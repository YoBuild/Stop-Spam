# SecurityManager

`Yohns\Security\SecurityManager` -- Orchestrator that composes and coordinates all security components.

Provides a single entry point for form protection (CSRF + honeypot + spam detection), rate limiting, content validation, IP trust scoring, API token management, security headers, and maintenance. Internally creates and wires together `CSRFToken`, `RateLimiter`, `Honeypot`, `SpamDetector`, and `FileStorage`.

---

## Constructor

```php
$security = new \Yohns\Security\SecurityManager(?int $userId = null);
```

| Parameter | Type       | Description                                          |
|-----------|------------|------------------------------------------------------|
| `$userId` | `int|null` | Current user ID for context-aware rate limiting/logging |

The constructor instantiates all sub-components. IP detection throughout the class uses `ClientIP::get()`.

```php
// For a logged-in user
$security = new \Yohns\Security\SecurityManager(42);

// For anonymous visitors
$security = new \Yohns\Security\SecurityManager();
```

---

## Configuration

`SecurityManager` pulls values from several config sections in `config/security.php`:

| Config Key                       | Default                          | Used In                     |
|----------------------------------|----------------------------------|-----------------------------|
| `domain.base_url`               | `'http://stop-spam.jb'`          | `getSecurityHeaders()`       |
| `domain.allowed_origins`        | `['https://stop-spam.jb', ...]`  | CORS `Access-Control-Allow-Origin` |
| `security.csp_cdn_sources`      | jsdelivr, cdnjs, Google Fonts, unpkg | Content-Security-Policy   |
| `content_validation.max_length` | `10000`                          | `validateContent()`          |
| `ip_security.blacklist`         | `[]`                             | `checkIPSecurity()`          |
| `ip_security.whitelist`         | `[]`                             | `checkIPSecurity()`          |

Sub-component configs (`csrf`, `honeypot`, `spam_detection`, `rate_limiting`) are loaded by each component's own constructor.

---

## Complete Form Protection Flow

### Step 1: Initialize the form

#### initializeForm(string $formId = 'default'): array

Generates CSRF token, honeypot field HTML, and associated CSS. Returns everything needed to render a protected form.

**Return keys:**

| Key              | Type     | Contains                                       |
|------------------|----------|-------------------------------------------------|
| `csrf_field`     | `string` | `<input type="hidden" name="csrf_token" value="...">` |
| `csrf_meta`      | `string` | `<meta name="csrf-token" content="...">`        |
| `honeypot_field`  | `string` | Hidden field HTML from `Honeypot::initialize()` |
| `honeypot_css`   | `string` | CSS to hide the honeypot field                  |

```php
$security = new \Yohns\Security\SecurityManager();
$form = $security->initializeForm('contact_form');
```

### Step 2: Render the form

```php
<!DOCTYPE html>
<html>
<head>
	<?= $form['csrf_meta'] ?>
	<style><?= $form['honeypot_css'] ?></style>
</head>
<body>
	<form method="POST" action="/contact">
		<?= $form['csrf_field'] ?>
		<?= $form['honeypot_field'] ?>

		<label>Name: <input type="text" name="name"></label>
		<label>Message: <textarea name="message"></textarea></label>
		<button type="submit">Send</button>
	</form>
</body>
</html>
```

### Step 3: Validate the submission

#### securityCheck(string $actionType, array $postData, bool $requireCSRF = true, float $spamThreshold = 0.5, string $formId = 'default'): array

Runs checks in order: rate limit, CSRF, honeypot, spam detection. Stops at the first failure.

**Parameters:**

| Parameter        | Type     | Description                                      |
|------------------|----------|--------------------------------------------------|
| `$actionType`    | `string` | Action name for rate limiting (e.g. `'login'`, `'contact'`) |
| `$postData`      | `array`  | `$_POST` data                                     |
| `$requireCSRF`   | `bool`   | Whether to enforce CSRF validation                |
| `$spamThreshold` | `float`  | Spam score cutoff (0.0-1.0); higher = more lenient |
| `$formId`        | `string` | Must match the `$formId` from `initializeForm()`  |

**Return keys:**

| Key               | Type    | Description                                      |
|-------------------|---------|--------------------------------------------------|
| `passed`          | `bool`  | `true` if all checks passed                      |
| `reason`          | `string`| Why it failed (empty on success)                  |
| `details`         | `array` | Human-readable detail messages                    |
| `security_checks` | `array` | Per-check results (see below)                     |

**`security_checks` contents on success:**

```php
[
	'rate_limit'      => true,
	'csrf'            => true,
	'honeypot'        => ['passed' => true],
	'spam_detection'  => [
		'score'   => 0.12,
		'is_spam' => false,
		'reasons' => [],
	],
]
```

```php
// Process the form submission
$security = new \Yohns\Security\SecurityManager($userId);
$check = $security->securityCheck('contact', $_POST, true, 0.5, 'contact_form');

if (!$check['passed']) {
	http_response_code(403);
	echo json_encode([
		'error'   => $check['reason'],
		'details' => $check['details'],
	]);
	exit;
}

// All checks passed -- process the form
$name    = $_POST['name'];
$message = $security->validateContent($_POST['message']);
// Save to database...
```

**Spam detection extracts content** from POST fields named: `content`, `message`, `text`, `body`, `comment`, `description`. Other field names are not scanned.

---

## Content Validation

### validateContent(string $content, bool $allowHtml = false, bool $cleanProfanity = true): string

Sanitizes content for safe storage/display. Returns the cleaned string directly (not an array).

Processing order:
1. Truncate to `content_validation.max_length` (default 10000)
2. Strip tags if `$allowHtml` is `false`
3. Run through `SpamDetector::cleanContent()` if `$cleanProfanity` is `true`
4. Apply `htmlspecialchars(ENT_QUOTES, 'UTF-8')`
5. Trim

```php
$security = new \Yohns\Security\SecurityManager();

// Clean a user comment (no HTML, filter profanity)
$clean = $security->validateContent(
	'<script>alert("xss")</script>Check out my comment!',
	false,
	true
);
// $clean => 'Check out my comment!' (tags stripped, encoded, trimmed)

// Clean a blog post (allow HTML, skip profanity filter)
$clean = $security->validateContent(
	'<p>My <b>blog</b> post</p>',
	true,
	false
);
// $clean => '&lt;p&gt;My &lt;b&gt;blog&lt;/b&gt; post&lt;/p&gt;'
// Note: htmlspecialchars is always applied here, unlike ContentValidator::validate()
```

Note: This is a simpler interface than `ContentValidator::validate()`. For full control (XSS detection results, change tracking, per-option overrides), use `ContentValidator` directly.

---

## IP Security

### checkIPSecurity(string $ipAddress = null): array

Analyzes an IP address against blacklists, whitelists, and recent violation history from `spam_log`.

**Return keys:**

| Key           | Type    | Description                                        |
|---------------|---------|----------------------------------------------------|
| `blocked`     | `bool`  | `true` if IP is in the configured blacklist         |
| `suspicious`  | `bool`  | `true` if IP has recent violations                  |
| `reason`      | `string`| Why blocked/suspicious (empty if clean)             |
| `trust_score` | `float` | 0.0 (blocked) to 1.0 (fully trusted)               |

**Trust score thresholds:**

| Violations (last hour) | Trust Score | Status      |
|------------------------|-------------|-------------|
| 0-5                    | 1.0         | Clean       |
| 6-10                   | 0.6         | Suspicious  |
| 11+                    | 0.3         | Suspicious  |
| Blacklisted            | 0.0         | Blocked     |
| Whitelisted            | 1.0         | Trusted     |

```php
$security = new \Yohns\Security\SecurityManager();

// Check current visitor
$ipCheck = $security->checkIPSecurity();

if ($ipCheck['blocked']) {
	http_response_code(403);
	die('Access denied');
}

if ($ipCheck['suspicious']) {
	// Require CAPTCHA or additional verification
	echo 'Trust score: ' . ($ipCheck['trust_score'] * 100) . '%';
	echo 'Reason: ' . $ipCheck['reason'];
}

// Check a specific IP
$ipCheck = $security->checkIPSecurity('203.0.113.50');
```

---

## API Token Management

### generateAPIToken(int $userId, int $expiresIn = 3600): string

Creates a 64-character hex token stored in the `api_tokens` FileStorage table with the user's IP.

### validateAPIToken(string $token): ?array

Returns the full token record (including `user_id`, `permissions`, `expires_at`) or `null` if invalid/expired. Expired tokens are auto-deleted.

```php
$security = new \Yohns\Security\SecurityManager();

// Issue a token on login
$token = $security->generateAPIToken(42, 86400); // 24-hour token

echo json_encode([
	'token'      => $token,
	'expires_in' => 86400,
	'token_type' => 'Bearer',
]);

// Validate on subsequent API requests
$authHeader = $_SERVER['HTTP_AUTHORIZATION'] ?? '';
if (preg_match('/Bearer\s+(.+)$/i', $authHeader, $m)) {
	$tokenData = $security->validateAPIToken($m[1]);

	if ($tokenData) {
		$userId = $tokenData['user_id'];
		// Proceed with authenticated request
	} else {
		http_response_code(401);
		echo json_encode(['error' => 'Invalid or expired token']);
		exit;
	}
}
```

Note: This is `SecurityManager`'s own simple token store (in the `api_tokens` table). For the full-featured token system with usage limits, signing, and multiple token types, use `TokenManager` directly.

---

## Security Headers

### getSecurityHeaders(): array

Returns an associative array of HTTP security headers.

### applySecurityHeaders(): void

Sends all security headers via `header()`. Call before any output.

**Headers generated:**

| Header                          | Value                                             |
|---------------------------------|---------------------------------------------------|
| `X-Content-Type-Options`        | `nosniff`                                          |
| `X-Frame-Options`               | `DENY`                                             |
| `X-XSS-Protection`              | `1; mode=block`                                    |
| `Referrer-Policy`               | `strict-origin-when-cross-origin`                  |
| `Content-Security-Policy`       | `default-src 'self' <CDN sources>; script-src ...` |
| `Strict-Transport-Security`     | `max-age=31536000; includeSubDomains`              |
| `Access-Control-Allow-Origin`   | Comma-separated `domain.allowed_origins`           |

CDN sources in the CSP come from `csp_cdn_sources` config (defaults: jsdelivr, cdnjs, Google Fonts, unpkg).

```php
$security = new \Yohns\Security\SecurityManager();

// Option A: Apply all headers automatically
$security->applySecurityHeaders();

// Option B: Get headers for manual control (e.g., in a middleware)
$headers = $security->getSecurityHeaders();
foreach ($headers as $name => $value) {
	header("{$name}: {$value}");
}
```

---

## Security Event Logging

### logSecurityEvent(string $eventType, array $details = []): void

Writes an event to the `security_log` FileStorage table with user ID, IP, user agent, request URI, and severity.

```php
$security = new \Yohns\Security\SecurityManager(42);

// Log a successful login
$security->logSecurityEvent('login_success', [
	'method'   => 'password',
	'severity' => 'info',
]);

// Log a blocked attack
$security->logSecurityEvent('xss_blocked', [
	'payload_hash' => hash('sha256', $maliciousInput),
	'severity'     => 'high',
	'blocked'      => true,
]);

// Log a failed login
$security->logSecurityEvent('login_failed', [
	'username' => 'admin',
	'severity' => 'warning',
]);
```

---

## Maintenance

### performMaintenance(): array

Runs cleanup across all components: expired CSRF tokens, rate limiter entries, honeypot sessions, and general storage.

**Returns:**

| Key                  | Type  | Description                          |
|----------------------|-------|--------------------------------------|
| `csrf_cleanup`       | `int` | Number of expired CSRF tokens removed |
| `rate_limit_cleanup` | `int` | Number of rate limit entries removed  |
| `honeypot_cleanup`   | `int` | Number of honeypot sessions removed   |
| `storage_cleanup`    | `int` | `1` if storage cleanup ran            |

```php
$security = new \Yohns\Security\SecurityManager();
$results = $security->performMaintenance();

echo "Cleaned: {$results['csrf_cleanup']} CSRF tokens, "
	. "{$results['rate_limit_cleanup']} rate limit entries, "
	. "{$results['honeypot_cleanup']} honeypot sessions";
```

**Cron job example** (run hourly):

```php
#!/usr/bin/env php
<?php
// maintenance.php -- run via cron: 0 * * * * php /path/to/maintenance.php

require __DIR__ . '/vendor/autoload.php';

$security = new \Yohns\Security\SecurityManager();
$results = $security->performMaintenance();

$security->logSecurityEvent('maintenance_completed', [
	'results'  => $results,
	'severity' => 'info',
]);
```

---

## Component Accessors

Direct access to sub-components for advanced usage:

| Method              | Returns        | Use Case                              |
|---------------------|----------------|---------------------------------------|
| `getCSRFToken()`    | `CSRFToken`    | Manual token generation/validation    |
| `getRateLimiter()`  | `RateLimiter`  | Check remaining requests, custom limits |
| `getHoneypot()`     | `Honeypot`     | Custom honeypot configuration          |
| `getSpamDetector()` | `SpamDetector` | Direct content analysis                |
| `getStorage()`      | `FileStorage`  | Query security logs, custom tables     |

```php
$security = new \Yohns\Security\SecurityManager();

// Direct rate limiter access
$rl = $security->getRateLimiter();
$isLimited = $rl->isLimited('192.168.1.100', 'api_call');

// Query security logs directly
$storage = $security->getStorage();
$highSeverity = $storage->find('security_log', ['severity' => 'high']);

// Custom spam analysis
$spam = $security->getSpamDetector();
$analysis = $spam->analyzeContent('Buy cheap viagra now!!!');
echo 'Spam score: ' . $analysis['spam_score'];
```

---

## Statistics

### getSecurityStats(): array

Aggregates statistics from all sub-components.

```php
$security = new \Yohns\Security\SecurityManager();
$stats = $security->getSecurityStats();

// $stats = [
//     'csrf'           => ['active' => 5, 'expired' => 12, ...],
//     'rate_limiting'  => ['blocked_requests' => 23, ...],
//     'honeypot'       => ['bots_caught' => 7, ...],
//     'spam_detection' => ['total_detections' => 45, 'average_spam_score' => 0.32, ...],
//     'storage'        => ['total_records' => 1200, ...],
// ]
```

---

## Gotchas

1. **`securityCheck()` short-circuits.**
   Checks run in order: rate limit, CSRF, honeypot, spam. The method returns immediately on the first failure. If rate limiting fails, CSRF is never checked. This is by design for performance but means `security_checks` may be incomplete on failure.

2. **Spam detection only scans specific field names.**
   `extractContentFromPost()` looks for POST keys: `content`, `message`, `text`, `body`, `comment`, `description`. If your form uses different field names (e.g., `feedback`), they will not be scanned for spam.

3. **`validateContent()` always applies `htmlspecialchars()`.**
   Even with `$allowHtml=true`, the output is run through `htmlspecialchars()`. This differs from `ContentValidator::validate()` which skips `finalEncode()` when `allow_html=true`. If you need sanitized HTML preserved, use `ContentValidator` directly.

4. **`generateAPIToken()` / `validateAPIToken()` use a separate storage table.**
   These use the `api_tokens` FileStorage table, not the `security_tokens` table used by `TokenManager`. The two token systems are independent.

5. **All IP detection goes through `ClientIP::get()`.**
   Forwarded headers (`X-Forwarded-For`, etc.) are only trusted when `REMOTE_ADDR` is a known proxy. Never read `$_SERVER` IP headers directly.

6. **`applySecurityHeaders()` must be called before any output.**
   PHP cannot send headers after output has started. Call it early in your bootstrap or middleware.