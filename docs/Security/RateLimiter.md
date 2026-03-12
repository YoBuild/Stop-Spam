# Yohns\Security\RateLimiter

IP and user rate limiting with progressive timeouts. Tracks requests by identifier (IP or user ID) and action type, automatically blocking repeat offenders with escalating block durations. No database required -- stores all data in JSON files via `FileStorage`.

## Configuration

All values come from the `rate_limiting` section of `config/security.php`:

| Key               | Default | Description                                      |
|--------------------|---------|--------------------------------------------------|
| `enabled`          | `true`  | Master switch for rate limiting                  |
| `storage`          | `'json'`| Storage backend (only JSON supported)            |
| `global_max`       | `1000`  | Max requests per hour (global)                   |
| `per_endpoint`     | `100`   | Max requests per minute per endpoint             |
| `per_ip`           | `300`   | Max requests per minute per IP                   |
| `login_max`        | `5`     | Max login attempts per 15 minutes                |
| `block_duration`   | `900`   | Initial block duration in seconds (15 minutes)   |
| `block_multiplier` | `2.0`   | Multiplier applied to block duration per repeat violation |

### Built-in Action Limits

The class maps action types to specific limits internally:

| Action          | Max Requests | Time Window  |
|-----------------|--------------|--------------|
| `login`         | 5 (from `login_max`)  | 15 minutes   |
| `post`          | 10           | 10 minutes   |
| `message`       | 20           | 10 minutes   |
| `search`        | 15           | 1 minute     |
| `profile_view`  | 50           | 5 minutes    |
| *(any other)*   | 100 (from `per_endpoint`) | 1 minute |

## Critical Gotcha

**`isLimited()` is a PURE CHECK.** It does NOT create records or increment counters. You must call `recordAttempt()` separately to track the request. This is intentional -- it prevents double-counting when you check first, then record after processing.

```php
// CORRECT: check then record separately
if ($limiter->isLimited($ip, 'login')) {
	http_response_code(429);
	die('Too many attempts.');
}
// ... process login ...
$limiter->recordAttempt($ip, 'login', $loginSuccess);

// WRONG: assuming isLimited() records the attempt
if ($limiter->isLimited($ip, 'login')) {
	die('Rate limited');
}
// Forgot to call recordAttempt() -- counter never increments!
```

## Progressive Timeouts

When an identifier exceeds the limit, block duration escalates with each violation:

- 1st violation: `900` seconds (15 min)
- 2nd violation: `900 * 2.0` = `1800` seconds (30 min)
- 3rd violation: `900 * 2.0^2` = `3600` seconds (1 hour)
- 4th violation: `900 * 2.0^3` = `7200` seconds (2 hours)

Formula: `block_duration * (block_multiplier ^ (violation_count - 1))`

## Methods

### isLimited(string $ipAddress, string $actionType, ?int $userId = null): bool

Returns `true` if the identifier has exceeded its rate limit or is currently blocked. Does NOT record the attempt.

```php
$limiter = new RateLimiter();
$ip = ClientIP::get(); // '203.0.113.45'

// Check by IP only
if ($limiter->isLimited($ip, 'search')) {
	http_response_code(429);
	echo json_encode(['error' => 'Too many search requests. Try again in 1 minute.']);
	exit;
}

// Check by user ID (takes precedence over IP for the identifier)
$userId = 42;
if ($limiter->isLimited($ip, 'post', $userId)) {
	// Identifier becomes "user_42" instead of "ip_203.0.113.45"
	http_response_code(429);
	exit;
}
```

When `$userId` is provided, the identifier is `"user_{$userId}"`. When `null`, it is `"ip_{$ipAddress}"`.

### recordAttempt(string $ipAddress, string $actionType, bool $success, ?int $userId = null): void

Records a request attempt. Creates the rate limit record if it does not exist. On failure, increments `failed_attempts`; if failures hit the action limit, the identifier is auto-blocked. On success for `login` actions, `failed_attempts` resets to `0`.

```php
$limiter = new RateLimiter();
$ip = ClientIP::get();

// Login flow
if ($limiter->isLimited($ip, 'login')) {
	http_response_code(429);
	$remaining = $limiter->getBlockTimeRemaining("ip_{$ip}", 'login');
	echo "Blocked for {$remaining} more seconds.";
	exit;
}

$authenticated = authenticate($username, $password); // your auth logic

// Record the outcome -- on 5th failure, auto-blocks the IP
$limiter->recordAttempt($ip, 'login', $authenticated);

if (!$authenticated) {
	$left = $limiter->getRemainingRequests("ip_{$ip}", 'login');
	echo "Invalid credentials. {$left} attempts remaining.";
}
```

```php
// Recording a successful post submission
$limiter->recordAttempt($ip, 'post', true, $userId);

// Recording a failed API call
$limiter->recordAttempt($ip, 'api_call', false);
```

### isEnabled(): bool

Returns whether rate limiting is active based on config.

```php
$limiter = new RateLimiter();
if (!$limiter->isEnabled()) {
	// Rate limiting disabled in config -- skip checks
	processRequest();
}
```

### getRemainingRequests(string $identifier, string $actionType): int

Returns how many requests the identifier can still make in the current time window. Returns `PHP_INT_MAX` when rate limiting is disabled.

**Note:** The `$identifier` parameter is the internal identifier string, not a raw IP. Use `"ip_203.0.113.45"` or `"user_42"`.

```php
$limiter = new RateLimiter();
$identifier = "ip_203.0.113.45";

$remaining = $limiter->getRemainingRequests($identifier, 'login');
// Returns: 5 (no attempts yet, login_max = 5)

$remaining = $limiter->getRemainingRequests($identifier, 'search');
// Returns: 15 (no attempts yet, search max = 15)

// After 3 login attempts:
$remaining = $limiter->getRemainingRequests($identifier, 'login');
// Returns: 2

// Use in response headers
header("X-RateLimit-Remaining: {$remaining}");
```

### getBlockTimeRemaining(string $identifier, string $actionType): int

Returns seconds remaining on a block, or `0` if not blocked.

```php
$limiter = new RateLimiter();
$seconds = $limiter->getBlockTimeRemaining("ip_203.0.113.45", 'login');

if ($seconds > 0) {
	$minutes = ceil($seconds / 60);
	echo "You are blocked for approximately {$minutes} minute(s).";
	// "You are blocked for approximately 15 minute(s)."
} else {
	echo "You are not blocked.";
}
```

### blockIdentifier(string $identifier, string $actionType, ?int $duration = null): void

Manually block an identifier. Uses `block_duration` (900s) when `$duration` is `null`.

```php
$limiter = new RateLimiter();

// Block an IP from posting for 1 hour
$limiter->blockIdentifier('ip_198.51.100.25', 'post', 3600);

// Block a user from login using default duration (900s)
$limiter->blockIdentifier('user_99', 'login');
```

### unblockIdentifier(string $identifier, string $actionType): bool

Remove a block. Returns `false` if the identifier has no record for that action.

```php
$limiter = new RateLimiter();

$unblocked = $limiter->unblockIdentifier('user_123', 'login');
// Returns: true (record found and unblocked)

$unblocked = $limiter->unblockIdentifier('ip_10.0.0.1', 'login');
// Returns: false (no record exists)
```

### resetIdentifier(string $identifier): int

Deletes ALL rate limit records for an identifier across all action types. Returns the count of deleted records.

```php
$limiter = new RateLimiter();

$deleted = $limiter->resetIdentifier('user_42');
// Returns: 3 (had records for login, post, search)

$deleted = $limiter->resetIdentifier('ip_203.0.113.45');
// Returns: 1
```

### cleanup(): int

Removes rate limit records older than 7 days that are not currently blocked. Returns the number of deleted records. Run this periodically (e.g., via cron).

```php
$limiter = new RateLimiter();
$deleted = $limiter->cleanup();
// Returns: 47 (removed 47 stale records)
```

### getStats(): array

Returns rate limiting statistics.

```php
$limiter = new RateLimiter();
$stats = $limiter->getStats();

// $stats = [
//     'total_records'     => 156,
//     'currently_blocked' => 3,
//     'total_violations'  => 28,
//     'action_types'      => [
//         'login'   => 42,
//         'post'    => 67,
//         'search'  => 31,
//         'message' => 16,
//     ],
//     'top_violators' => [
//         'ip_203.0.113.45' => 5,
//         'user_99'         => 3,
//         'ip_198.51.100.7' => 2,
//     ],
// ];
```

## Full Example: Login Rate Limiting

```php
use Yohns\Security\RateLimiter;
use Yohns\Security\ClientIP;

$limiter = new RateLimiter();
$ip      = ClientIP::get();

// Step 1: Check if already rate limited
if ($limiter->isLimited($ip, 'login')) {
	$wait = $limiter->getBlockTimeRemaining("ip_{$ip}", 'login');
	http_response_code(429);
	header("Retry-After: {$wait}");
	echo json_encode([
		'error'       => 'Too many login attempts.',
		'retry_after' => $wait,
	]);
	exit;
}

// Step 2: Show remaining attempts in the response
$remaining = $limiter->getRemainingRequests("ip_{$ip}", 'login');

// Step 3: Process login
$authenticated = authenticate($_POST['username'], $_POST['password']);

// Step 4: Record the attempt (this is what increments the counter)
$limiter->recordAttempt($ip, 'login', $authenticated);

if ($authenticated) {
	// Success -- failed_attempts resets to 0 for login actions
	redirectToDashboard();
} else {
	$left = $remaining - 1; // we just used one
	echo json_encode([
		'error'              => 'Invalid credentials.',
		'attempts_remaining' => max(0, $left),
	]);
}
```

## Full Example: API Endpoint Rate Limiting

```php
use Yohns\Security\RateLimiter;
use Yohns\Security\ClientIP;

$limiter = new RateLimiter();
$ip      = ClientIP::get();
$userId  = $_SESSION['user_id'] ?? null;

// Check rate limit for this API endpoint
if ($limiter->isLimited($ip, 'api_search', $userId)) {
	http_response_code(429);
	echo json_encode(['error' => 'Rate limit exceeded.']);
	exit;
}

// Process the request
$results = performSearch($_GET['q']);

// Record successful attempt
$limiter->recordAttempt($ip, 'api_search', true, $userId);

// Include rate limit headers
$identifier = $userId ? "user_{$userId}" : "ip_{$ip}";
$remaining  = $limiter->getRemainingRequests($identifier, 'api_search');
header("X-RateLimit-Remaining: {$remaining}");

echo json_encode($results);
```

## Storage

Data is persisted in the `rate_limits` FileStorage table. Violations are logged to `rate_limit_violations` and security events to `security_events`. All tables are JSON files in the `database/` directory.

## IP Detection

Uses `ClientIP::get()` internally for logging. The `$ipAddress` parameter you pass to `isLimited()` and `recordAttempt()` should also come from `ClientIP::get()` to ensure consistency with the trusted proxy gate.