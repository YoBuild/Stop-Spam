# Yohns\Security\IPSecurity

IP whitelist/blacklist management and reputation tracking. Provides comprehensive IP analysis including proxy detection, threat assessment, trust scoring, and automated blocking of low-trust IPs. Supports both IPv4 and IPv6 with CIDR range matching. No database required -- stores all data in JSON files via `FileStorage`.

## Configuration

All values come from the `ip_security` section of `config/security.php`:

| Key               | Default | Description                                          |
|--------------------|---------|------------------------------------------------------|
| `enabled`          | `true`  | Master switch for IP security features               |
| `whitelist`        | `[]`    | Array of IPs/CIDRs to always trust (config-level)    |
| `blacklist`        | `[]`    | Array of IPs/CIDRs to always block (config-level)    |
| `check_proxies`    | `true`  | Enable proxy/VPN detection during analysis           |
| `max_proxy_depth`  | `3`     | Max proxy hops to inspect                            |

Config-level whitelist/blacklist entries are merged with entries stored in FileStorage at runtime. To add IPs via config:

```php
// config/security.php
'ip_security' => [
	'enabled'   => true,
	'whitelist' => ['10.0.0.0/8', '192.168.1.0/24'],
	'blacklist' => ['198.51.100.25'],
],
```

## Critical Gotcha

**`analyzeIP()` is a PURE READ** -- it returns trust score, threat data, and reputation but **never modifies state**. It will not block, blacklist, or update any records.

**`enforcePolicy()` is the enforcement method** -- it calls `analyzeIP()` internally, then auto-blacklists the IP if the trust score falls below the threshold.

```php
// SAFE: read-only analysis, no side effects
$analysis = $ipSec->analyzeIP('203.0.113.45');
// Nothing is blocked, nothing is written. You decide what to do.

// ENFORCEMENT: analyzes AND auto-blocks low-trust IPs
$result = $ipSec->enforcePolicy('203.0.113.45');
// If trust_score < 0.2, the IP is now blacklisted for 1 hour.
```

## Methods

### analyzeIP(?string $ipAddress = null): array

Performs a full security analysis of an IP address. When `$ipAddress` is `null`, uses `ClientIP::get()`. Returns a detailed result array. **No side effects.**

```php
$ipSec    = new IPSecurity();
$analysis = $ipSec->analyzeIP('203.0.113.45');

// Returned array structure:
// [
//     'ip_address'     => '203.0.113.45',
//     'is_blocked'     => false,
//     'is_whitelisted' => false,
//     'trust_score'    => 0.7,           // 0.0 (dangerous) to 1.0 (trusted)
//     'threats'        => [
//         [
//             'type'        => 'proxy_detected',
//             'severity'    => 'medium',
//             'description' => 'Request coming through proxy/VPN',
//         ],
//     ],
//     'geolocation'     => ['country' => 'US', 'city' => 'Los Angeles', ...],
//     'reputation'      => ['score' => 0.5, 'violation_count' => 0, ...],
//     'proxy_info'      => ['is_proxy' => true, 'proxy_type' => 'http_proxy', ...],
//     'recommendations' => ['Increase monitoring for this IP address'],
// ]

// Use the trust score for decisions
if ($analysis['trust_score'] < 0.3) {
	// Require CAPTCHA or additional verification
	requireCaptcha();
}
```

Trust score deductions:
- Blacklisted: score = `0.0`, `is_blocked` = `true`
- Whitelisted: score = `1.0`, analysis stops early
- Proxy/VPN detected: `-0.3`
- Poor reputation (score < 0.5): `-0.4`
- Recent violations: `-0.1` per violation (capped at `-1.0`)
- Suspicious geolocation: `-0.2`

### enforcePolicy(?string $ipAddress = null, float $threshold = 0.2, int $duration = 3600): array

Calls `analyzeIP()` then auto-blacklists the IP if `trust_score < $threshold`. Whitelisted IPs are never blocked. Returns the same array as `analyzeIP()` with `is_blocked` updated.

```php
$ipSec = new IPSecurity();

// Default: block IPs with trust score below 0.2 for 1 hour
$result = $ipSec->enforcePolicy('203.0.113.45');

if ($result['is_blocked']) {
	http_response_code(403);
	echo 'Access denied.';
	exit;
}
```

```php
// Stricter threshold: block below 0.5, for 24 hours
$result = $ipSec->enforcePolicy('198.51.100.10', 0.5, 86400);

// Lenient: only block the worst offenders
$result = $ipSec->enforcePolicy('198.51.100.10', 0.1, 1800);
```

```php
// Use with current client IP (null = auto-detect via ClientIP::get())
$result = $ipSec->enforcePolicy();
if ($result['is_blocked']) {
	http_response_code(403);
	exit;
}
```

### addToWhitelist(string $ip, string $reason = '', int $duration = 0): bool

Adds an IP or CIDR range to the whitelist. Duration `0` means permanent.

```php
$ipSec = new IPSecurity();

// Permanent: office network
$ipSec->addToWhitelist('10.0.0.0/8', 'Internal office network');

// Temporary: trusted partner for 24 hours
$ipSec->addToWhitelist('203.0.113.50', 'Partner API server', 86400);

// Single IP, no reason
$ipSec->addToWhitelist('192.168.1.100');
```

### addToBlacklist(string $ip, string $reason = '', int $duration = 0): bool

Adds an IP or CIDR range to the blacklist. Duration `0` means permanent. Logs a security event on every call.

```php
$ipSec = new IPSecurity();

// Temporary block for 1 hour
$ipSec->addToBlacklist('203.0.113.45', 'Brute force attempt', 3600);

// Permanent block
$ipSec->addToBlacklist('198.51.100.0/24', 'Known malicious network');

// Block an entire /16 range for 12 hours
$ipSec->addToBlacklist('192.0.2.0/16', 'DDoS source range', 43200);
```

### removeFromWhitelist(string $ip): bool

Removes all whitelist entries matching the IP. Returns `false` if not found.

```php
$ipSec = new IPSecurity();

$removed = $ipSec->removeFromWhitelist('203.0.113.50');
// Returns: true

$removed = $ipSec->removeFromWhitelist('10.10.10.10');
// Returns: false (was not in whitelist)
```

### removeFromBlacklist(string $ip): bool

Removes all blacklist entries matching the IP. Returns `false` if not found.

```php
$ipSec = new IPSecurity();

$removed = $ipSec->removeFromBlacklist('203.0.113.45');
// Returns: true (access restored)
```

### isWhitelisted(string $ip): bool

Checks if an IP matches any whitelist entry, including CIDR ranges.

```php
$ipSec = new IPSecurity();

// After adding 10.0.0.0/8 to whitelist:
$ipSec->isWhitelisted('10.0.0.1');    // true (matches CIDR)
$ipSec->isWhitelisted('10.255.0.99'); // true (matches CIDR)
$ipSec->isWhitelisted('11.0.0.1');    // false
```

### isBlacklisted(string $ip): bool

Checks if an IP matches any blacklist entry. Expired temporary entries are auto-removed on check and return `false`.

```php
$ipSec = new IPSecurity();

$ipSec->addToBlacklist('203.0.113.45', 'Test', 60); // 60-second block

$ipSec->isBlacklisted('203.0.113.45'); // true (within 60 seconds)
// ... 61 seconds later ...
$ipSec->isBlacklisted('203.0.113.45'); // false (expired, auto-removed)
```

### updateReputation(string $ip, string $action, float $scoreChange): void

Adjusts an IP's reputation score. Score is clamped between `0.0` and `1.0`. New IPs start at `0.5`. Negative `$scoreChange` increments `violation_count`.

```php
$ipSec = new IPSecurity();

// Decrease reputation for failed login (-0.1)
$ipSec->updateReputation('203.0.113.45', 'failed_login', -0.1);
// Score: 0.5 -> 0.4, violation_count: 0 -> 1

// Another failure
$ipSec->updateReputation('203.0.113.45', 'failed_login', -0.1);
// Score: 0.4 -> 0.3, violation_count: 1 -> 2

// Successful auth improves reputation
$ipSec->updateReputation('203.0.113.45', 'successful_auth', 0.05);
// Score: 0.3 -> 0.35, violation_count stays at 2
```

### bulkBlacklist(array $ips, string $reason = 'Bulk import'): int

Blacklists multiple IPs at once. Skips invalid IPs. Returns the count of successfully added entries.

```php
$ipSec = new IPSecurity();

$malicious = ['203.0.113.10', '198.51.100.25', 'not-an-ip', '192.0.2.50'];
$added = $ipSec->bulkBlacklist($malicious, 'Threat intelligence feed');
// Returns: 3 ('not-an-ip' was skipped)
```

### getSecurityStats(): array

Returns statistics about the IP security system.

```php
$ipSec = new IPSecurity();
$stats = $ipSec->getSecurityStats();

// $stats = [
//     'whitelist_count'      => 5,
//     'blacklist_count'      => 12,
//     'tracked_ips'          => 234,
//     'recent_events'        => 47,     // last 24 hours
//     'avg_reputation_score' => 0.62,
//     'top_violators'        => [
//         ['ip' => '203.0.113.45', 'violations' => 15, 'score' => 0.1],
//         ['ip' => '198.51.100.7', 'violations' => 8,  'score' => 0.25],
//     ],
// ];
```

### performMaintenance(): array

Removes expired blacklist/whitelist entries, reputation records older than 30 days, and geolocation cache older than 7 days. Refreshes internal caches.

```php
$ipSec  = new IPSecurity();
$result = $ipSec->performMaintenance();

// $result = [
//     'expired_blacklist' => 3,
//     'expired_whitelist' => 1,
//     'old_reputation'    => 45,
//     'old_geolocation'   => 12,
// ];
```

### exportIPLists() / importIPLists(array $data)

Backup and restore whitelist, blacklist, and reputation data.

```php
$ipSec = new IPSecurity();

// Export
$backup = $ipSec->exportIPLists();
file_put_contents('ip_backup.json', json_encode($backup, JSON_PRETTY_PRINT));

// Import
$data    = json_decode(file_get_contents('ip_backup.json'), true);
$results = $ipSec->importIPLists($data);
// $results = [
//     'whitelist_imported'  => 5,
//     'blacklist_imported'  => 12,
//     'reputation_imported' => 234,
// ];
```

### isEnabled(): bool

Returns whether IP security is active based on config.

```php
$ipSec = new IPSecurity();
if ($ipSec->isEnabled()) {
	$result = $ipSec->enforcePolicy();
}
```

## IPv4 and IPv6 CIDR Matching

The `ipInRange()` method (used internally by `isWhitelisted()`, `isBlacklisted()`, and proxy detection) supports both IPv4 and IPv6 CIDR notation using `inet_pton()` bitwise comparison.

```php
// IPv4 CIDR -- all of these work in whitelist/blacklist:
$ipSec->addToWhitelist('192.168.1.0/24');    // matches 192.168.1.0 - 192.168.1.255
$ipSec->addToBlacklist('10.0.0.0/8');        // matches 10.0.0.0 - 10.255.255.255

// IPv6 CIDR:
$ipSec->addToWhitelist('2001:db8::/32');     // matches entire 2001:db8:: block
$ipSec->addToBlacklist('fe80::/10');         // matches link-local addresses

// Exact IP match (no CIDR):
$ipSec->addToBlacklist('203.0.113.45');      // matches only this IP
$ipSec->addToBlacklist('::1');               // matches only IPv6 loopback
```

## Full Example: Middleware Gate

```php
use Yohns\Security\IPSecurity;
use Yohns\Security\ClientIP;

$ipSec = new IPSecurity();

if (!$ipSec->isEnabled()) {
	return; // IP security disabled in config
}

$ip = ClientIP::get();

// Quick check: is this IP already blacklisted?
if ($ipSec->isBlacklisted($ip)) {
	http_response_code(403);
	echo json_encode(['error' => 'Access denied.']);
	exit;
}

// Full analysis with auto-blocking
// Block IPs with trust score below 0.3 for 2 hours
$result = $ipSec->enforcePolicy($ip, 0.3, 7200);

if ($result['is_blocked']) {
	http_response_code(403);
	echo json_encode([
		'error'   => 'Access denied.',
		'threats' => array_column($result['threats'], 'description'),
	]);
	exit;
}

// Log low-trust IPs for monitoring (but don't block yet)
if ($result['trust_score'] < 0.6) {
	error_log("Low trust IP: {$ip} (score: {$result['trust_score']})");
}
```

## Full Example: Admin IP Management

```php
use Yohns\Security\IPSecurity;

$ipSec = new IPSecurity();

// Whitelist the office
$ipSec->addToWhitelist('203.0.113.0/24', 'Main office network');

// Block a bad actor for 24 hours
$ipSec->addToBlacklist('198.51.100.25', 'Scraped user data', 86400);

// Check an IP before taking action
$analysis = $ipSec->analyzeIP('192.0.2.100');
echo "Trust score: {$analysis['trust_score']}\n";
foreach ($analysis['threats'] as $threat) {
	echo "  [{$threat['severity']}] {$threat['description']}\n";
}
foreach ($analysis['recommendations'] as $rec) {
	echo "  Recommendation: {$rec}\n";
}

// Degrade reputation after suspicious behavior
$ipSec->updateReputation('192.0.2.100', 'suspicious_scraping', -0.2);

// View system health
$stats = $ipSec->getSecurityStats();
echo "Blacklisted: {$stats['blacklist_count']}, ";
echo "Tracked IPs: {$stats['tracked_ips']}, ";
echo "Avg reputation: {$stats['avg_reputation_score']}\n";
```

## Storage

Data is persisted across several FileStorage tables in the `database/` directory:

| Table                | Contents                              |
|----------------------|---------------------------------------|
| `ip_whitelist`       | Whitelisted IPs/CIDRs with expiry    |
| `ip_blacklist`       | Blacklisted IPs/CIDRs with expiry    |
| `ip_reputation`      | Per-IP reputation scores and history  |
| `ip_geolocation`     | Cached geolocation lookups (24h TTL)  |
| `known_proxy_ranges` | Known proxy/VPN IP ranges             |
| `security_log`       | Security events (blacklist additions) |

## IP Detection

Uses `ClientIP::get()` internally when no IP is passed to `analyzeIP()` or `enforcePolicy()`. This respects the trusted proxy gate -- forwarded headers are only read when `REMOTE_ADDR` is a known proxy.