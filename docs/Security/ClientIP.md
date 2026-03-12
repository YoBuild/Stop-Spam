# ClientIP

**Class:** `Yohns\Security\ClientIP`
**File:** `Yohns/Security/ClientIP.php`

Shared utility that determines the real client IP address. Every other security class in the library delegates IP detection to `ClientIP::get()` rather than reading `$_SERVER` headers directly.

## Why This Matters

HTTP headers like `X-Forwarded-For` and `X-Real-IP` are trivially spoofable. An attacker can send:

```
X-Forwarded-For: 8.8.8.8
```

If your application blindly trusts that header, the attacker appears to come from `8.8.8.8` -- bypassing IP-based rate limiting, blacklists, and audit trails.

`ClientIP` solves this with a **trusted proxy gate**: forwarded headers are only read when `REMOTE_ADDR` matches a known trusted proxy IP or CIDR range. If the direct connection is not from a trusted proxy, the raw `REMOTE_ADDR` is returned and all forwarded headers are ignored.

## Config

Trusted proxies are loaded from `ip_security.trusted_proxies` in `config/security.php`. If that key is absent or empty, these hardcoded defaults are used:

| Default Proxy       | Description              |
|----------------------|--------------------------|
| `127.0.0.1`         | IPv4 loopback            |
| `::1`               | IPv6 loopback            |
| `10.0.0.0/8`        | Private Class A          |
| `172.16.0.0/12`     | Private Class B          |
| `192.168.0.0/16`    | Private Class C          |

To add your own proxies (e.g., Cloudflare edge IPs or a load balancer), set the config key:

```php
// config/security.php
'ip_security' => [
	'trusted_proxies' => [
		'127.0.0.1',
		'::1',
		'10.0.0.0/8',
		'172.16.0.0/12',
		'192.168.0.0/16',
		'173.245.48.0/20',   // Cloudflare
		'103.21.244.0/22',   // Cloudflare
		'198.51.100.42',     // Your load balancer
	],
],
```

**Note:** Setting `trusted_proxies` replaces the defaults entirely. If you add custom proxies, include the private ranges too or loopback connections will stop resolving forwarded headers.

## Methods

### `ClientIP::get(): string`

Returns the client IP address as a string. Returns `'0.0.0.0'` if no IP can be determined.

```php
<?php
use Yohns\Security\ClientIP;

$ip = ClientIP::get();
// Direct connection from 203.0.113.50 => returns '203.0.113.50'
// Behind Nginx on 127.0.0.1 with X-Real-IP: 203.0.113.50 => returns '203.0.113.50'
// Spoofed X-Forwarded-For from non-proxy 198.51.100.99 => returns '198.51.100.99' (header ignored)
```

### `ClientIP::resetCache(): void`

Clears the cached trusted proxy list. Useful in tests when you need to reload config between test cases.

```php
<?php
use Yohns\Security\ClientIP;

// After changing config in a test
ClientIP::resetCache();
$ip = ClientIP::get(); // Re-reads trusted_proxies from config
```

## Header Priority

When the connection comes from a trusted proxy, headers are checked in this order. The first header containing a valid public IP wins:

1. `CF-Connecting-IP` -- Cloudflare
2. `X-Forwarded-For` -- Standard proxy header (first public IP in the comma-separated list)
3. `X-Real-IP` -- Nginx
4. `X-Client-IP` -- Apache mod_remoteip
5. `X-Cluster-Client-IP` -- Cluster environments
6. `Forwarded` -- RFC 7239

Private and reserved IPs in forwarded headers are skipped. Only the first valid public IP is returned.

## How It Works Behind a Reverse Proxy

When your app sits behind Nginx or a load balancer:

```
Client (203.0.113.50) --> Nginx (127.0.0.1) --> PHP app
                          Sets X-Real-IP: 203.0.113.50
```

1. `REMOTE_ADDR` = `127.0.0.1`
2. `127.0.0.1` is in the trusted proxy list
3. `ClientIP` reads `X-Real-IP: 203.0.113.50`
4. `203.0.113.50` is a valid public IP
5. Returns `'203.0.113.50'`

## How It Works With a Direct Connection

When the client connects directly (no proxy):

```
Client (203.0.113.50) --> PHP app
                          Attacker sets X-Forwarded-For: 8.8.8.8
```

1. `REMOTE_ADDR` = `203.0.113.50`
2. `203.0.113.50` is NOT in the trusted proxy list
3. Forwarded headers are completely ignored
4. Returns `'203.0.113.50'`

## IPv6 CIDR Support

`ClientIP` handles IPv6 CIDR matching using `inet_pton()` with bitwise comparison. If your proxies use IPv6:

```php
'trusted_proxies' => [
	'::1',
	'2001:db8::/32',       // Your IPv6 proxy range
	'fd00::/8',            // Unique local addresses
],
```

## Classes That Use ClientIP

All of these call `ClientIP::get()` internally -- you never need to pass an IP address to them:

- `CSRFToken` -- tracks which IP generated each token
- `RateLimiter` -- rate limits by client IP
- `IPSecurity` -- whitelist/blacklist enforcement
- `SpamDetector` -- logs source IP of spam attempts
- `ContentValidator` -- associates validation results with IPs
- `TokenManager` -- tracks token creation/usage by IP
- `Honeypot` -- logs bot detection events by IP
- `SecurityManager` -- orchestrates all of the above

## Gotchas

- **Trusted proxy list replaces defaults.** If you set `ip_security.trusted_proxies` in config, the hardcoded private ranges are NOT merged in. Include them explicitly.
- **Cached per-request.** The trusted proxy list is loaded once and cached in a static property. If you modify config mid-request (unlikely in production, common in tests), call `ClientIP::resetCache()`.
- **Private IPs in forwarded headers are skipped.** If the real client is on a private network (e.g., `10.0.0.5`), `ClientIP::get()` will skip it and fall back to `REMOTE_ADDR`. This is by design -- the filter uses `FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE`.
- **Never read `$_SERVER['HTTP_X_FORWARDED_FOR']` directly.** Always use `ClientIP::get()`. Direct header reads bypass the trusted proxy gate and are vulnerable to spoofing.