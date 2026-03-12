# TokenManager

`Yohns\Security\TokenManager` -- API, verification, and reset token lifecycle management.

Generates, validates, expires, and revokes security tokens of various types. All tokens are stored via `FileStorage` (JSON files) with usage counting, expiration tracking, and IP logging via `ClientIP::get()`.

---

## Configuration

Values from `config/security.php` (under a `token_management` key if present):

| Key                                | Default  | Description                                      |
|------------------------------------|----------|--------------------------------------------------|
| `token_management.enabled`         | `true`   | Master switch for token operations                |
| `token_management.default_expiration` | `3600` | Default token lifetime in seconds (1 hour)        |
| `token_management.signing_secret`  | **none** | HMAC secret for `signToken()`/`verifyTokenSignature()` -- **REQUIRED**, no fallback |

**`signing_secret` has no default.** If you call `signToken()` or `verifyTokenSignature()` without configuring it, a `RuntimeException` is thrown.

---

## Built-in Token Types

| Type                 | Bytes | Hex Length | Expiration   | Max Uses  |
|----------------------|-------|------------|--------------|-----------|
| `api_access`         | 32    | 64 chars   | 30 days      | unlimited |
| `email_verification` | 32    | 64 chars   | 1 hour       | 1 (single use) |
| `password_reset`     | 32    | 64 chars   | 30 minutes   | 1 (single use) |
| `two_factor`         | 16    | 32 chars   | 5 minutes    | 1 (single use) |
| `session`            | 48    | 96 chars   | 24 hours     | unlimited |
| `file_upload`        | 24    | 48 chars   | 30 minutes   | 10        |
| `webhook`            | 40    | 80 chars   | 1 year       | unlimited |
| `temporary_access`   | 28    | 56 chars   | 15 minutes   | 3         |
| `default`            | 32    | 64 chars   | 1 hour       | unlimited |

Tokens are generated with `random_bytes()` and stored as hex via `bin2hex()`.

---

## Core Methods

### generateToken(string $type, array $data = [], int $expiresIn = null): string

Creates a token of the given type, stores it in FileStorage, and returns the raw token string. Throws `RuntimeException` if token management is disabled.

```php
$tm = new \Yohns\Security\TokenManager();

$token = $tm->generateToken('api_access', [
	'user_id'     => 42,
	'permissions' => ['read', 'write'],
], 86400 * 7); // 7 days

// $token => 'a3f8c1d9e7b2...' (64-char hex string)
// Stored with: type, data (JSON), expires_at, ip_address, usage_count=0, is_active=true
```

### validateToken(string $token, string $expectedType = null, bool $singleUse = false): array

Checks that a token exists, is active, is not expired, matches the expected type, and has not exceeded its usage limit. Increments usage count on success.

**Return keys:**

| Key              | Type         | Description                                         |
|------------------|--------------|-----------------------------------------------------|
| `is_valid`       | `bool`       | Whether the token passed all checks                  |
| `token_data`     | `array|null` | Decoded data from `generateToken()`'s `$data` param  |
| `error`          | `string`     | Reason for failure (empty on success)                 |
| `remaining_uses` | `int`        | Uses left (`-1` means unlimited)                     |

```php
$tm = new \Yohns\Security\TokenManager();

$result = $tm->validateToken($token, 'api_access');

if ($result['is_valid']) {
	$userId = $result['token_data']['user_id'];      // 42
	$perms  = $result['token_data']['permissions'];   // ['read', 'write']
	$left   = $result['remaining_uses'];              // -1 (unlimited)
} else {
	echo $result['error'];
	// Possible errors:
	// 'Token not found or inactive'
	// 'Token has expired'
	// 'Token type mismatch'
	// 'Token usage limit exceeded'
	// 'Token management is disabled'
}
```

---

## Convenience Generators

### generateAPIToken(int $userId, array $permissions = [], int $expiresIn = null): string

Creates an `api_access` token. Default expiration: 30 days.

```php
$tm = new \Yohns\Security\TokenManager();

$apiToken = $tm->generateAPIToken(42, ['users:read', 'posts:write'], 86400 * 90);

// Send to client
header('Content-Type: application/json');
echo json_encode([
	'token'      => $apiToken,
	'expires_in' => 86400 * 90,
	'token_type' => 'Bearer',
]);
```

### generateEmailVerificationToken(string $email, int $userId = null): string

Creates an `email_verification` token. Expires in 1 hour, single use.

```php
$tm = new \Yohns\Security\TokenManager();

$verifyToken = $tm->generateEmailVerificationToken('jane@example.com', 42);
$verifyUrl = 'https://myapp.com/verify-email?token=' . $verifyToken;

// Send email with $verifyUrl, then on the verification endpoint:
$result = $tm->validateToken($verifyToken, 'email_verification', true);

if ($result['is_valid']) {
	$email = $result['token_data']['email']; // 'jane@example.com'
	// Mark email as verified in your database
}
```

### generatePasswordResetToken(int $userId, string $email): string

Creates a `password_reset` token. Expires in 30 minutes, single use. **Automatically invalidates** any existing password reset tokens for the same user.

```php
$tm = new \Yohns\Security\TokenManager();

$resetToken = $tm->generatePasswordResetToken(42, 'jane@example.com');
$resetUrl = 'https://myapp.com/reset-password?token=' . $resetToken;

// On the reset form submission:
$result = $tm->validateToken($resetToken, 'password_reset', true);

if ($result['is_valid']) {
	$userId = $result['token_data']['user_id']; // 42
	// Update password in database
}
```

### generate2FAToken(int $userId): string

Creates a `two_factor` token. Expires in 5 minutes, single use.

```php
$tm = new \Yohns\Security\TokenManager();

$twoFA = $tm->generate2FAToken(42);
$_SESSION['pending_2fa_token'] = $twoFA;

// After user submits their 2FA code and you verify it:
$result = $tm->validateToken($twoFA, 'two_factor', true);

if ($result['is_valid']) {
	// Complete login
	$_SESSION['authenticated'] = true;
}
```

---

## Token Lifecycle

### deactivateToken(string $token): bool

Marks a token as inactive. Returns `false` if not found.

```php
$tm = new \Yohns\Security\TokenManager();

if ($tm->deactivateToken($suspiciousToken)) {
	echo 'Token revoked';
} else {
	echo 'Token not found';
}
```

### refreshToken(string $token, int $additionalTime = null): bool

Extends expiration from `time()` by the given seconds (or the token type's default expiration). Only works on active tokens.

```php
$tm = new \Yohns\Security\TokenManager();

// Extend session by 2 hours
$tm->refreshToken($sessionToken, 7200);

// Extend by the type's default (24 hours for session tokens)
$tm->refreshToken($sessionToken);
```

### revokeUserTokens(int $userId, string $type = null): int

Deactivates all active tokens for a user. Optionally filter by type.

```php
$tm = new \Yohns\Security\TokenManager();

// Compromised account -- revoke everything
$count = $tm->revokeUserTokens(42);
// $count => 7 (all tokens for user 42 deactivated)

// Revoke only API tokens
$count = $tm->revokeUserTokens(42, 'api_access');
// $count => 3
```

### cleanupExpiredTokens(): int

Deletes all expired tokens from storage. Run periodically.

```php
$tm = new \Yohns\Security\TokenManager();
$cleaned = $tm->cleanupExpiredTokens();
// $cleaned => 23 (expired tokens removed)
```

---

## Token Signing

### signToken(string $token, string $secret = null): string

Creates an HMAC-SHA256 signature. Uses `token_management.signing_secret` from config if `$secret` is null.

### verifyTokenSignature(string $token, string $signature, string $secret = null): bool

Verifies an HMAC-SHA256 signature using `hash_equals()` for timing-safe comparison.

**Both methods throw `RuntimeException` if no signing secret is available.**

```php
// config/security.php must include:
// 'token_management' => [
//     'signing_secret' => 'a-long-random-secret-at-least-32-chars',
// ],

$tm = new \Yohns\Security\TokenManager();

$token = $tm->generateAPIToken(42, ['read']);
$signature = $tm->signToken($token);

// Send both $token and $signature to the client.
// On subsequent requests, verify:
if ($tm->verifyTokenSignature($token, $signature)) {
	echo 'Signature valid -- token has not been tampered with';
}

// With an explicit secret (overrides config):
$sig = $tm->signToken($token, 'my-webhook-secret');
$ok  = $tm->verifyTokenSignature($token, $sig, 'my-webhook-secret');

// Without a configured secret and no explicit secret:
try {
	$tm->signToken($token);
} catch (\RuntimeException $e) {
	// 'Token signing secret is not configured. Set token_management.signing_secret in security config.'
}
```

---

## Export and Analytics

### exportTokens(array $filters = []): array

Exports token metadata for backup. The raw token value is hashed (SHA-256) before the `token` field is removed.

```php
$tm = new \Yohns\Security\TokenManager();

// Export only active API tokens
$exported = $tm->exportTokens(['type' => 'api_access', 'is_active' => true]);

// Each entry has 'token_hash' instead of 'token':
// [
//     [
//         'token_hash'  => 'a1b2c3d4...',
//         'type'        => 'api_access',
//         'data'        => '{"user_id":42,...}',
//         'expires_at'  => 1711900800,
//         'is_active'   => true,
//         'usage_count' => 5,
//         ...
//     ],
// ]

file_put_contents('tokens_backup.json', json_encode($exported, JSON_PRETTY_PRINT));
```

### getTokenStats(): array

Returns counts and breakdowns across all tokens and events.

```php
$tm = new \Yohns\Security\TokenManager();
$stats = $tm->getTokenStats();

// $stats = [
//     'total_tokens'   => 150,
//     'active_tokens'  => 42,
//     'expired_tokens' => 108,
//     'type_breakdown' => [
//         'api_access'         => 30,
//         'email_verification' => 50,
//         'password_reset'     => 20,
//         ...
//     ],
//     'recent_events'  => 15,   // last 24 hours
//     'usage_stats'    => [
//         'total_validations'  => 320,
//         'failed_validations' => 18,
//     ],
// ]
```

---

## Gotchas

1. **`signToken()` / `verifyTokenSignature()` throw `RuntimeException` if `signing_secret` is missing.**
   There is no hardcoded fallback secret. You must set `token_management.signing_secret` in `config/security.php` or pass an explicit `$secret` parameter.

2. **`exportTokens()` hashes the token before unsetting it.**
   The hash is computed as `hash('sha256', $token['token'])` before `unset($token['token'])`. An earlier bug hashed an empty string because the unset happened first -- this is now fixed.

3. **IP tracking uses `ClientIP::get()`.**
   Both `generateToken()` and `validateToken()` record the client IP via `ClientIP::get()`, which respects the trusted proxy gate. Raw `$_SERVER` headers are never read directly for IP.

4. **`generatePasswordResetToken()` auto-invalidates previous reset tokens.**
   Calling it for a user deactivates any existing `password_reset` tokens for that same `user_id` before creating a new one.

5. **Usage counting and single-use behavior.**
   `validateToken()` increments `usage_count` on every successful validation. If `max_usage` is set (e.g., 1 for single-use tokens), the token is deactivated once the count reaches the limit. Passing `singleUse=true` also deactivates after first use regardless of `max_usage`.

6. **Disabled token manager throws on `generateToken()`.**
   When `token_management.enabled` is `false`, `generateToken()` throws `RuntimeException`. However, `validateToken()` returns `['is_valid' => false, 'error' => 'Token management is disabled']` without throwing.

7. **Token storage is file-based.**
   All tokens live in the `database/` directory as JSON files via `FileStorage`. For high-traffic applications, consider the cleanup interval and call `cleanupExpiredTokens()` periodically to prevent file bloat.