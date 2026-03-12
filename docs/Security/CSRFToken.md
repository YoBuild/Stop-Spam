# CSRFToken

**Class:** `Yohns\Security\CSRFToken`
**File:** `Yohns/Security/CSRFToken.php`

CSRF protection with triple storage: session, JSON file (for stateless apps), and cookie (for JavaScript access). Tokens are generated with `random_bytes()` and validated with `hash_equals()` for timing-safe comparison.

## Config

All values come from the `csrf` section of `config/security.php`:

| Key              | Default          | Description                                      |
|------------------|------------------|--------------------------------------------------|
| `enabled`        | `true`           | Master switch. When `false`, `generateToken()` returns `''` and `validateToken()` returns `true`. |
| `expiration`     | `1800`           | Token lifetime in seconds (30 minutes).          |
| `session_prefix` | `'csrf_token_'`  | Prefix for session keys (`csrf_token_contact_form`). |
| `header_name`    | `'X-CSRF-TOKEN'` | HTTP header name for AJAX token submission.      |
| `cookie_name`    | `'XSRF-TOKEN'`   | Cookie name set for JavaScript access.           |
| `same_site`      | `'Lax'`          | Cookie SameSite attribute (`Lax`, `Strict`, or `None`). |
| `token_length`   | `32`             | Bytes passed to `random_bytes()`. Output is hex-encoded, so the token string is 64 characters. |

```php
// config/security.php
'csrf' => [
	'enabled'        => true,
	'expiration'     => 1800,
	'session_prefix' => 'csrf_token_',
	'header_name'    => 'X-CSRF-TOKEN',
	'cookie_name'    => 'XSRF-TOKEN',
	'same_site'      => 'Lax',
	'token_length'   => 32,
],
```

## Basic Usage: HTML Form

```php
<?php
use Yohns\Security\CSRFToken;

$csrf = new CSRFToken();
?>
<form method="post" action="/settings/save">
	<?= $csrf->getHiddenField('settings_form') ?>
	<input type="text" name="display_name" value="Jane">
	<button type="submit">Save</button>
</form>
```

This outputs:

```html
<input type="hidden" name="csrf_token" value="a1b2c3d4e5f6...">
```

### Validating the Submission

```php
<?php
use Yohns\Security\CSRFToken;

$csrf = new CSRFToken();

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
	if (!$csrf->validateRequest('settings_form')) {
		http_response_code(403);
		die('CSRF validation failed.');
	}

	// Token is valid -- process the form
	$displayName = $_POST['display_name'];
	saveSettings($displayName);

	// Invalidate the used token so it can't be replayed
	$csrf->invalidateToken('settings_form');
}
```

## AJAX Setup

Place a meta tag in your HTML `<head>`:

```php
<head>
	<?= $csrf->getMetaTag('api_calls') ?>
</head>
```

This outputs:

```html
<meta name="csrf-token" content="a1b2c3d4e5f6...">
```

Then in JavaScript, read the token and send it as a header:

```javascript
const token = document.querySelector('meta[name="csrf-token"]').content;

fetch('/api/update-profile', {
	method: 'POST',
	headers: {
		'Content-Type': 'application/json',
		'X-CSRF-TOKEN': token
	},
	body: JSON.stringify({ name: 'Jane' })
});
```

The server-side handler:

```php
<?php
use Yohns\Security\CSRFToken;

$csrf = new CSRFToken();

// validateRequest() checks POST body first, then the X-CSRF-TOKEN header
if (!$csrf->validateRequest('api_calls')) {
	http_response_code(403);
	echo json_encode(['error' => 'Invalid CSRF token']);
	exit;
}

// Process the API request
$data = json_decode(file_get_contents('php://input'), true);
```

## Methods

### `generateToken(string $context = 'default'): string`

Creates a new token and stores it in session, file storage, and cookie. Returns the hex-encoded token string (64 characters with default `token_length` of 32). Returns `''` if CSRF is disabled.

```php
$token = $csrf->generateToken('checkout_form');
// '3f8a1b2c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a'
```

### `validateToken(string $token, string $context = 'default'): bool`

Validates a token against session storage first, then file storage. Uses `hash_equals()` to prevent timing attacks. Returns `true` if CSRF is disabled.

```php
$isValid = $csrf->validateToken($_POST['csrf_token'], 'checkout_form');
// true or false
```

### `validateRequest(string $context = 'default'): bool`

Extracts the token from the current request (POST body `csrf_token` field, then `X-CSRF-TOKEN` header) and validates it. Convenience wrapper around `getTokenFromRequest()` + `validateToken()`.

```php
if ($csrf->validateRequest('checkout_form')) {
	// Process form
}
```

### `getTokenFromRequest(string $context = 'default'): ?string`

Returns the token found in the request, or `null`. Checks in order:
1. `$_POST['csrf_token']`
2. `X-CSRF-TOKEN` header (via `getallheaders()`)
3. `$_SERVER['HTTP_X_CSRF_TOKEN']` (fallback)

```php
$token = $csrf->getTokenFromRequest();
// 'a1b2c3...' or null
```

### `getHiddenField(string $context = 'default'): string`

Generates a token and returns it wrapped in an HTML hidden input. Calls `generateToken()` internally.

```php
echo $csrf->getHiddenField('login_form');
// <input type="hidden" name="csrf_token" value="a1b2c3...">
```

### `getMetaTag(string $context = 'default'): string`

Generates a token and returns it in a meta tag for JavaScript access. Calls `generateToken()` internally.

```php
echo $csrf->getMetaTag('api_calls');
// <meta name="csrf-token" content="a1b2c3...">
```

### `invalidateToken(string $context = 'default'): void`

Removes the token from session, deletes all matching tokens from file storage, and clears the cookie.

```php
$csrf->invalidateToken('checkout_form');
```

### `regenerateToken(string $context = 'default'): string`

Invalidates the current token and generates a new one. Use after sensitive operations like password changes.

```php
$newToken = $csrf->regenerateToken('account_settings');
// Old token is now invalid, $newToken is the replacement
```

### `cleanupExpiredTokens(): int`

Removes expired tokens from file storage and session. Returns the count of file-stored tokens deleted.

```php
$cleaned = $csrf->cleanupExpiredTokens();
// 12 (number of expired tokens removed from file storage)
```

### `getStats(): array`

Returns token statistics from file storage.

```php
$stats = $csrf->getStats();
// [
//     'total'    => 45,
//     'active'   => 38,
//     'expired'  => 7,
//     'contexts' => [
//         'login_form'    => 20,
//         'settings_form' => 15,
//         'api_calls'     => 10,
//     ],
// ]
```

### `isEnabled(): bool`

Returns whether CSRF protection is enabled.

```php
if ($csrf->isEnabled()) {
	echo $csrf->getHiddenField('my_form');
}
```

## Token Storage Details

Each generated token is stored in three places:

| Storage       | Purpose                            | Access                              |
|---------------|------------------------------------|-------------------------------------|
| **Session**   | Primary validation (fastest)       | `$_SESSION['csrf_token_<context>']` |
| **FileStorage** | Stateless app support (no session) | `csrf_tokens` table in JSON file    |
| **Cookie**    | JavaScript access for AJAX         | `XSRF-TOKEN` cookie, `httponly=false` |

The cookie is intentionally **not httponly** so JavaScript can read it. The cookie value alone cannot be used to bypass CSRF protection -- the token must also be submitted in the POST body or header, which a cross-origin attacker cannot do.

## Security Design Decisions

**Timing-safe comparison.** `validateToken()` uses `hash_equals()` instead of `===`. A naive string comparison leaks timing information: an attacker can guess the token one character at a time by measuring response times.

**No GET parameter tokens.** Tokens are only accepted via `$_POST['csrf_token']` or the `X-CSRF-TOKEN` header. GET parameters were intentionally excluded because URLs leak in:
- Server access logs
- Browser history
- Referer headers sent to external sites
- Proxy logs

**IP tracking.** Each token records the client IP (via `ClientIP::get()`) in file storage. This is for audit purposes -- IP mismatch does not cause validation failure (that would break users whose IP changes mid-session).

## Gotchas

- **`getHiddenField()` and `getMetaTag()` both call `generateToken()`.** If you call both for the same context, you get two different tokens. Only the second one will be valid in the session (the first is overwritten). Use different contexts, or call `generateToken()` once and build your own HTML.
- **Session must be started.** The constructor calls `session_start()` if no session is active. If your framework manages sessions differently, make sure one is started before constructing `CSRFToken`.
- **Cookie only set if headers not sent.** If you construct `CSRFToken` and generate a token after output has started, the cookie won't be set. The session and file storage will still work.
- **Disabled mode is permissive.** When `enabled=false`, `generateToken()` returns `''` and `validateToken()` returns `true`. This means all requests pass validation. Only disable for development/testing.