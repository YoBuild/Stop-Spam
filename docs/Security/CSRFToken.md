# Yohns\Security\CSRFToken

CSRFToken class for Cross-Site Request Forgery protection

Provides secure token generation and validation to prevent CSRF attacks.
Supports multiple storage backends and provides flexible integration options.

Usage example:
```php
$csrf = new CSRFToken();
// In your form:
echo $csrf->getHiddenField('contact_form');
echo $csrf->getMetaTag('contact_form');

// In your form handler:
if (!$csrf->validateRequest('contact_form')) {
    die('CSRF token validation failed');
}
```


## Methods

| Name | Description |
|------|-------------|
|[__construct](#csrftoken__construct)|Constructor - Initialize CSRF protection with configuration|
|[cleanupExpiredTokens](#csrftokencleanupexpiredtokens)|Clean up expired tokens|
|[generateToken](#csrftokengeneratetoken)|Generate a new CSRF token|
|[getHiddenField](#csrftokengethiddenfield)|Generate HTML hidden input field for forms|
|[getMetaTag](#csrftokengetmetatag)|Generate meta tag for JavaScript access|
|[getStats](#csrftokengetstats)|Get token statistics|
|[getTokenFromRequest](#csrftokengettokenfromrequest)|Get token from various sources (POST, GET, headers)|
|[invalidateToken](#csrftokeninvalidatetoken)|Invalidate a token|
|[isEnabled](#csrftokenisenabled)|Check if CSRF protection is enabled|
|[regenerateToken](#csrftokenregeneratetoken)|Regenerate token (for enhanced security)|
|[validateRequest](#csrftokenvalidaterequest)|Validate token from request|
|[validateToken](#csrftokenvalidatetoken)|Validate a CSRF token|




### CSRFToken::__construct

**Description**

```php
public __construct (void)
```

Constructor - Initialize CSRF protection with configuration

Sets up CSRF protection system with configuration from Config class.
Starts session if not already active and configures token parameters.

**Parameters**

`This function has no parameters.`

**Return Values**

`void`


**Throws Exceptions**


`\Exception`
> If FileStorage initialization fails

Usage example:
```php
$csrf = new CSRFToken();
// CSRF protection is now ready to use
```

<hr />


### CSRFToken::cleanupExpiredTokens

**Description**

```php
public cleanupExpiredTokens (void)
```

Clean up expired tokens

Removes expired tokens from both session and file storage to prevent
storage bloat and maintain performance.

**Parameters**

`This function has no parameters.`

**Return Values**

`int`

> Number of tokens cleaned up

Usage example:
```php
$csrf = new CSRFToken();
$cleaned = $csrf->cleanupExpiredTokens();
echo "Cleaned up {$cleaned} expired tokens";
// Run this periodically via cron job
```


<hr />


### CSRFToken::generateToken

**Description**

```php
public generateToken (string $context)
```

Generate a new CSRF token

Creates a cryptographically secure token for the specified context.
Stores token in session, file storage, and optionally sets a cookie.

**Parameters**

* `(string) $context`
: Context identifier for the token (default: 'default')

**Return Values**

`string`

> Generated CSRF token or empty string if disabled

Usage example:
```php
$csrf = new CSRFToken();
$token = $csrf->generateToken('user_profile');
echo "Generated token: " . $token;
// Use this token in your forms or AJAX requests
```


<hr />


### CSRFToken::getHiddenField

**Description**

```php
public getHiddenField (string $context)
```

Generate HTML hidden input field for forms

Creates a hidden input field containing a CSRF token for the specified context.
This should be included in all forms that modify server state.

**Parameters**

* `(string) $context`
: Context identifier for the token

**Return Values**

`string`

> HTML hidden input element or empty string if disabled

Usage example:
```php
$csrf = new CSRFToken();
echo '<form method="post">';
echo $csrf->getHiddenField('user_settings');
echo '<input type="text" name="username">';
echo '<button type="submit">Save</button>';
echo '</form>';
```


<hr />


### CSRFToken::getMetaTag

**Description**

```php
public getMetaTag (string $context)
```

Generate meta tag for JavaScript access

Creates a meta tag containing CSRF token for JavaScript/AJAX requests.
Place this in your HTML head section for frontend access.

**Parameters**

* `(string) $context`
: Context identifier for the token

**Return Values**

`string`

> HTML meta tag or empty string if disabled

Usage example:
```php
$csrf = new CSRFToken();
echo '<head>';
echo $csrf->getMetaTag('api_calls');
echo '</head>';
// In JavaScript: document.querySelector('meta[name="csrf-token"]').content
```


<hr />


### CSRFToken::getStats

**Description**

```php
public getStats (void)
```

Get token statistics

Returns comprehensive statistics about CSRF tokens including
total count, active/expired breakdown, and context distribution.

**Parameters**

`This function has no parameters.`

**Return Values**

`array`

> Statistics array with 'total', 'active', 'expired', 'contexts' keys

Usage example:
```php
$csrf = new CSRFToken();
$stats = $csrf->getStats();
echo "Total tokens: " . $stats['total'];
echo "Active tokens: " . $stats['active'];
echo "Expired tokens: " . $stats['expired'];
print_r($stats['contexts']);
```


<hr />


### CSRFToken::getTokenFromRequest

**Description**

```php
public getTokenFromRequest (string $context)
```

Get token from various sources (POST, GET, headers)

Attempts to retrieve CSRF token from POST data, GET parameters,
or HTTP headers in that order of priority.

**Parameters**

* `(string) $context`
: Context identifier (currently unused but for future compatibility)

**Return Values**

`string|null`

> Found token or null if not found

Usage example:
```php
$csrf = new CSRFToken();
$token = $csrf->getTokenFromRequest();
if ($token) {
    echo "Found token: " . $token;
} else {
    echo "No CSRF token found in request";
}
```


<hr />


### CSRFToken::invalidateToken

**Description**

```php
public invalidateToken (string $context)
```

Invalidate a token

Removes token from session, file storage, and clears associated cookie.
Use this when you want to force token regeneration.

**Parameters**

* `(string) $context`
: Context of token to invalidate

**Return Values**

`void`

>

Usage example:
```php
$csrf = new CSRFToken();
// After successful form submission or security event
$csrf->invalidateToken('user_profile');
echo "Token invalidated, new token required";
```


<hr />


### CSRFToken::isEnabled

**Description**

```php
public isEnabled (void)
```

Check if CSRF protection is enabled

Returns the current enabled status of the CSRF protection system
based on configuration settings.

**Parameters**

`This function has no parameters.`

**Return Values**

`bool`

> True if CSRF protection is enabled, false otherwise

Usage example:
```php
$csrf = new CSRFToken();
if ($csrf->isEnabled()) {
    echo $csrf->getHiddenField();
} else {
    echo "CSRF protection is disabled";
}
```


<hr />


### CSRFToken::regenerateToken

**Description**

```php
public regenerateToken (string $context)
```

Regenerate token (for enhanced security)

Invalidates the current token and generates a new one for the context.
Useful for enhanced security after sensitive operations.

**Parameters**

* `(string) $context`
: Context to regenerate token for

**Return Values**

`string`

> Newly generated CSRF token

Usage example:
```php
$csrf = new CSRFToken();
// After password change or other sensitive operation
$newToken = $csrf->regenerateToken('user_profile');
echo "New token generated: " . $newToken;
```


<hr />


### CSRFToken::validateRequest

**Description**

```php
public validateRequest (string $context)
```

Validate token from request

Convenience method that extracts token from the current request
and validates it for the specified context.

**Parameters**

* `(string) $context`
: Context to validate token against

**Return Values**

`bool`

> True if request contains valid CSRF token, false otherwise

Usage example:
```php
$csrf = new CSRFToken();
if ($csrf->validateRequest('contact_form')) {
    // Process the form submission
    processContactForm($_POST);
} else {
    http_response_code(403);
    die('CSRF validation failed');
}
```


<hr />


### CSRFToken::validateToken

**Description**

```php
public validateToken (string $token, string $context)
```

Validate a CSRF token

Checks if the provided token is valid for the given context.
Verifies token existence, expiration, and context match.

**Parameters**

* `(string) $token`
: Token to validate
* `(string) $context`
: Context the token should be valid for

**Return Values**

`bool`

> True if token is valid, false otherwise

Usage example:
```php
$csrf = new CSRFToken();
$isValid = $csrf->validateToken($_POST['csrf_token'], 'user_profile');
if ($isValid) {
    // Process form submission
} else {
    // Handle invalid token
}
```


<hr />
