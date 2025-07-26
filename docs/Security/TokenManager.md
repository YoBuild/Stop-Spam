# Yohns\Security\TokenManager

TokenManager class for managing various types of security tokens

Handles API tokens, session tokens, verification tokens, and more.
Provides comprehensive token lifecycle management including generation,
validation, expiration, and usage tracking.

Usage example:
```php
$tokenManager = new TokenManager();
// Generate API token
$apiToken = $tokenManager->generateAPIToken(123, ['read', 'write']);
// Validate token
$result = $tokenManager->validateToken($apiToken, 'api_access');
if ($result['is_valid']) {
    echo "Token is valid!";
}
```



## Methods

| Name | Description |
|------|-------------|
|[__construct](#tokenmanager__construct)|Constructor - Initialize token management system|
|[addTokenType](#tokenmanageraddtokentype)|Add custom token type|
|[batchGenerateTokens](#tokenmanagerbatchgeneratetokens)|Batch generate tokens|
|[checkTokenRateLimit](#tokenmanagerchecktokenratelimit)|Check token rate limiting|
|[cleanupExpiredTokens](#tokenmanagercleanupexpiredtokens)|Clean up expired tokens|
|[deactivateToken](#tokenmanagerdeactivatetoken)|Deactivate a token|
|[exportTokens](#tokenmanagerexporttokens)|Export tokens for backup|
|[generate2FAToken](#tokenmanagergenerate2fatoken)|Generate two-factor authentication token|
|[generateAPIToken](#tokenmanagergenerateapitoken)|Generate API token for user|
|[generateCustomToken](#tokenmanagergeneratecustomtoken)|Generate secure token with custom entropy|
|[generateEmailVerificationToken](#tokenmanagergenerateemailverificationtoken)|Generate email verification token|
|[generateOneTimeToken](#tokenmanagergenerateonetimetoken)|Generate one-time use token with callback|
|[generatePasswordResetToken](#tokenmanagergeneratepasswordresettoken)|Generate password reset token|
|[generateSessionToken](#tokenmanagergeneratesessiontoken)|Generate session token|
|[generateToken](#tokenmanagergeneratetoken)|Generate a new token|
|[generateUploadToken](#tokenmanagergenerateuploadtoken)|Generate file upload token|
|[getTokenAnalytics](#tokenmanagergettokenanalytics)|Get token usage analytics|
|[getTokenInfo](#tokenmanagergettokeninfo)|Get token information without validating|
|[getTokenStats](#tokenmanagergettokenstats)|Get token statistics|
|[getTokenTypes](#tokenmanagergettokentypes)|Get available token types|
|[getUserTokens](#tokenmanagergetusertokens)|Get tokens for user|
|[invalidateTokensByData](#tokenmanagerinvalidatetokensbydata)|Invalidate tokens by criteria|
|[isEnabled](#tokenmanagerisenabled)|Check if token management is enabled|
|[refreshToken](#tokenmanagerrefreshtoken)|Refresh token (extend expiration)|
|[revokeUserTokens](#tokenmanagerrevokeusertokens)|Revoke all tokens for a user|
|[signToken](#tokenmanagersigntoken)|Sign a token for additional security|
|[validateOneTimeToken](#tokenmanagervalidateonetimetoken)|Validate and consume one-time token|
|[validateToken](#tokenmanagervalidatetoken)|Validate a token|
|[verifyTokenSignature](#tokenmanagerverifytokensignature)|Verify token signature (for advanced security)|




### TokenManager::__construct

**Description**

```php
public __construct (void)
```

Constructor - Initialize token management system

Sets up token management with configuration from Config class
and initializes token type definitions and storage.

**Parameters**

`This function has no parameters.`

**Return Values**

`void`


**Throws Exceptions**


`\Exception`
> If FileStorage initialization fails

Usage example:
```php
$tokenManager = new TokenManager();
// Token management system is now ready
```

<hr />


### TokenManager::addTokenType

**Description**

```php
public addTokenType (string $type, array $config)
```

Add custom token type

Registers a new token type with custom configuration including
length, expiration, usage limits, and description.

**Parameters**

* `(string) $type`
: Token type name
* `(array) $config`
: Token type configuration

**Return Values**

`void`

>

Usage example:
```php
$tokenManager = new TokenManager();
$tokenManager->addTokenType('payment_authorization', [
    'length' => 48,
    'expiration' => 600, // 10 minutes
    'max_usage' => 1,
    'description' => 'Payment authorization token'
]);

// Now you can generate tokens of this type
$paymentToken = $tokenManager->generateToken('payment_authorization', $paymentData);
```


<hr />


### TokenManager::batchGenerateTokens

**Description**

```php
public batchGenerateTokens (string $type, int $count, array $baseData, int|null $expiresIn)
```

Batch generate tokens

Generates multiple tokens of the same type efficiently.
Useful for creating invitation codes or access tokens in bulk.

**Parameters**

* `(string) $type`
: Token type to generate
* `(int) $count`
: Number of tokens to generate
* `(array) $baseData`
: Base data to include in all tokens
* `(int|null) $expiresIn`
: Expiration time in seconds

**Return Values**

`array`

> Array of generated tokens

Usage example:
```php
$tokenManager = new TokenManager();
$inviteTokens = $tokenManager->batchGenerateTokens('invitation', 10, [
    'event_id' => 456,
    'role' => 'guest'
], 86400 * 7); // 7 days
foreach ($inviteTokens as $i => $token) {
    echo "Invitation " . ($i + 1) . ": " . $token . "\n";
}
```


<hr />


### TokenManager::checkTokenRateLimit

**Description**

```php
public checkTokenRateLimit (string $identifier, string $action)
```

Check token rate limiting

Verifies if token generation is allowed based on rate limiting rules
to prevent token abuse and brute force attacks.

**Parameters**

* `(string) $identifier`
: Identifier for rate limiting (IP, user ID, etc.)
* `(string) $action`
: Action being rate limited (default: 'token_generation')

**Return Values**

`bool`

> True if rate limit allows action, false if limited

Usage example:
```php
$tokenManager = new TokenManager();
$clientIP = $_SERVER['REMOTE_ADDR'];
if ($tokenManager->checkTokenRateLimit($clientIP, 'password_reset')) {
    $resetToken = $tokenManager->generatePasswordResetToken($userId, $email);
} else {
    echo "Rate limit exceeded. Please try again later.";
}
```


<hr />


### TokenManager::cleanupExpiredTokens

**Description**

```php
public cleanupExpiredTokens (void)
```

Clean up expired tokens

Removes all expired tokens from storage to prevent database bloat
and maintain performance. Logs cleanup statistics.

**Parameters**

`This function has no parameters.`

**Return Values**

`int`

> Number of expired tokens cleaned up

Usage example:
```php
$tokenManager = new TokenManager();
$cleaned = $tokenManager->cleanupExpiredTokens();
echo "Cleaned up {$cleaned} expired tokens";
// Run this periodically via cron job
```


<hr />


### TokenManager::deactivateToken

**Description**

```php
public deactivateToken (string $token)
```

Deactivate a token

Marks a token as inactive, preventing further use.
Logs the deactivation event for audit purposes.

**Parameters**

* `(string) $token`
: Token to deactivate

**Return Values**

`bool`

> True if token was deactivated, false if not found

Usage example:
```php
$tokenManager = new TokenManager();
if ($tokenManager->deactivateToken($suspiciousToken)) {
    echo "Token deactivated successfully";
} else {
    echo "Token not found";
}
```


<hr />


### TokenManager::exportTokens

**Description**

```php
public exportTokens (array $filters)
```

Export tokens for backup

Exports token metadata for backup purposes while excluding
actual token values for security.

**Parameters**

* `(array) $filters`
: Optional filters to apply to export

**Return Values**

`array`

> Exported token data with hashed tokens

Usage example:
```php
$tokenManager = new TokenManager();
// Export only API tokens
$apiTokens = $tokenManager->exportTokens(['type' => 'api_access']);
file_put_contents('api_tokens_backup.json', json_encode($apiTokens));

// Export all active tokens
$allTokens = $tokenManager->exportTokens(['is_active' => true]);
```


<hr />


### TokenManager::generate2FAToken

**Description**

```php
public generate2FAToken (int $userId)
```

Generate two-factor authentication token

Creates a short-lived token for two-factor authentication process.
Token expires after 5 minutes and is single-use.

**Parameters**

* `(int) $userId`
: User ID for 2FA process

**Return Values**

`string`

> Generated 2FA token

Usage example:
```php
$tokenManager = new TokenManager();
$twoFAToken = $tokenManager->generate2FAToken(123);
$_SESSION['2fa_token'] = $twoFAToken;
// Use token to verify second factor
```


<hr />


### TokenManager::generateAPIToken

**Description**

```php
public generateAPIToken (int $userId, array $permissions, int|null $expiresIn)
```

Generate API token for user

Creates a long-lived API access token for a user with specific permissions.
Typically used for programmatic access to APIs.

**Parameters**

* `(int) $userId`
: User ID to generate token for
* `(array) $permissions`
: Array of permissions for this token
* `(int|null) $expiresIn`
: Expiration time in seconds (default: 30 days)

**Return Values**

`string`

> Generated API token

Usage example:
```php
$tokenManager = new TokenManager();
$apiToken = $tokenManager->generateAPIToken(123, [
    'users:read', 'posts:write', 'comments:delete'
], 86400 * 90); // 90 days
echo "API Token: " . $apiToken;
```


<hr />


### TokenManager::generateCustomToken

**Description**

```php
public generateCustomToken (int $length, string|null $charset)
```

Generate secure token with custom entropy

Creates a secure random token with custom length and character set.
Useful for specific formatting requirements.

**Parameters**

* `(int) $length`
: Length of token to generate
* `(string|null) $charset`
: Custom character set (null uses alphanumeric)

**Return Values**

`string`

> Generated custom token

Usage example:
```php
$tokenManager = new TokenManager();
// Generate numeric-only token
$numericToken = $tokenManager->generateCustomToken(8, '0123456789');
echo "Verification code: " . $numericToken;

// Generate URL-safe token
$urlSafeToken = $tokenManager->generateCustomToken(16, 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_');
```


<hr />


### TokenManager::generateEmailVerificationToken

**Description**

```php
public generateEmailVerificationToken (string $email, int|null $userId)
```

Generate email verification token

Creates a single-use token for email address verification.
Token expires after 1 hour and can only be used once.

**Parameters**

* `(string) $email`
: Email address to verify
* `(int|null) $userId`
: User ID (optional)

**Return Values**

`string`

> Generated email verification token

Usage example:
```php
$tokenManager = new TokenManager();
$verifyToken = $tokenManager->generateEmailVerificationToken('user@example.com', 123);
$verifyUrl = "https://example.com/verify?token=" . $verifyToken;
// Send verification email with $verifyUrl
```


<hr />


### TokenManager::generateOneTimeToken

**Description**

```php
public generateOneTimeToken (string $action, array $data, int $expiresIn)
```

Generate one-time use token with callback

Creates a token that can only be used once for a specific action.
Automatically deactivated after first use.

**Parameters**

* `(string) $action`
: Action this token authorizes
* `(array) $data`
: Additional data to store with token
* `(int) $expiresIn`
: Expiration time in seconds (default: 1 hour)

**Return Values**

`string`

> Generated one-time token

Usage example:
```php
$tokenManager = new TokenManager();
$deleteToken = $tokenManager->generateOneTimeToken('delete_account', [
    'user_id' => 123,
    'confirmation_required' => true
], 1800);
echo "One-time delete token: " . $deleteToken;
```


<hr />


### TokenManager::generatePasswordResetToken

**Description**

```php
public generatePasswordResetToken (int $userId, string $email)
```

Generate password reset token

Creates a single-use token for password reset functionality.
Invalidates any existing password reset tokens for the user.

**Parameters**

* `(int) $userId`
: User ID requesting password reset
* `(string) $email`
: User's email address

**Return Values**

`string`

> Generated password reset token

Usage example:
```php
$tokenManager = new TokenManager();
$resetToken = $tokenManager->generatePasswordResetToken(123, 'user@example.com');
$resetUrl = "https://example.com/reset-password?token=" . $resetToken;
// Send password reset email with $resetUrl
```


<hr />


### TokenManager::generateSessionToken

**Description**

```php
public generateSessionToken (int $userId, array $sessionData)
```

Generate session token

Creates a token for session management with configurable lifetime.
Used to maintain user sessions across requests.

**Parameters**

* `(int) $userId`
: User ID for the session
* `(array) $sessionData`
: Additional session data to store

**Return Values**

`string`

> Generated session token

Usage example:
```php
$tokenManager = new TokenManager();
$sessionToken = $tokenManager->generateSessionToken(123, [
    'role' => 'admin',
    'login_time' => time(),
    'ip_address' => $_SERVER['REMOTE_ADDR']
]);
setcookie('session_token', $sessionToken, time() + 86400);
```


<hr />


### TokenManager::generateToken

**Description**

```php
public generateToken (string $type, array $data, int|null $expiresIn)
```

Generate a new token

Creates a new security token of the specified type with associated data
and expiration. Stores token securely and logs the generation event.

**Parameters**

* `(string) $type`
: Token type (e.g., 'api_access', 'email_verification')
* `(array) $data`
: Associated data to store with token
* `(int|null) $expiresIn`
: Expiration time in seconds (null uses type default)

**Return Values**

`string`

> Generated token string


**Throws Exceptions**


`\RuntimeException`
> If token management is disabled

Usage example:
```php
$tokenManager = new TokenManager();
$token = $tokenManager->generateToken('api_access', [
    'user_id' => 123,
    'permissions' => ['read', 'write']
], 86400);
echo "Generated token: " . $token;
```

<hr />


### TokenManager::generateUploadToken

**Description**

```php
public generateUploadToken (array $uploadConfig)
```

Generate file upload token

Creates a token for secure file upload with specific constraints
like file size limits and allowed types.

**Parameters**

* `(array) $uploadConfig`
: Upload configuration (max_size, allowed_types, path)

**Return Values**

`string`

> Generated upload token

Usage example:
```php
$tokenManager = new TokenManager();
$uploadToken = $tokenManager->generateUploadToken([
    'max_size' => 5242880, // 5MB
    'allowed_types' => ['image/jpeg', 'image/png', 'application/pdf'],
    'path' => '/uploads/documents'
]);
echo "Upload token: " . $uploadToken;
```


<hr />


### TokenManager::getTokenAnalytics

**Description**

```php
public getTokenAnalytics (int $days)
```

Get token usage analytics

Returns detailed analytics about token usage patterns, events,
and error rates over a specified time period.

**Parameters**

* `(int) $days`
: Number of days to analyze (default: 30)

**Return Values**

`array`

> Analytics data with usage patterns and error rates

Usage example:
```php
$tokenManager = new TokenManager();
$analytics = $tokenManager->getTokenAnalytics(7); // Last 7 days

echo "Total events: " . $analytics['total_events'];
echo "Error rate: " . $analytics['error_rate'] . "%";
foreach ($analytics['event_types'] as $type => $count) {
    echo "Event {$type}: {$count} times";
}
foreach ($analytics['daily_breakdown'] as $date => $count) {
    echo "Date {$date}: {$count} events";
}
```


<hr />


### TokenManager::getTokenInfo

**Description**

```php
public getTokenInfo (string $token)
```

Get token information without validating

Retrieves token metadata and configuration without performing
validation or updating usage counts.

**Parameters**

* `(string) $token`
: Token to get information for

**Return Values**

`array|null`

> Token information or null if not found

Usage example:
```php
$tokenManager = new TokenManager();
$info = $tokenManager->getTokenInfo($userToken);
if ($info) {
    echo "Token type: " . $info['type'];
    echo "Expires at: " . date('Y-m-d H:i:s', $info['expires_at']);
    echo "Usage count: " . $info['usage_count'];
}
```


<hr />


### TokenManager::getTokenStats

**Description**

```php
public getTokenStats (void)
```

Get token statistics

Returns comprehensive statistics about token usage including
counts, types breakdown, and validation metrics.

**Parameters**

`This function has no parameters.`

**Return Values**

`array`

> Token statistics with counts, breakdowns, and usage data

Usage example:
```php
$tokenManager = new TokenManager();
$stats = $tokenManager->getTokenStats();
echo "Active tokens: " . $stats['active_tokens'];
echo "Total validations: " . $stats['usage_stats']['total_validations'];
foreach ($stats['type_breakdown'] as $type => $count) {
    echo "Type {$type}: {$count} tokens";
}
```


<hr />


### TokenManager::getTokenTypes

**Description**

```php
public getTokenTypes (void)
```

Get available token types

Returns a list of all configured token types that can be
generated by the token manager.

**Parameters**

`This function has no parameters.`

**Return Values**

`array`

> Array of available token type names

Usage example:
```php
$tokenManager = new TokenManager();
$types = $tokenManager->getTokenTypes();
foreach ($types as $type) {
    echo "Available token type: " . $type . "\n";
}
// Outputs: api_access, email_verification, password_reset, etc.
```


<hr />


### TokenManager::getUserTokens

**Description**

```php
public getUserTokens (int $userId, string|null $type)
```

Get tokens for user

Retrieves all active tokens for a specific user, optionally
filtered by token type.

**Parameters**

* `(int) $userId`
: User ID to get tokens for
* `(string|null) $type`
: Optional token type filter

**Return Values**

`array`

> Array of user's tokens with metadata

Usage example:
```php
$tokenManager = new TokenManager();
$userTokens = $tokenManager->getUserTokens(123, 'api_access');
foreach ($userTokens as $token) {
    echo "API token created: " . date('Y-m-d', $token['created_at']);
    echo "Usage count: " . $token['usage_count'];
}
```


<hr />


### TokenManager::invalidateTokensByData

**Description**

```php
public invalidateTokensByData (array $criteria, string|null $type)
```

Invalidate tokens by criteria

Deactivates multiple tokens that match specific data criteria.
Useful for bulk operations like revoking all tokens for a user.

**Parameters**

* `(array) $criteria`
: Key-value pairs to match in token data
* `(string|null) $type`
: Optional token type filter

**Return Values**

`int`

> Number of tokens invalidated

Usage example:
```php
$tokenManager = new TokenManager();
// Revoke all API tokens for user 123
$revoked = $tokenManager->invalidateTokensByData(['user_id' => 123], 'api_access');
echo "Revoked {$revoked} API tokens";
```


<hr />


### TokenManager::isEnabled

**Description**

```php
public isEnabled (void)
```

Check if token management is enabled

Returns the current enabled status of the token management system
based on configuration settings.

**Parameters**

`This function has no parameters.`

**Return Values**

`bool`

> True if token management is enabled, false otherwise

Usage example:
```php
$tokenManager = new TokenManager();
if ($tokenManager->isEnabled()) {
    $token = $tokenManager->generateToken('api_access', $data);
} else {
    echo "Token management is disabled";
}
```


<hr />


### TokenManager::refreshToken

**Description**

```php
public refreshToken (string $token, int|null $additionalTime)
```

Refresh token (extend expiration)

Extends the expiration time of an active token by the specified
additional time or the token type's default expiration.

**Parameters**

* `(string) $token`
: Token to refresh
* `(int|null) $additionalTime`
: Additional time in seconds (null uses type default)

**Return Values**

`bool`

> True if token was refreshed, false if not found

Usage example:
```php
$tokenManager = new TokenManager();
if ($tokenManager->refreshToken($sessionToken, 3600)) {
    echo "Session extended by 1 hour";
}
```


<hr />


### TokenManager::revokeUserTokens

**Description**

```php
public revokeUserTokens (int $userId, string|null $type)
```

Revoke all tokens for a user

Deactivates all active tokens for a specific user, optionally
filtered by token type. Useful for security incidents.

**Parameters**

* `(int) $userId`
: User ID to revoke tokens for
* `(string|null) $type`
: Optional token type filter

**Return Values**

`int`

> Number of tokens revoked

Usage example:
```php
$tokenManager = new TokenManager();
// Revoke all tokens for compromised user
$revoked = $tokenManager->revokeUserTokens(123);
echo "Revoked {$revoked} tokens for user";

// Revoke only API tokens
$apiRevoked = $tokenManager->revokeUserTokens(123, 'api_access');
```


<hr />


### TokenManager::signToken

**Description**

```php
public signToken (string $token, string|null $secret)
```

Sign a token for additional security

Creates an HMAC signature for a token using a secret key.
Provides tamper detection for tokens transmitted over insecure channels.

**Parameters**

* `(string) $token`
: Token to sign
* `(string|null) $secret`
: Secret key (null uses config default)

**Return Values**

`string`

> HMAC signature for the token

Usage example:
```php
$tokenManager = new TokenManager();
$token = "abc123def456";
$signature = $tokenManager->signToken($token);

// Send both token and signature to client
echo "Token: " . $token;
echo "Signature: " . $signature;
```


<hr />


### TokenManager::validateOneTimeToken

**Description**

```php
public validateOneTimeToken (string $token, string $expectedAction)
```

Validate and consume one-time token

Validates a one-time token for a specific action and automatically
deactivates it after successful validation.

**Parameters**

* `(string) $token`
: Token to validate and consume
* `(string) $expectedAction`
: Expected action for this token

**Return Values**

`array`

> Validation result with action verification

Usage example:
```php
$tokenManager = new TokenManager();
$result = $tokenManager->validateOneTimeToken($deleteToken, 'delete_account');
if ($result['is_valid']) {
    $userId = $result['token_data']['user_id'];
    // Proceed with account deletion
}
```


<hr />


### TokenManager::validateToken

**Description**

```php
public validateToken (string $token, string|null $expectedType, bool $singleUse)
```

Validate a token

Checks if a token is valid, not expired, and matches expected type.
Updates usage count and handles single-use token deactivation.

**Parameters**

* `(string) $token`
: Token to validate
* `(string|null) $expectedType`
: Expected token type (null accepts any)
* `(bool) $singleUse`
: Whether to deactivate token after validation

**Return Values**

`array`

> Validation result with validity, data, error, and remaining uses

Usage example:
```php
$tokenManager = new TokenManager();
$result = $tokenManager->validateToken($userToken, 'email_verification', true);
if ($result['is_valid']) {
    $userData = $result['token_data'];
    echo "Email verified for: " . $userData['email'];
} else {
    echo "Validation failed: " . $result['error'];
}
```


<hr />


### TokenManager::verifyTokenSignature

**Description**

```php
public verifyTokenSignature (string $token, string $signature, string|null $secret)
```

Verify token signature (for advanced security)

Verifies that a token signature matches the expected HMAC signature
for additional security in high-security environments.

**Parameters**

* `(string) $token`
: Token to verify
* `(string) $signature`
: HMAC signature to verify
* `(string|null) $secret`
: Secret key (null uses config default)

**Return Values**

`bool`

> True if signature is valid, false otherwise

Usage example:
```php
$tokenManager = new TokenManager();
$token = "abc123def456";
$signature = "provided_signature_from_client";

if ($tokenManager->verifyTokenSignature($token, $signature)) {
    echo "Token signature is valid";
} else {
    echo "Invalid token signature";
}
```


<hr />
