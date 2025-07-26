# Yohns\Security\SecurityManager

SecurityManager class - Main security coordination class

Coordinates all security components for comprehensive protection.
Provides a unified interface for CSRF protection, rate limiting,
honeypot anti-spam, content validation, and security monitoring.


Usage example:
```php
$security = new SecurityManager($userId);

// Initialize form security
$formSecurity = $security->initializeForm('contact_form');
echo $formSecurity['csrf_field'];
echo $formSecurity['honeypot_field'];

// Validate form submission
$securityCheck = $security->securityCheck('contact', $_POST, true, 0.5, 'contact_form');
if (!$securityCheck['passed']) {
    die('Security validation failed: ' . $securityCheck['reason']);
}
```


## Methods

| Name | Description |
|------|-------------|
|[__construct](#securitymanager__construct)|Constructor - Initialize security manager with all components|
|[applySecurityHeaders](#securitymanagerapplysecurityheaders)|Apply security headers to current response|
|[checkIPSecurity](#securitymanagercheckipsecurity)|Check if IP is blocked or suspicious|
|[generateAPIToken](#securitymanagergenerateapitoken)|Generate security token for API access|
|[getCSRFToken](#securitymanagergetcsrftoken)|Get individual security components|
|[getHoneypot](#securitymanagergethoneypot)|Get honeypot component|
|[getRateLimiter](#securitymanagergetratelimiter)|Get rate limiter component|
|[getSecurityHeaders](#securitymanagergetsecurityheaders)|Get security headers for responses|
|[getSecurityStats](#securitymanagergetsecuritystats)|Get comprehensive security statistics|
|[getSpamDetector](#securitymanagergetspamdetector)|Get spam detector component|
|[getStorage](#securitymanagergetstorage)|Get file storage component|
|[initializeForm](#securitymanagerinitializeform)|Initialize security for a form|
|[logSecurityEvent](#securitymanagerlogsecurityevent)|Log security event|
|[performMaintenance](#securitymanagerperformmaintenance)|Perform security maintenance|
|[securityCheck](#securitymanagersecuritycheck)|Comprehensive security check for form submissions|
|[validateAPIToken](#securitymanagervalidateapitoken)|Validate API token|
|[validateContent](#securitymanagervalidatecontent)|Validate and clean content|




### SecurityManager::__construct

**Description**

```php
public __construct (int|null $userId)
```

Constructor - Initialize security manager with all components

Sets up all security components including CSRF protection, rate limiting,
honeypot, spam detection, and file storage with optional user context.

**Parameters**

* `(int|null) $userId`
: Current user ID for context-aware security (optional)

Usage example:
```php
// For logged-in user
$security = new SecurityManager(123);

// For anonymous user
$security = new SecurityManager();
```

**Return Values**

`void`


<hr />


### SecurityManager::applySecurityHeaders

**Description**

```php
public applySecurityHeaders (void)
```

Apply security headers to current response

Automatically sends all security headers to the browser for the current
HTTP response to enhance security posture.

**Parameters**

`This function has no parameters.`

**Return Values**

`void`

>

Usage example:
```php
$security = new SecurityManager();

// Apply security headers before any output
$security->applySecurityHeaders();

// Now output content
echo '<html><head><title>Secure Page</title></head>';
echo '<body>Content with security headers applied</body></html>';
```


<hr />


### SecurityManager::checkIPSecurity

**Description**

```php
public checkIPSecurity (string|null $ipAddress)
```

Check if IP is blocked or suspicious

Analyzes IP address against blacklists, whitelists, and recent violation
history to determine trustworthiness and security risk.

**Parameters**

* `(string|null) $ipAddress`
: IP address to check (null uses client IP)

**Return Values**

`array`

> IP security analysis with block status, suspicion level, and trust score

Usage example:
```php
$security = new SecurityManager();
$ipCheck = $security->checkIPSecurity('192.168.1.100');

if ($ipCheck['blocked']) {
    http_response_code(403);
    die('Access denied: ' . $ipCheck['reason']);
}

if ($ipCheck['suspicious']) {
    error_log('Suspicious IP detected: ' . $ipCheck['reason']);
    // Apply additional verification
}

echo "Trust score: " . ($ipCheck['trust_score'] * 100) . "%";
```


<hr />


### SecurityManager::generateAPIToken

**Description**

```php
public generateAPIToken (int $userId, int $expiresIn)
```

Generate security token for API access

Creates a secure API access token for a user with specified expiration
and associates it with IP address for additional security.

**Parameters**

* `(int) $userId`
: User ID to generate token for
* `(int) $expiresIn`
: Token expiration time in seconds (default: 1 hour)

**Return Values**

`string`

> Generated API token

Usage example:
```php
$security = new SecurityManager();

// Generate 24-hour API token
$apiToken = $security->generateAPIToken(123, 86400);

// Return to client
echo json_encode([
    'api_token' => $apiToken,
    'expires_in' => 86400,
    'token_type' => 'Bearer'
]);
```


<hr />


### SecurityManager::getCSRFToken

**Description**

```php
public getCSRFToken (void)
```

Get individual security components

Provides access to individual security components for advanced usage
and direct interaction when needed.

**Parameters**

`This function has no parameters.`

**Return Values**

`\CSRFToken`

> CSRF token manager instance

Usage example:
```php
$security = new SecurityManager();
$csrf = $security->getCSRFToken();
$token = $csrf->generateToken('special_form');
```


<hr />


### SecurityManager::getHoneypot

**Description**

```php
public getHoneypot (void)
```

Get honeypot component



**Parameters**

`This function has no parameters.`

**Return Values**

`\Honeypot`

> Honeypot anti-spam instance

Usage example:
```php
$security = new SecurityManager();
$honeypot = $security->getHoneypot();
$stats = $honeypot->getStats();
```


<hr />


### SecurityManager::getRateLimiter

**Description**

```php
public getRateLimiter (void)
```

Get rate limiter component



**Parameters**

`This function has no parameters.`

**Return Values**

`\RateLimiter`

> Rate limiter instance

Usage example:
```php
$security = new SecurityManager();
$rateLimiter = $security->getRateLimiter();
$remaining = $rateLimiter->getRemainingRequests($identifier);
```


<hr />


### SecurityManager::getSecurityHeaders

**Description**

```php
public getSecurityHeaders (void)
```

Get security headers for responses

Returns a comprehensive set of HTTP security headers including CSP,
HSTS, XSS protection, and CORS settings based on configuration.

**Parameters**

`This function has no parameters.`

**Return Values**

`array`

> Associative array of security headers

Usage example:
```php
$security = new SecurityManager();
$headers = $security->getSecurityHeaders();

foreach ($headers as $name => $value) {
    echo "Header: {$name}: {$value}\n";
}

// Output includes:
// X-Content-Type-Options: nosniff
// X-Frame-Options: DENY
// Content-Security-Policy: default-src 'self'...
// Strict-Transport-Security: max-age=31536000...
```


<hr />


### SecurityManager::getSecurityStats

**Description**

```php
public getSecurityStats (void)
```

Get comprehensive security statistics

Returns detailed statistics from all security components for monitoring
and reporting purposes.

**Parameters**

`This function has no parameters.`

**Return Values**

`array`

> Complete security statistics from all components

Usage example:
```php
$security = new SecurityManager();
$stats = $security->getSecurityStats();

echo "CSRF Tokens:\n";
echo "- Active: " . $stats['csrf']['active'] . "\n";
echo "- Expired: " . $stats['csrf']['expired'] . "\n";

echo "Rate Limiting:\n";
echo "- Requests blocked: " . $stats['rate_limiting']['blocked_requests'] . "\n";

echo "Spam Detection:\n";
echo "- Total detections: " . $stats['spam_detection']['total_detections'] . "\n";
echo "- Average score: " . $stats['spam_detection']['average_spam_score'] . "\n";

echo "Storage:\n";
echo "- Total records: " . $stats['storage']['total_records'] . "\n";
```


<hr />


### SecurityManager::getSpamDetector

**Description**

```php
public getSpamDetector (void)
```

Get spam detector component



**Parameters**

`This function has no parameters.`

**Return Values**

`\SpamDetector`

> Spam detection instance

Usage example:
```php
$security = new SecurityManager();
$spamDetector = $security->getSpamDetector();
$analysis = $spamDetector->analyzeContent($content);
```


<hr />


### SecurityManager::getStorage

**Description**

```php
public getStorage (void)
```

Get file storage component



**Parameters**

`This function has no parameters.`

**Return Values**

`\FileStorage`

> File storage instance

Usage example:
```php
$security = new SecurityManager();
$storage = $security->getStorage();
$records = $storage->find('security_log', ['severity' => 'high']);
```


<hr />


### SecurityManager::initializeForm

**Description**

```php
public initializeForm (string $formId)
```

Initialize security for a form

Generates all necessary security tokens and fields for a form including
CSRF tokens, honeypot fields, and associated CSS for proper rendering.

**Parameters**

* `(string) $formId`
: Form identifier for context-specific tokens

**Return Values**

`array`

> Array containing HTML fields and meta tags for form security

Usage example:
```php
$security = new SecurityManager();
$formSecurity = $security->initializeForm('contact_form');

echo '<html><head>';
echo $formSecurity['csrf_meta'];
echo $formSecurity['honeypot_css'];
echo '</head><body>';

echo '<form method="post">';
echo $formSecurity['csrf_field'];
echo $formSecurity['honeypot_field'];
echo '<input type="text" name="message">';
echo '<button type="submit">Submit</button>';
echo '</form></body></html>';
```


<hr />


### SecurityManager::logSecurityEvent

**Description**

```php
public logSecurityEvent (string $eventType, array $details)
```

Log security event

Records security-related events for monitoring, analysis, and audit trails
with comprehensive context including user, IP, and request information.

**Parameters**

* `(string) $eventType`
: Type of security event
* `(array) $details`
: Additional event details and context

**Return Values**

`void`

>

Usage example:
```php
$security = new SecurityManager(123);

// Log successful login
$security->logSecurityEvent('login_success', [
    'method' => '2fa',
    'severity' => 'info'
]);

// Log security violation
$security->logSecurityEvent('xss_attempt', [
    'content_hash' => hash('sha256', $maliciousContent),
    'severity' => 'high',
    'blocked' => true
]);
```


<hr />


### SecurityManager::performMaintenance

**Description**

```php
public performMaintenance (void)
```

Perform security maintenance

Executes cleanup operations across all security components to remove
expired tokens, old logs, and optimize performance.

**Parameters**

`This function has no parameters.`

**Return Values**

`array`

> Summary of maintenance operations performed

Usage example:
```php
$security = new SecurityManager();
$maintenanceResults = $security->performMaintenance();

echo "Maintenance completed:\n";
echo "- CSRF tokens cleaned: " . $maintenanceResults['csrf_cleanup'] . "\n";
echo "- Rate limit entries cleaned: " . $maintenanceResults['rate_limit_cleanup'] . "\n";
echo "- Honeypot sessions cleaned: " . $maintenanceResults['honeypot_cleanup'] . "\n";
echo "- Storage cleanup: " . ($maintenanceResults['storage_cleanup'] ? 'Done' : 'Failed') . "\n";

// Run this periodically via cron job
```


<hr />


### SecurityManager::securityCheck

**Description**

```php
public securityCheck (string $actionType, array $postData, bool $requireCSRF, float $spamThreshold, string $formId)
```

Comprehensive security check for form submissions

Performs complete security validation including rate limiting, CSRF protection,
honeypot validation, and spam detection. Returns detailed results for each check.

**Parameters**

* `(string) $actionType`
: Type of action being performed (for rate limiting)
* `(array) $postData`
: Form submission data to validate
* `(bool) $requireCSRF`
: Whether CSRF token validation is required
* `(float) $spamThreshold`
: Spam score threshold (0.0-1.0)
* `(string) $formId`
: Form identifier for context-specific validation

**Return Values**

`array`

> Security validation result with pass/fail status and details

Usage example:
```php
$security = new SecurityManager($userId);
$result = $security->securityCheck('login', $_POST, true, 0.3, 'login_form');

if (!$result['passed']) {
    error_log('Security check failed: ' . $result['reason']);
    foreach ($result['details'] as $detail) {
        echo "Issue: " . $detail . "\n";
    }
    http_response_code(403);
    exit;
}

// Check individual security components
if (!$result['security_checks']['csrf']) {
    echo "CSRF validation failed";
}
echo "Spam score: " . $result['security_checks']['spam_detection']['score'];
```


<hr />


### SecurityManager::validateAPIToken

**Description**

```php
public validateAPIToken (string $token)
```

Validate API token

Verifies API token validity, expiration, and returns associated user data.
Automatically cleans up expired tokens.

**Parameters**

* `(string) $token`
: API token to validate

**Return Values**

`array|null`

> Token data if valid, null if invalid or expired

Usage example:
```php
$security = new SecurityManager();

$authHeader = $_SERVER['HTTP_AUTHORIZATION'] ?? '';
if (preg_match('/Bearer\s+(.*)$/i', $authHeader, $matches)) {
    $token = $matches[1];
    $tokenData = $security->validateAPIToken($token);

    if ($tokenData) {
        $userId = $tokenData['user_id'];
        echo "Authenticated user: " . $userId;
    } else {
        http_response_code(401);
        echo json_encode(['error' => 'Invalid or expired token']);
    }
}
```


<hr />


### SecurityManager::validateContent

**Description**

```php
public validateContent (string $content, bool $allowHtml, bool $cleanProfanity)
```

Validate and clean content

Performs content sanitization including length truncation, HTML stripping,
profanity filtering, and XSS protection based on specified options.

**Parameters**

* `(string) $content`
: Content to validate and clean
* `(bool) $allowHtml`
: Whether to allow HTML tags in content
* `(bool) $cleanProfanity`
: Whether to filter profanity and spam

**Return Values**

`string`

> Cleaned and validated content safe for storage/display

Usage example:
```php
$security = new SecurityManager();

// Clean user comment (no HTML)
$cleanComment = $security->validateContent($userComment, false, true);

// Clean blog post (allow HTML)
$cleanPost = $security->validateContent($blogContent, true, false);

// Clean with full restrictions
$userInput = '<script>alert("xss")</script>Some bad words here';
$cleaned = $security->validateContent($userInput);
echo $cleaned; // Safe output without scripts or profanity
```


<hr />
