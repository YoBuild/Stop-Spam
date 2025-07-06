# Spam Prevention and Security System Documentation

## Overview

This security system provides comprehensive protection against spam and malicious activity for your social network application. It includes:

1. **CSRF Protection**:
   - Form token generation and validation
   - Configurable token expiration (default 30 minutes)
   - Session-bound tokens
   - Automatic token rotation
   - JavaScript validation before form submission

2. **Honeypot Fields and Timing Analysis**:
   - Hidden form fields to catch automated submissions
   - Timing analysis to detect bot submissions
   - JavaScript-based bot detection methods

## Installation

### 1. Database Setup

First, create the necessary database tables by running the provided SQL script:

```bash
mysql -u username -p your_database < database/security_schema.sql
```

The script creates the following tables:
- `security_csrf_tokens`: For database storage of CSRF tokens
- `security_rate_limits`: For tracking rate limits
- `security_spam_log`: For logging spam detection events
- `security_ip_reputation`: For tracking IP reputations

### 2. Directory Structure

Ensure the following directory structure exists in your application:

```
src/
  ├── Yohns/
  │   ├── Security/
  │   │   ├── CSRFToken.php
  │   │   ├── CSRFMiddleware.php
  │   │   ├── Honeypot.php
  │   │   ├── SpamDetector.php
  │   │   ├── SecurityConfig.php
  │   │   └── TokenStorage.php
  │   └── Core/
  │       ├── Config.php
  │       └── ConfigEditor.php
public/
  └── js/
      └── SecurityValidator.js
logs/
```

Ensure the `logs` directory is writable by your web server.

### 3. Configuration

The system will automatically create a default configuration file when `SecurityConfig::load()` is called, but you can manually configure the settings by creating a `security.php` file in your config directory:

```php
<?php
return [
    // CSRF Protection
    'csrf_enabled' => true,
    'csrf_expiration' => 1800, // 30 minutes in seconds
    'csrf_session_prefix' => 'csrf_token_',
    'csrf_header_name' => 'X-CSRF-TOKEN',
    'csrf_cookie_name' => 'XSRF-TOKEN',
    'csrf_same_site' => 'Lax',

    // Honeypot
    'honeypot_enabled' => true,
    'honeypot_field_name' => 'website',
    'honeypot_min_time' => 2, // seconds
    'honeypot_max_time' => 3600, // 1 hour in seconds
    'honeypot_session_prefix' => 'honeypot_',

    // Spam Detection
    'spam_detection_enabled' => true,
    'spam_log_enabled' => true,
    'spam_log_file' => '../logs/spam_detection.log',
    'challenge_enabled' => false,
    'js_token_secret' => 'your-random-secret-key',

    // Rate Limiting
    'rate_limiting_enabled' => true,
    'rate_limit_storage' => 'database', // 'database' or 'memory'
    'rate_limit_global_max' => 1000, // requests per hour
    'rate_limit_per_endpoint' => 100, // requests per minute
    'rate_limit_per_ip' => 300, // requests per minute
    'rate_limit_login_max' => 5, // attempts per 15 minutes

    // Token Storage
    'token_storage' => 'session', // 'session' or 'database'
    'db_based_csrf_cleanup_interval' => 3600, // 1 hour in seconds
];
```

## Implementation Guide

### 1. CSRF Protection

#### Basic Usage

To protect your forms against CSRF attacks:

```php
<?php
// Initialize CSRF protection
use Yohns\Security\CSRFToken;
CSRFToken::init();

// In your HTML form
<form method="post" action="/submit">
    <!-- Form fields -->
    <?= CSRFToken::tokenField('login_form') ?>
    <button type="submit">Submit</button>
</form>

// When processing the form
if (CSRFToken::validate($_POST['csrf_token'], 'login_form')) {
    // Process the form
} else {
    // Invalid token, reject the submission
}
```

#### Middleware Usage

For automatic CSRF validation in a middleware-based application:

```php
<?php
use Yohns\Security\CSRFMiddleware;

// Initialize middleware with options
$csrfMiddleware = new CSRFMiddleware([
    'methods' => ['POST', 'PUT', 'DELETE'], // Methods to protect
    'except' => ['api/webhook', 'api/callback'], // URLs to exempt
    'error_response' => function() {
        header('HTTP/1.1 403 Forbidden');
        echo json_encode(['error' => 'Invalid security token']);
        exit;
    }
]);

// Apply middleware
$csrfMiddleware->protect();
```

#### Database Storage for Tokens

To use database storage instead of sessions for tokens:

```php
<?php
use Yohns\Security\TokenStorage;
use PDOChainer\PDOChainer;

// Initialize database connection
$pdo = new PDOChainer([
    'host' => 'localhost',
    'dbname' => 'your_database',
    'user' => 'username',
    'pass' => 'password'
]);

// Initialize token storage
TokenStorage::init($pdo);

// Generate and store a token
$token = bin2hex(random_bytes(32));
TokenStorage::store('login_form', $token, 1800);

// Validate a token
if (TokenStorage::validate('login_form', $_POST['csrf_token'])) {
    // Process the form
}
```

### 2. Honeypot Fields and Timing Analysis

#### Basic Usage

To protect your forms with honeypot fields and timing analysis:

```php
<?php
use Yohns\Security\Honeypot;
Honeypot::init();

// In your HTML form
<form method="post" action="/submit">
    <!-- Form fields -->
    <?= Honeypot::field() ?>
    <?= Honeypot::startTiming('registration_form') ?>
    <button type="submit">Submit</button>
</form>

// When processing the form
if (Honeypot::validate($_POST) && Honeypot::validateTiming($_POST, 'registration_form')) {
    // Process the form
} else {
    // Bot detected, reject the submission
}
```

### 3. Combined Security with SpamDetector

For a complete spam prevention solution:

```php
<?php
use Yohns\Security\SecurityConfig;
use Yohns\Security\SpamDetector;

// Load security configuration
SecurityConfig::load();

// Initialize spam detector
$detector = new SpamDetector();

// In your HTML form
<form method="post" action="/submit">
    <!-- Form fields -->
    <?= $detector->protectForm('contact_form') ?>
    <button type="submit">Submit</button>
</form>

// When processing the form
if ($detector->validateRequest($_POST, 'contact_form')) {
    // Process the form
} else {
    // Spam detected, reject the submission
}
```

### 4. Client-Side JavaScript Validation

Include the JavaScript file in your HTML:

```html
<script src="/js/SecurityValidator.js"></script>
```

Initialize with custom options (optional):

```javascript
document.addEventListener('DOMContentLoaded', () => {
    const validator = new SecurityValidator('form.secured', {
        csrfTokenName: 'csrf_token',
        csrfHeaderName: 'X-CSRF-TOKEN',
        honeypotFieldName: 'website',
        minSubmitTime: 2000, // 2 seconds
        detectBotBehavior: true,
        validateBeforeSubmit: true
    });
});
```

## Configuration Options

### CSRF Protection Options

| Option | Description | Default |
|--------|-------------|---------|
| `csrf_enabled` | Enable/disable CSRF protection | `true` |
| `csrf_expiration` | Token expiration time in seconds | `1800` (30 minutes) |
| `csrf_session_prefix` | Prefix for session keys | `'csrf_token_'` |
| `csrf_header_name` | HTTP header name for AJAX requests | `'X-CSRF-TOKEN'` |
| `csrf_cookie_name` | Cookie name for JavaScript frameworks | `'XSRF-TOKEN'` |
| `csrf_same_site` | SameSite cookie attribute | `'Lax'` |

### Honeypot Options

| Option | Description | Default |
|--------|-------------|---------|
| `honeypot_enabled` | Enable/disable honeypot fields | `true` |
| `honeypot_field_name` | Name of the honeypot field | `'website'` |
| `honeypot_min_time` | Minimum form fill time in seconds | `2` |
| `honeypot_max_time` | Maximum form validity time in seconds | `3600` (1 hour) |
| `honeypot_session_prefix` | Prefix for session keys | `'honeypot_'` |

### Spam Detection Options

| Option | Description | Default |
|--------|-------------|---------|
| `spam_detection_enabled` | Enable/disable spam detection | `true` |
| `spam_log_enabled` | Enable/disable logging | `true` |
| `spam_log_file` | Path to log file | `'../logs/spam_detection.log'` |
| `challenge_enabled` | Enable/disable challenge questions | `false` |
| `js_token_secret` | Secret key for JavaScript token | Random value |

## Best Practices

1. **Multiple Protection Layers**: Use a combination of CSRF protection, honeypot fields, and timing analysis for the strongest security.

2. **Dynamic Field Names**: Consider changing the honeypot field name periodically to avoid detection by sophisticated bots.

3. **Log Analysis**: Regularly review the spam detection logs to identify patterns and adjust your protection strategies.

4. **Token Expiration**: Choose appropriate token expiration times based on your user activity patterns.

5. **Challenge Questions**: Enable challenge questions only for high-risk forms or after detecting suspicious behavior.

6. **JavaScript Validation**: While client-side validation improves user experience, always validate on the server side as well.

7. **Performance Considerations**: Database token storage adds overhead but provides better protection for stateless applications.

8. **Regular Updates**: Keep your security system updated to address new threats and attack vectors.

## Troubleshooting

### Common Issues

1. **False Positives**: If legitimate users are being blocked:
   - Increase the `honeypot_min_time` value
   - Verify that honeypot fields are properly hidden via CSS
   - Check for browser extensions that might fill in hidden fields

2. **CSRF Token Validation Failures**:
   - Ensure the token is included in all forms
   - Check if the token expires too quickly for your use case
   - Verify that the context name is consistent between generation and validation

3. **Database Storage Issues**:
   - Verify database connection parameters
   - Check table permissions
   - Ensure the cleanup procedure is running to prevent table growth

### Debugging

Enable detailed logging for troubleshooting:

```php
<?php
// Add debug options to SpamDetector
$detector = new SpamDetector([
    'log_detections' => true,
    'log_file' => '/path/to/detailed/log.txt'
]);
```

## Security Considerations

1. **Keep Secrets Secure**: The `js_token_secret` should be unique for each installation and kept confidential.

2. **Sanitize Log Data**: Sensitive information in form submissions is automatically redacted in logs, but review logs to ensure no sensitive data is being stored.

3. **Session Security**: Ensure your PHP session configuration is secure (use secure cookies, appropriate session lifetime, etc.).

4. **Database Security**: Apply the principle of least privilege to the database user that accesses the security tables.

5. **Regular Audits**: Periodically review security logs and configuration to ensure optimal protection.

## Extending the System

The security system is designed to be extensible. Here are some ways to extend it:

### Custom Bot Detection

Add your own bot detection logic:

```javascript
// Client-side
const validator = new SecurityValidator();
validator.addBotDetectionCheck(function() {
    // Custom detection logic
    return suspiciousBehaviorDetected;
});
```

### Custom Token Storage

Create a custom token storage class:

```php
<?php
namespace Yohns\Security\Storage;

class RedisTokenStorage {
    // Implement storage and retrieval methods
}
```

### Custom Validation Rules

Add custom validation logic to the SpamDetector:

```php
<?php
class EnhancedSpamDetector extends SpamDetector {
    public function validateRequest(array $data, string $formId): bool {
        // Run parent validations
        $valid = parent::validateRequest($data, $formId);

        // Add custom validations
        if ($valid && !$this->customValidation($data)) {
            $valid = false;
        }

        return $valid;
    }

    private function customValidation(array $data): bool {
        // Implement custom validation logic
        return true;
    }
}
```

## Conclusion

This spam prevention and security system provides robust protection against various types of attacks while maintaining flexibility and ease of use. By combining server-side and client-side validation, it creates multiple layers of defense against spam and malicious activity.

Regular monitoring, updating, and customization based on your specific needs will ensure that your social network remains secure and spam-free.