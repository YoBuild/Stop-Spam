# Yohns Security Framework - Quick Start

A comprehensive PHP security library providing CSRF protection, rate limiting, spam detection, content validation, and more.

## Installation

```php
// Include the framework
require_once 'path/to/yohns/security/autoload.php';

use Yohns\Security\SecurityManager;
```

## Basic Usage

### 1. Initialize Security Manager

```php
// For logged-in users
$security = new SecurityManager($userId);

// For anonymous users
$security = new SecurityManager();
```

### 2. Secure a Form

```php
// Initialize form security
$formSecurity = $security->initializeForm('contact_form');

// In your HTML
echo '<form method="post">';
echo $formSecurity['csrf_field'];      // CSRF protection
echo $formSecurity['honeypot_field'];  // Bot detection
echo '<input type="text" name="message">';
echo '<button type="submit">Submit</button>';
echo '</form>';

// Add to <head>
echo $formSecurity['csrf_meta'];       // For AJAX
echo $formSecurity['honeypot_css'];    // Hide honeypot
```

### 3. Validate Form Submission

```php
// Comprehensive security check
$result = $security->securityCheck('contact', $_POST, true, 0.5, 'contact_form');

if (!$result['passed']) {
    die('Security validation failed: ' . $result['reason']);
}

// Process form safely
```

### 4. Apply Security Headers

```php
// Apply security headers
$security->applySecurityHeaders();

// Now output your content
echo '<html>...';
```

## Individual Components

### CSRF Protection
```php
$csrf = new CSRFToken();
$token = $csrf->generateToken('my_form');
$isValid = $csrf->validateRequest('my_form');
```

### Rate Limiting
```php
$rateLimiter = new RateLimiter();
if ($rateLimiter->isLimited($_SERVER['REMOTE_ADDR'], 'login')) {
    die('Too many requests');
}
```

### Spam Detection
```php
$spamDetector = new SpamDetector();
$result = $spamDetector->analyzeContent($userInput);
if ($result['is_spam']) {
    die('Spam detected');
}
```

### Content Validation
```php
$validator = new ContentValidator();
$result = $validator->validate($userInput);
$safeContent = $result['sanitized_content'];
```

### IP Security
```php
$ipSecurity = new IPSecurity();
$analysis = $ipSecurity->analyzeIP();
if ($analysis['is_blocked']) {
    die('IP blocked');
}
```

### Token Management
```php
$tokenManager = new TokenManager();
$apiToken = $tokenManager->generateAPIToken($userId);
$resetToken = $tokenManager->generatePasswordResetToken($userId, $email);
```

## Configuration

Create `config/security.php`:

```php
return [
    'csrf' => [
        'enabled' => true,
        'expiration' => 1800,
    ],
    'rate_limiting' => [
        'enabled' => true,
        'max_requests' => 100,
        'time_window' => 3600,
    ],
    'spam_detection' => [
        'enabled' => true,
        'max_links' => 3,
    ],
    'storage' => [
        'directory' => __DIR__ . '/../database',
    ],
];
```

## Maintenance

```php
// Run periodically (cron job)
$results = $security->performMaintenance();
echo "Cleaned up " . array_sum($results) . " expired records";
```

## Statistics

```php
$stats = $security->getSecurityStats();
echo "Active CSRF tokens: " . $stats['csrf']['active'];
echo "Spam detections: " . $stats['spam_detection']['total_detections'];
```

## Requirements

- PHP 8.2 or newer
- JSON extension
- DOM extension (for HTML sanitization)

## Security Features

✅ **CSRF Protection** - Token-based request validation
✅ **Rate Limiting** - IP and user-based request throttling
✅ **Spam Detection** - Content analysis and filtering
✅ **XSS Protection** - Input sanitization and validation
✅ **Honeypot** - Bot detection and prevention
✅ **IP Security** - Blacklisting and reputation tracking
✅ **Token Management** - Secure token generation and validation
✅ **Content Validation** - Email, URL, phone, filename validation
✅ **Security Headers** - Comprehensive HTTP security headers
✅ **File Storage** - Secure JSON-based data storage

## Quick Examples

### Secure Login Form
```php
$security = new SecurityManager();
$formSecurity = $security->initializeForm('login');

// In form
echo $formSecurity['csrf_field'];
echo $formSecurity['honeypot_field'];

// On submission
$result = $security->securityCheck('login', $_POST);
if ($result['passed']) {
    // Process login
}
```

### API Endpoint Protection
```php
$security = new SecurityManager();

// Check rate limits
if ($security->getRateLimiter()->isLimited($_SERVER['REMOTE_ADDR'], 'api')) {
    http_response_code(429);
    exit;
}

// Validate API token
$token = $_SERVER['HTTP_AUTHORIZATION'] ?? '';
$tokenData = $security->validateAPIToken($token);
if (!$tokenData) {
    http_response_code(401);
    exit;
}
```

### Content Sanitization
```php
$security = new SecurityManager();

// Clean user content
$safeContent = $security->validateContent($userInput, false, true);

// Or use validator directly
$validator = new ContentValidator();
$result = $validator->validate($content, ['allow_html' => true]);
```