# Yohns Security Framework - Comprehensive Guide

## Table of Contents

1. [Introduction](#introduction)
2. [Installation & Setup](#installation--setup)
3. [Architecture Overview](#architecture-overview)
4. [Core Components](#core-components)
5. [Security Manager](#security-manager)
6. [Configuration](#configuration)
7. [Advanced Usage](#advanced-usage)
8. [Best Practices](#best-practices)
9. [Performance Considerations](#performance-considerations)
10. [Troubleshooting](#troubleshooting)
11. [Security Considerations](#security-considerations)
12. [API Reference](#api-reference)

## Introduction

The Yohns Security Framework is a comprehensive PHP security library designed to protect web applications from common security threats. It provides a unified approach to handling CSRF attacks, rate limiting, spam detection, content validation, and more.

### Key Features

- **Multi-layered Protection**: Combines multiple security mechanisms
- **Framework Agnostic**: Works with any PHP framework or vanilla PHP
- **File-based Storage**: No database dependency
- **Configurable**: Extensive configuration options
- **Performance Optimized**: Efficient algorithms and caching
- **PSR Compliant**: Follows PHP standards
- **Comprehensive Logging**: Detailed security event tracking

### Supported Threats

- Cross-Site Request Forgery (CSRF)
- Cross-Site Scripting (XSS)
- Spam and Bot Attacks
- Rate Limiting Bypass
- Content Injection
- Directory Traversal
- Malicious File Uploads
- IP-based Attacks

## Installation & Setup

### Requirements

- PHP 8.2 or newer
- JSON extension (enabled by default)
- DOM extension (for HTML sanitization)
- Write permissions for storage directory

### Installation

```bash
# Clone repository
git clone https://github.com/yohns/security-framework.git

# Or via Composer (if available)
composer require yohns/security-framework
```

### Directory Structure

```
yohns-security/
├── Yohns/
│   ├── Security/
│   │   ├── ContentValidator.php
│   │   ├── CSRFToken.php
│   │   ├── FileStorage.php
│   │   ├── IPSecurity.php
│   │   ├── RateLimiter.php
│   │   ├── SecurityManager.php
│   │   └── TokenManager.php
│   └── AntiSpam/
│       ├── ContentAnalyzer.php
│       ├── Honeypot.php
│       └── SpamDetector.php
├── config/
│   └── security.php
├── database/
│   └── (storage files)
├── docs/
│   ├── Security/
│   │   ├── ContentValidator.php
│   │   ├── CSRFToken.php
│   │   ├── FileStorage.php
│   │   ├── IPSecurity.php
│   │   ├── RateLimiter.php
│   │   ├── SecurityManager.php
│   │   └── TokenManager.php
│   ├── AntiSpam/
│   │   ├── ContentAnalyzer.php
│   │   ├── Honeypot.php
│   │   └── SpamDetector.php
│   └── README.md
├── examples/
│   └── (usage examples)
└── public/
    └── assets/
        └── js/
            └── security-validator.js
```

### Basic Setup

```php
<?php
// Include autoloader
require_once 'path/to/yohns/autoload.php';

// Import classes
use Yohns\Security\SecurityManager;
use Yohns\Core\Config;

// Configure (optional - uses defaults if not set)
Config::set('storage.directory', __DIR__ . '/database');
Config::set('csrf.enabled', true);

// Initialize
$security = new SecurityManager();
```

## Architecture Overview

### Design Principles

1. **Separation of Concerns**: Each component handles specific security aspects
2. **Composition over Inheritance**: Components work together through composition
3. **Configuration-driven**: Behavior controlled through configuration
4. **Fail-safe Defaults**: Secure by default configuration
5. **Extensibility**: Easy to extend and customize

### Component Relationships

```
SecurityManager (Orchestrator)
├── CSRFToken (CSRF Protection)
├── RateLimiter (Request Throttling)
├── Honeypot (Bot Detection)
├── SpamDetector (Content Analysis)
├── IPSecurity (IP Management)
├── TokenManager (Token Lifecycle)
├── ContentValidator (Input Validation)
└── FileStorage (Data Persistence)
```

## Core Components

### 1. SecurityManager

The main orchestrator that coordinates all security components.

#### Key Methods

```php
$security = new SecurityManager($userId);

// Comprehensive form validation
$result = $security->securityCheck($action, $postData, $requireCSRF, $spamThreshold, $formId);

// Form initialization
$formSecurity = $security->initializeForm($formId);

// Content validation
$cleanContent = $security->validateContent($content, $allowHtml, $cleanProfanity);

// Security headers
$security->applySecurityHeaders();

// IP security check
$ipStatus = $security->checkIPSecurity($ipAddress);
```

#### Usage Example

```php
<?php
use Yohns\Security\SecurityManager;

// Initialize with user context
$security = new SecurityManager($_SESSION['user_id'] ?? null);

// Handle form submission
if ($_POST) {
    $result = $security->securityCheck('contact', $_POST, true, 0.5, 'contact_form');

    if (!$result['passed']) {
        $error = $result['reason'];
        $details = $result['details'];
        // Handle security failure
    } else {
        // Process form safely
        $message = $security->validateContent($_POST['message']);
        // Save to database
    }
}

// Initialize form
$formSecurity = $security->initializeForm('contact_form');
?>

<!DOCTYPE html>
<html>
<head>
    <?= $formSecurity['csrf_meta'] ?>
    <?= $formSecurity['honeypot_css'] ?>
</head>
<body>
    <form method="post">
        <?= $formSecurity['csrf_field'] ?>
        <?= $formSecurity['honeypot_field'] ?>
        <textarea name="message"></textarea>
        <button type="submit">Send</button>
    </form>
</body>
</html>
```

### 2. CSRFToken

Provides Cross-Site Request Forgery protection through secure tokens.

#### Features

- Token generation with configurable expiration
- Multiple storage backends (session + file)
- Context-specific tokens
- Cookie support for JavaScript access
- Automatic cleanup of expired tokens

#### Usage

```php
use Yohns\Security\CSRFToken;

$csrf = new CSRFToken();

// Generate token for form
$token = $csrf->generateToken('user_profile');

// Generate hidden field
echo $csrf->getHiddenField('user_profile');

// Generate meta tag for AJAX
echo $csrf->getMetaTag('user_profile');

// Validate submission
if ($csrf->validateRequest('user_profile')) {
    // Process form
} else {
    // CSRF validation failed
}

// Manual validation
$isValid = $csrf->validateToken($_POST['csrf_token'], 'user_profile');
```

#### JavaScript Integration

```javascript
// Get CSRF token from meta tag
const token = document.querySelector('meta[name="csrf-token"]').content;

// Include in AJAX requests
fetch('/api/endpoint', {
    method: 'POST',
    headers: {
        'X-CSRF-TOKEN': token,
        'Content-Type': 'application/json'
    },
    body: JSON.stringify(data)
});
```

### 3. RateLimiter

Implements request throttling to prevent abuse and DoS attacks.

#### Features

- IP-based and user-based limiting
- Sliding window algorithm
- Configurable limits per action type
- Automatic cleanup
- Detailed statistics

#### Configuration

```php
// In config/security.php
'rate_limiting' => [
    'enabled' => true,
    'default_max_requests' => 100,
    'default_time_window' => 3600, // 1 hour
    'block_duration' => 3600,
    'limits' => [
        'login' => ['max_requests' => 5, 'time_window' => 900], // 5 per 15 min
        'api' => ['max_requests' => 1000, 'time_window' => 3600], // 1000 per hour
        'contact' => ['max_requests' => 10, 'time_window' => 3600], // 10 per hour
    ]
]
```

#### Usage

```php
use Yohns\Security\RateLimiter;

$rateLimiter = new RateLimiter();

// Check if request is allowed
$clientIP = $_SERVER['REMOTE_ADDR'];
if ($rateLimiter->isLimited($clientIP, 'login')) {
    http_response_code(429);
    $remaining = $rateLimiter->getBlockTimeRemaining("ip_{$clientIP}", 'login');
    die("Rate limit exceeded. Try again in " . ceil($remaining / 60) . " minutes.");
}

// Record successful request
$rateLimiter->recordRequest($clientIP, 'login');

// Get remaining requests
$remaining = $rateLimiter->getRemainingRequests($clientIP, 'login');
header("X-RateLimit-Remaining: {$remaining}");
```

### 4. Honeypot

Implements honeypot techniques to detect and block automated spam bots.

#### How It Works

1. Adds hidden form fields invisible to humans
2. Monitors form submission timing
3. Analyzes request patterns
4. Blocks requests that fail honeypot checks

#### Usage

```php
use Yohns\AntiSpam\Honeypot;

$honeypot = new Honeypot();

// Initialize for form
$honeypotField = $honeypot->initialize('contact_form');
$honeypotCSS = $honeypot->getCSS();

// In your form
echo $honeypotCSS;
echo $honeypotField;

// Validate submission
$result = $honeypot->validate($_POST, 'contact_form');
if (!$result['passed']) {
    // Bot detected
    error_log("Bot detected: " . $result['reason']);
    http_response_code(403);
    exit;
}
```

### 5. SpamDetector

Analyzes content for spam patterns and malicious content.

#### Features

- Keyword-based detection
- Profanity filtering
- Link analysis
- Behavioral pattern recognition
- Machine learning-style scoring
- Content cleaning

#### Usage

```php
use Yohns\AntiSpam\SpamDetector;

$spamDetector = new SpamDetector();

// Analyze content
$result = $spamDetector->analyzeContent($userMessage);

if ($result['is_spam']) {
    echo "Spam detected! Score: " . $result['spam_score'];
    echo "Reasons: " . implode(', ', $result['reasons']);
    // Block or flag content
} else {
    // Content is clean
    $cleanContent = $spamDetector->cleanContent($userMessage);
    // Save to database
}

// Add custom spam keywords
$spamDetector->addSpamKeyword('new-spam-word');

// Training with feedback
$spamDetector->trainWithFeedback($content, $isSpam);
```

### 6. IPSecurity

Manages IP-based security including blacklisting, whitelisting, and reputation tracking.

#### Features

- IP whitelisting and blacklisting
- Geolocation analysis
- Proxy/VPN detection
- Reputation scoring
- Automatic threat analysis
- CIDR range support

#### Usage

```php
use Yohns\Security\IPSecurity;

$ipSecurity = new IPSecurity();

// Analyze IP
$analysis = $ipSecurity->analyzeIP('192.168.1.100');

if ($analysis['is_blocked']) {
    http_response_code(403);
    die('Access denied from your location');
}

if ($analysis['trust_score'] < 0.5) {
    // Additional verification required
    $threats = $analysis['threats'];
    foreach ($threats as $threat) {
        error_log("Threat: " . $threat['description']);
    }
}

// Manage lists
$ipSecurity->addToBlacklist('203.0.113.0/24', 'Spam network', 86400);
$ipSecurity->addToWhitelist('192.168.1.0/24', 'Office network');

// Update reputation
$ipSecurity->updateReputation($ip, 'failed_login', -0.1);
```

### 7. TokenManager

Handles lifecycle management of various security tokens.

#### Token Types

- **API Access**: Long-lived tokens for API authentication
- **Email Verification**: Single-use tokens for email confirmation
- **Password Reset**: Secure tokens for password recovery
- **Two-Factor Auth**: Short-lived 2FA tokens
- **Session**: Session management tokens
- **File Upload**: Temporary upload authorization tokens

#### Usage

```php
use Yohns\Security\TokenManager;

$tokenManager = new TokenManager();

// Generate different token types
$apiToken = $tokenManager->generateAPIToken($userId, ['read', 'write']);
$verifyToken = $tokenManager->generateEmailVerificationToken($email, $userId);
$resetToken = $tokenManager->generatePasswordResetToken($userId, $email);

// Validate tokens
$result = $tokenManager->validateToken($token, 'email_verification', true);
if ($result['is_valid']) {
    $email = $result['token_data']['email'];
    // Verify email address
} else {
    echo "Error: " . $result['error'];
}

// Custom token types
$tokenManager->addTokenType('payment_auth', [
    'length' => 48,
    'expiration' => 300, // 5 minutes
    'max_usage' => 1
]);
```

### 8. ContentValidator

Provides comprehensive input validation and sanitization.

#### Validation Types

- Generic content validation
- Email address validation
- URL validation
- Phone number validation
- Filename sanitization
- XSS detection and prevention

#### Usage

```php
use Yohns\Security\ContentValidator;

$validator = new ContentValidator();

// Validate content
$result = $validator->validate($userInput, [
    'allow_html' => false,
    'max_length' => 5000,
    'check_xss' => true
]);

if ($result['is_valid']) {
    $safeContent = $result['sanitized_content'];
    // Use sanitized content
} else {
    foreach ($result['errors'] as $error) {
        echo "Error: " . $error . "\n";
    }
}

// Specific validations
$emailResult = $validator->validateEmail($email);
$urlResult = $validator->validateURL($url);
$phoneResult = $validator->validatePhone($phone);
$fileResult = $validator->validateFilename($filename);

// XSS detection
$xssCheck = $validator->detectXSS($suspiciousContent);
if (!$xssCheck['is_safe']) {
    foreach ($xssCheck['threats'] as $threat) {
        error_log("XSS threat: " . $threat['description']);
    }
}
```

### 9. FileStorage

Provides secure file-based data storage for security components.

#### Features

- JSON-based storage
- Automatic cleanup
- File locking
- Configurable permissions
- CRUD operations

#### Usage

```php
use Yohns\Security\FileStorage;

$storage = new FileStorage();

// Basic CRUD operations
$id = $storage->insert('users', ['name' => 'John', 'email' => 'john@example.com']);
$users = $storage->find('users', ['status' => 'active']);
$user = $storage->findOne('users', ['email' => 'john@example.com']);
$storage->update('users', $id, ['last_login' => time()]);
$storage->delete('users', $id);

// Statistics
$stats = $storage->getStats();
echo "Total records: " . $stats['total_records'];
echo "Storage size: " . $stats['total_size'] . " bytes";
```

## Configuration

### Configuration File Structure

Create `config/security.php`:

```php
<?php
return [
    // CSRF Protection
    'csrf' => [
        'enabled' => true,
        'expiration' => 1800, // 30 minutes
        'header_name' => 'X-CSRF-TOKEN',
        'cookie_name' => 'XSRF-TOKEN',
        'same_site' => 'Lax',
    ],

    // Rate Limiting
    'rate_limiting' => [
        'enabled' => true,
        'default_max_requests' => 100,
        'default_time_window' => 3600,
        'block_duration' => 3600,
        'cleanup_interval' => 300,
        'limits' => [
            'login' => ['max_requests' => 5, 'time_window' => 900],
            'api' => ['max_requests' => 1000, 'time_window' => 3600],
            'contact' => ['max_requests' => 10, 'time_window' => 3600],
            'password_reset' => ['max_requests' => 3, 'time_window' => 900],
        ]
    ],

    // Honeypot
    'honeypot' => [
        'enabled' => true,
        'field_name' => 'website',
        'min_time' => 2, // seconds
        'max_time' => 3600, // 1 hour
    ],

    // Spam Detection
    'spam_detection' => [
        'enabled' => true,
        'max_links' => 3,
        'max_capitals_percent' => 70,
        'max_repeated_chars' => 5,
    ],

    // Content Validation
    'content_validation' => [
        'enabled' => true,
        'max_length' => 10000,
        'allow_html' => false,
        'strip_tags' => true,
    ],

    // IP Security
    'ip_security' => [
        'enabled' => true,
        'check_proxies' => true,
        'max_proxy_depth' => 3,
        'whitelist' => [
            '127.0.0.1',
            '192.168.1.0/24',
        ],
        'blacklist' => [
            // Known malicious IPs
        ],
        'trusted_proxies' => [
            '127.0.0.1',
            '10.0.0.0/8',
            '172.16.0.0/12',
            '192.168.0.0/16',
        ],
    ],

    // Token Management
    'token_management' => [
        'enabled' => true,
        'default_expiration' => 3600,
        'signing_secret' => 'your-secret-key-here',
    ],

    // File Storage
    'storage' => [
        'directory' => __DIR__ . '/../database',
        'file_permissions' => 0664,
        'directory_permissions' => 0755,
        'auto_cleanup' => true,
        'cleanup_interval' => 3600,
    ],

    // Security Headers
    'security' => [
        'csp_cdn_sources' => [
            'https://cdn.jsdelivr.net',
            'https://cdnjs.cloudflare.com',
            'https://fonts.googleapis.com',
            'https://fonts.gstatic.com',
        ],
    ],

    // Domain Settings
    'domain' => [
        'base_url' => 'https://yoursite.com',
        'allowed_origins' => [
            'https://yoursite.com',
            'https://www.yoursite.com',
        ],
    ],
];
```

### Environment-Specific Configuration

```php
// config/security.php
$baseConfig = [
    // Base configuration
];

$environment = $_ENV['APP_ENV'] ?? 'production';

if ($environment === 'development') {
    $baseConfig['csrf']['enabled'] = false; // For testing
    $baseConfig['rate_limiting']['enabled'] = false;
}

return $baseConfig;
```

## Advanced Usage

### Custom Security Workflow

```php
<?php
use Yohns\Security\SecurityManager;

class CustomSecurityManager extends SecurityManager {

    public function customSecurityCheck(array $postData): array {
        // Pre-check custom logic
        if ($this->isMaintenanceMode()) {
            return ['passed' => false, 'reason' => 'Maintenance mode'];
        }

        // Run standard security checks
        $result = $this->securityCheck('custom', $postData);

        // Post-check custom logic
        if ($result['passed'] && $this->isHighRiskAction($postData)) {
            $result = $this->performAdditionalValidation($postData);
        }

        return $result;
    }

    private function isMaintenanceMode(): bool {
        return file_exists(__DIR__ . '/.maintenance');
    }

    private function isHighRiskAction(array $postData): bool {
        $highRiskFields = ['password', 'email', 'payment_info'];
        foreach ($highRiskFields as $field) {
            if (isset($postData[$field])) {
                return true;
            }
        }
        return false;
    }

    private function performAdditionalValidation(array $postData): array {
        // Additional checks for high-risk actions
        // Could include 2FA verification, email confirmation, etc.
        return ['passed' => true, 'reason' => ''];
    }
}
```

### Custom Token Types

```php
use Yohns\Security\TokenManager;

$tokenManager = new TokenManager();

// Add custom token type for document signing
$tokenManager->addTokenType('document_signature', [
    'length' => 64,
    'expiration' => 1800, // 30 minutes
    'max_usage' => 1, // Single use
    'description' => 'Document signature authorization'
]);

// Generate signature token
$signToken = $tokenManager->generateToken('document_signature', [
    'document_id' => $documentId,
    'user_id' => $userId,
    'signature_type' => 'electronic'
]);

// Validate when user signs
$result = $tokenManager->validateToken($signToken, 'document_signature', true);
if ($result['is_valid']) {
    $documentId = $result['token_data']['document_id'];
    // Process document signature
}
```

### Custom Spam Detection Rules

```php
use Yohns\AntiSpam\SpamDetector;

class CustomSpamDetector extends SpamDetector {

    protected function checkCustomRules(string $content): float {
        $score = 0.0;

        // Check for cryptocurrency spam
        if (preg_match('/\b(bitcoin|crypto|mining|wallet)\b/i', $content)) {
            $score += 0.3;
        }

        // Check for suspicious domains
        $suspiciousDomains = ['bit.ly', 't.co', 'tinyurl.com'];
        foreach ($suspiciousDomains as $domain) {
            if (strpos($content, $domain) !== false) {
                $score += 0.2;
            }
        }

        // Check content-to-link ratio
        $linkCount = preg_match_all('/https?:\/\//', $content);
        $wordCount = str_word_count($content);
        if ($wordCount > 0 && ($linkCount / $wordCount) > 0.3) {
            $score += 0.4;
        }

        return min($score, 1.0);
    }
}
```

### Middleware Integration

#### Laravel Middleware

```php
<?php
namespace App\Http\Middleware;

use Closure;
use Yohns\Security\SecurityManager;

class YohnsSecurityMiddleware {

    private SecurityManager $security;

    public function __construct() {
        $this->security = new SecurityManager(auth()->id());
    }

    public function handle($request, Closure $next, $action = 'default') {
        // Apply security headers
        $this->security->applySecurityHeaders();

        // Check IP security
        $ipCheck = $this->security->checkIPSecurity();
        if ($ipCheck['blocked']) {
            abort(403, 'Access denied');
        }

        // For POST requests, perform security check
        if ($request->isMethod('POST')) {
            $result = $this->security->securityCheck(
                $action,
                $request->all(),
                true,
                0.5,
                $request->route()->getName()
            );

            if (!$result['passed']) {
                return response()->json([
                    'error' => $result['reason'],
                    'details' => $result['details']
                ], 403);
            }
        }

        return $next($request);
    }
}
```

#### Symfony Event Subscriber

```php
<?php
namespace App\EventSubscriber;

use Symfony\Component\EventDispatcher\EventSubscriberInterface;
use Symfony\Component\HttpKernel\Event\RequestEvent;
use Symfony\Component\HttpKernel\KernelEvents;
use Yohns\Security\SecurityManager;

class SecuritySubscriber implements EventSubscriberInterface {

    private SecurityManager $security;

    public function __construct() {
        $this->security = new SecurityManager();
    }

    public static function getSubscribedEvents(): array {
        return [
            KernelEvents::REQUEST => 'onKernelRequest',
        ];
    }

    public function onKernelRequest(RequestEvent $event): void {
        $request = $event->getRequest();

        // Apply security headers
        $this->security->applySecurityHeaders();

        // Perform security checks for form submissions
        if ($request->isMethod('POST')) {
            $result = $this->security->securityCheck(
                $request->get('_route'),
                $request->request->all()
            );

            if (!$result['passed']) {
                throw new AccessDeniedHttpException($result['reason']);
            }
        }
    }
}
```

### Database Integration

While the framework uses file storage by default, you can integrate with databases:

```php
<?php
use Yohns\Security\FileStorage;

class DatabaseStorage extends FileStorage {

    private PDO $pdo;

    public function __construct(PDO $pdo) {
        $this->pdo = $pdo;
    }

    public function insert(string $table, array $record): string {
        $id = uniqid(more_entropy: true);
        $record['id'] = $id;
        $record['created_at'] = time();
        $record['updated_at'] = time();

        $columns = implode(',', array_keys($record));
        $placeholders = ':' . implode(', :', array_keys($record));

        $sql = "INSERT INTO {$table} ({$columns}) VALUES ({$placeholders})";
        $stmt = $this->pdo->prepare($sql);
        $stmt->execute($record);

        return $id;
    }

    public function find(string $table, array $criteria = []): array {
        $sql = "SELECT * FROM {$table}";
        $params = [];

        if (!empty($criteria)) {
            $conditions = [];
            foreach ($criteria as $field => $value) {
                $conditions[] = "{$field} = :{$field}";
                $params[$field] = $value;
            }
            $sql .= " WHERE " . implode(' AND ', $conditions);
        }

        $stmt = $this->pdo->prepare($sql);
        $stmt->execute($params);

        return $stmt->fetchAll(PDO::FETCH_ASSOC);
    }

    // Implement other methods...
}

// Usage
$pdo = new PDO($dsn, $username, $password);
$security = new SecurityManager();
$security->setStorage(new DatabaseStorage($pdo));
```

## Best Practices

### 1. Security Configuration

```php
// Always enable security features in production
$securityConfig = [
    'csrf' => ['enabled' => true],
    'rate_limiting' => ['enabled' => true],
    'honeypot' => ['enabled' => true],
    'spam_detection' => ['enabled' => true],
    'ip_security' => ['enabled' => true],
];

// Use environment variables for sensitive settings
$securityConfig['token_management']['signing_secret'] = $_ENV['TOKEN_SIGNING_SECRET'];
```

### 2. Form Security Implementation

```php
// Always initialize forms with security
function renderSecureForm($formId, $content) {
    $security = new SecurityManager();
    $formSecurity = $security->initializeForm($formId);

    return "
    <head>
        {$formSecurity['csrf_meta']}
        {$formSecurity['honeypot_css']}
    </head>
    <body>
        <form method='post'>
            {$formSecurity['csrf_field']}
            {$formSecurity['honeypot_field']}
            {$content}
        </form>
    </body>";
}

// Always validate on submission
function processSecureForm($action, $formId, $postData) {
    $security = new SecurityManager($_SESSION['user_id'] ?? null);

    $result = $security->securityCheck($action, $postData, true, 0.5, $formId);

    if (!$result['passed']) {
        throw new SecurityException($result['reason'], $result['details']);
    }

    return $result;
}
```

### 3. API Security

```php
// Secure API endpoint
function secureAPIEndpoint($action) {
    $security = new SecurityManager();

    // Apply security headers
    $security->applySecurityHeaders();

    // Check rate limits
    $clientIP = $_SERVER['REMOTE_ADDR'];
    if ($security->getRateLimiter()->isLimited($clientIP, 'api')) {
        http_response_code(429);
        echo json_encode(['error' => 'Rate limit exceeded']);
        exit;
    }

    // Validate API token
    $authHeader = $_SERVER['HTTP_AUTHORIZATION'] ?? '';
    if (!preg_match('/Bearer\s+(.*)$/i', $authHeader, $matches)) {
        http_response_code(401);
        echo json_encode(['error' => 'Missing authorization header']);
        exit;
    }

    $token = $matches[1];
    $tokenData = $security->validateAPIToken($token);

    if (!$tokenData) {
        http_response_code(401);
        echo json_encode(['error' => 'Invalid or expired token']);
        exit;
    }

    // Log API access
    $security->logSecurityEvent('api_access', [
        'action' => $action,
        'user_id' => $tokenData['user_id'],
        'severity' => 'info'
    ]);

    return $tokenData['user_id'];
}
```

### 4. Content Handling

```php
// Always validate and sanitize user content
function processUserContent($content, $allowHtml = false) {
    $security = new SecurityManager();
    $validator = $security->getContentValidator();

    // Validate content
    $result = $validator->validate($content, [
        'allow_html' => $allowHtml,
        'max_length' => 10000,
        'check_xss' => true,
        'normalize_whitespace' => true
    ]);

    if (!$result['is_valid']) {
        throw new ValidationException('Content validation failed', $result['errors']);
    }

    // Check for spam
    $spamResult = $security->getSpamDetector()->analyzeContent($content);
    if ($spamResult['is_spam']) {
        throw new SpamException('Content flagged as spam', $spamResult['reasons']);
    }

    return $result['sanitized_content'];
}
```

### 5. Maintenance Tasks

```php
// Set up automated maintenance (cron job)
// crontab: 0 * * * * php /path/to/maintenance.php

<?php
require_once 'vendor/autoload.php';

use Yohns\Security\SecurityManager;

$security = new SecurityManager();

// Perform maintenance
$results = $security->performMaintenance();

// Log results
error_log("Security maintenance completed: " . json_encode($results));

// Optional: Send alerts for high activity
$stats = $security->getSecurityStats();
if ($stats['spam_detection']['recent_detections'] > 100) {
    // Send alert email
    mail('admin@example.com', 'High Spam Activity',
         'Detected ' . $stats['spam_detection']['recent_detections'] . ' spam attempts in the last 24 hours');
}
```

## Performance Considerations

### 1. Caching Strategies

```php
// Use APCu for in-memory caching
class CachedSecurityManager extends SecurityManager {

    private function getCached(string $key, callable $callback, int $ttl = 300) {
        if (extension_loaded('apcu')) {
            $cached = apcu_fetch($key);
            if ($cached !== false) {
                return $cached;
            }
        }

        $value = $callback();

        if (extension_loaded('apcu')) {
            apcu_store($key, $value, $ttl);
        }

        return $value;
    }

    public function checkIPSecurity(string $ipAddress = null): array {
        $ip = $ipAddress ?: $this->getClientIP();
        $cacheKey = "ip_security_{$ip}";

        return $this->getCached($cacheKey, function() use ($ip) {
            return parent::checkIPSecurity($ip);
        }, 300); // Cache for 5 minutes
    }
}
```

### 2. Optimized File Storage

```php
// Use compressed storage for large datasets
class CompressedFileStorage extends FileStorage {

    public function write(string $table, array $data): bool {
        $json = json_encode($data, JSON_PRETTY_PRINT);
        $compressed = gzcompress($json, 6);

        $filePath = $this->getFilePath($table) . '.gz';
        $result = file_put_contents($filePath, $compressed, LOCK_EX);

        return $result !== false;
    }

    public function read(string $table): array {
        $filePath = $this->getFilePath($table) . '.gz';

        if (!file_exists($filePath)) {
            return [];
        }

        $compressed = file_get_contents($filePath);
        $json = gzuncompress($compressed);
        $data = json_decode($json, true);

        return $data ?: [];
    }
}
```

### 3. Batch Operations

```php
// Process multiple security checks efficiently
function batchSecurityCheck(array $requests): array {
    $security = new SecurityManager();
    $results = [];

    // Group by action type for efficient rate limiting
    $groupedRequests = [];
    foreach ($requests as $index => $request) {
        $action = $request['action'];
        $groupedRequests[$action][] = ['index' => $index, 'data' => $request];
    }

    foreach ($groupedRequests as $action => $actionRequests) {
        foreach ($actionRequests as $request) {
            $result = $security->securityCheck(
                $action,
                $request['data']['post_data'],
                $request['data']['require_csrf'] ?? true,
                $request['data']['spam_threshold'] ?? 0.5,
                $request['data']['form_id'] ?? 'default'
            );

            $results[$request['index']] = $result;
        }
    }

    return $results;
}
```

## Troubleshooting

### Common Issues

#### 1. CSRF Token Validation Failing

```php
// Debug CSRF issues
$csrf = new CSRFToken();

// Check if tokens are being generated
$token = $csrf->generateToken('test_form');
echo "Generated token: " . $token . "\n";

// Check session storage
echo "Session data: " . print_r($_SESSION, true) . "\n";

// Check token validation
$isValid = $csrf->validateToken($token, 'test_form');
echo "Token valid: " . ($isValid ? 'Yes' : 'No') . "\n";

// Check for timing issues
echo "Token from request: " . ($_POST['csrf_token'] ?? 'Not found') . "\n";
```

#### 2. Rate Limiting Not Working

```php
// Debug rate limiting
$rateLimiter = new RateLimiter();

$clientIP = $_SERVER['REMOTE_ADDR'];
echo "Client IP: " . $clientIP . "\n";

// Check current request count
$count = $rateLimiter->getCurrentRequestCount($clientIP, 'test_action');
echo "Current requests: " . $count . "\n";

// Check if limited
$isLimited = $rateLimiter->isLimited($clientIP, 'test_action');
echo "Is limited: " . ($isLimited ? 'Yes' : 'No') . "\n";

// Check configuration
$config = $rateLimiter->getConfiguration();
echo "Rate limit config: " . print_r($config, true) . "\n";
```

#### 3. File Storage Permission Issues

```php
// Check storage permissions
$storage = new FileStorage();

$storageDir = '/path/to/storage';
echo "Storage directory: " . $storageDir . "\n";
echo "Directory exists: " . (is_dir($storageDir) ? 'Yes' : 'No') . "\n";
echo "Directory writable: " . (is_writable($storageDir) ? 'Yes' : 'No') . "\n";
echo "Directory permissions: " . substr(sprintf('%o', fileperms($storageDir)), -4) . "\n";

// Test write operation
try {
    $testId = $storage->insert('test_table', ['test' => 'data']);
    echo "Write test successful: " . $testId . "\n";
} catch (Exception $e) {
    echo "Write test failed: " . $e->getMessage() . "\n";
}
```

### Debugging Tools

```php
// Enable debug mode
class DebugSecurityManager extends SecurityManager {

    private bool $debugMode = true;

    public function securityCheck(
        string $actionType,
        array $postData,
        bool $requireCSRF = true,
        float $spamThreshold = 0.5,
        string $formId = 'default'
    ): array {

        if ($this->debugMode) {
            $this->logDebug("Starting security check", [
                'action' => $actionType,
                'form_id' => $formId,
                'require_csrf' => $requireCSRF,
                'spam_threshold' => $spamThreshold
            ]);
        }

        $result = parent::securityCheck($actionType, $postData, $requireCSRF, $spamThreshold, $formId);

        if ($this->debugMode) {
            $this->logDebug("Security check completed", [
                'passed' => $result['passed'],
                'reason' => $result['reason'],
                'checks' => $result['security_checks']
            ]);
        }

        return $result;
    }

    private function logDebug(string $message, array $context = []): void {
        error_log("DEBUG: " . $message . " - " . json_encode($context));
    }
}
```

## Security Considerations

### 1. Secure Configuration

- **Never disable security features in production**
- **Use strong, unique secrets for token signing**
- **Regularly rotate API tokens and secrets**
- **Monitor security logs for suspicious activity**
- **Keep framework updated to latest version**

### 2. Storage Security

```php
// Secure storage directory
// Set proper permissions: 755 for directory, 644 for files
chmod('/path/to/storage', 0755);

// Add .htaccess to prevent direct access
file_put_contents('/path/to/storage/.htaccess', "Deny from all\n");

// Store sensitive data encrypted
class EncryptedFileStorage extends FileStorage {

    private string $encryptionKey;

    public function __construct(string $key) {
        parent::__construct();
        $this->encryptionKey = $key;
    }

    public function write(string $table, array $data): bool {
        $json = json_encode($data);
        $encrypted = $this->encrypt($json);

        $filePath = $this->getFilePath($table);
        return file_put_contents($filePath, $encrypted, LOCK_EX) !== false;
    }

    public function read(string $table): array {
        $filePath = $this->getFilePath($table);

        if (!file_exists($filePath)) {
            return [];
        }

        $encrypted = file_get_contents($filePath);
        $json = $this->decrypt($encrypted);

        return json_decode($json, true) ?: [];
    }

    private function encrypt(string $data): string {
        $iv = random_bytes(16);
        $encrypted = openssl_encrypt($data, 'AES-256-CBC', $this->encryptionKey, 0, $iv);
        return base64_encode($iv . $encrypted);
    }

    private function decrypt(string $data): string {
        $data = base64_decode($data);
        $iv = substr($data, 0, 16);
        $encrypted = substr($data, 16);
        return openssl_decrypt($encrypted, 'AES-256-CBC', $this->encryptionKey, 0, $iv);
    }
}
```

### 3. Monitoring and Alerting

```php
// Set up security monitoring
class SecurityMonitor {

    private SecurityManager $security;
    private array $alertThresholds;

    public function __construct(SecurityManager $security) {
        $this->security = $security;
        $this->alertThresholds = [
            'failed_csrf' => 10,        // per hour
            'rate_limited' => 50,       // per hour
            'spam_detected' => 25,      // per hour
            'xss_attempts' => 5,        // per hour
        ];
    }

    public function checkAlerts(): void {
        $stats = $this->security->getSecurityStats();
        $recentEvents = $this->getRecentSecurityEvents();

        foreach ($this->alertThresholds as $eventType => $threshold) {
            $count = $this->countEventType($recentEvents, $eventType);

            if ($count >= $threshold) {
                $this->sendAlert($eventType, $count, $threshold);
            }
        }
    }

    private function getRecentSecurityEvents(): array {
        $storage = $this->security->getStorage();
        $events = $storage->find('security_log');
        $oneHourAgo = time() - 3600;

        return array_filter($events, function($event) use ($oneHourAgo) {
            return ($event['created_at'] ?? 0) > $oneHourAgo;
        });
    }

    private function countEventType(array $events, string $eventType): int {
        return count(array_filter($events, function($event) use ($eventType) {
            return strpos($event['event_type'] ?? '', $eventType) !== false;
        }));
    }

    private function sendAlert(string $eventType, int $count, int $threshold): void {
        $message = "Security Alert: {$count} {$eventType} events in the last hour (threshold: {$threshold})";

        // Send email, Slack notification, etc.
        error_log("SECURITY ALERT: " . $message);

        // Optional: Send to external monitoring service
        // $this->sendToMonitoringService($eventType, $count);
    }
}

// Use in cron job
$security = new SecurityManager();
$monitor = new SecurityMonitor($security);
$monitor->checkAlerts();
```

## API Reference

### SecurityManager

#### Constructor
```php
public function __construct(?int $userId = null)
```

#### Core Methods
```php
public function securityCheck(string $actionType, array $postData, bool $requireCSRF = true, float $spamThreshold = 0.5, string $formId = 'default'): array
public function initializeForm(string $formId = 'default'): array
public function getSecurityHeaders(): array
public function applySecurityHeaders(): void
public function validateContent(string $content, bool $allowHtml = false, bool $cleanProfanity = true): string
public function checkIPSecurity(string $ipAddress = null): array
public function generateAPIToken(int $userId, int $expiresIn = 3600): string
public function validateAPIToken(string $token): ?array
public function logSecurityEvent(string $eventType, array $details = []): void
public function getSecurityStats(): array
public function performMaintenance(): array
```

#### Component Getters
```php
public function getCSRFToken(): CSRFToken
public function getRateLimiter(): RateLimiter
public function getHoneypot(): Honeypot
public function getSpamDetector(): SpamDetector
public function getStorage(): FileStorage
```

### Individual Components

For detailed API reference of individual components, refer to the PHPDoc comments in each class file. Each component follows consistent patterns:

- **Constructor**: Initialize with configuration
- **Primary methods**: Core functionality (generate, validate, analyze, etc.)
- **Management methods**: Add, remove, update operations
- **Utility methods**: Statistics, cleanup, configuration
- **Internal methods**: Helper functions (marked as private/protected)

---

## Conclusion

The Yohns Security Framework provides a comprehensive, easy-to-use security solution for PHP applications. By following the patterns and best practices outlined in this guide, you can significantly improve your application's security posture while maintaining good performance and usability.

Remember to:
- Always enable security features in production
- Regularly update and maintain the framework
- Monitor security logs and statistics
- Follow secure coding practices
- Test security implementations thoroughly

For support, updates, and additional resources, visit the project repository or documentation site.