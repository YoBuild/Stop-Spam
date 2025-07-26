# Yohns Stop Spam

A comprehensive spam prevention and security library for PHP 8.2+ applications. This library combines rate limiting, CSRF protection, honeypot fields, timing analysis, and content spam detection into a unified security solution.

## Features

### 🛡️ Core Security Components

- **CSRF Protection**: Token-based protection against cross-site request forgery
- **Rate Limiting**: Progressive timeouts with customizable thresholds
- **Honeypot Fields**: Hidden form fields to catch automated submissions
- **Content Spam Detection**: AI-powered content analysis with keyword filtering
- **File-based Storage**: Simple JSON file storage (no database required)

### 🚀 Advanced Features

- **Progressive Rate Limiting**: Automatic escalation for repeat offenders
- **Client-side Validation**: JavaScript validation with server-side verification
- **Comprehensive Logging**: Track security events and violations
- **Easy Configuration**: JSON-based configuration system
- **Automatic Cleanup**: Self-maintaining storage with configurable retention

## Installation

### Via Composer

```bash
composer require yohns/stop-spam
```

### Requirements

- PHP 8.2 or higher
- JSON extension
- yohns/config ^1.2

## More Information

### JavaScript Front End Docs and Code
 [README JavaScript Guide](README-JavaScript-GUIDE.md) - |.:.| - Code: [security-validator.js](public/assets/js/security-validator.js)

### More Reading
---
 - [Brief README](README-BRIEF.md)
 - [In Dept README](README-IN-DEPT.md)
---
### Docs for each Class
* [Yohns\AntiSpam\ContentAnalyzer](docs/AntiSpam/ContentAnalyzer.md)
  - ContentAnalyzer class for advanced content analysis and pattern detection.
  - Provides detailed content analysis including language detection, sentiment analysis, and advanced spam pattern recognition.
* [Yohns\AntiSpam\Honeypot](docs/AntiSpam/Honeypot.md)
  - Honeypot class for detecting automated bot submissions.
  - Uses hidden form fields and timing analysis to catch spam bots.
* [Yohns\AntiSpam\SpamDetector](docs/AntiSpam/SpamDetector.md)
  - SpamDetector class for comprehensive content spam detection
  - Analyzes content for spam patterns, keywords, and suspicious behavior. Uses machine learning-style scoring to determine spam likelihood.
* [Yohns\Security\ContentValidator](docs/Security/ContentValidator.md)
  - ContentValidator class for sanitizing and validating user input
  - Provides XSS protection, input sanitization, and content validation. Supports HTML filtering, email validation, URL validation, and comprehensive security threat detection with configurable rules and patterns.
* [Yohns\Security\CSRFToken](docs/Security/CSRFToken.md)
  - CSRFToken class for Cross-Site Request Forgery protection
  - Provides secure token generation and validation to prevent CSRF attacks. Supports multiple storage backends and provides flexible integration options.
* [Yohns\Security\FileStorage](docs/Security/FileStorage.md)
  - FileStorage class for managing JSON file-based data storage
  - This class provides a simple JSON file storage system to replace MySQL for security tokens, rate limits, and spam detection logs. Features automatic cleanup, file locking, and configurable permissions.
* [Yohns\Security\IPSecurity](docs/Security/IPSecurity.md)
  - IPSecurity class for IP-based security management
  - Handles IP whitelisting, blacklisting, geolocation, and reputation tracking. Provides comprehensive IP analysis including proxy detection, threat assessment, and automated security responses.
* [Yohns\Security\RateLimiter](docs/Security/RateLimiter.md)
  - RateLimiter class for preventing abuse through rate limiting
  - Implements progressive timeouts and tracks requests by IP and action type.
* [Yohns\Security\SecurityManager](docs/Security/SecurityManager.md)
  - SecurityManager class - Main security coordination class
  - Coordinates all security components for comprehensive protection. Provides a unified interface for CSRF protection, rate limiting, honeypot anti-spam, content validation, and security monitoring.
* [Yohns\Security\TokenManager](docs/Security/TokenManager.md)
  - TokenManager class for managing various types of security tokens
  - Handles API tokens, session tokens, verification tokens, and more. Provides comprehensive token lifecycle management including generation, validation, expiration, and usage tracking.

## Quick Start

### 1. Basic Setup

```php
<?php
require_once 'vendor/autoload.php';

use Yohns\Core\Config;
use Yohns\Security\SecurityManager;

// Initialize configuration
$config = new Config(__DIR__ . '/config');

// Start session
session_start();

// Initialize security manager
$security = new SecurityManager($_SESSION['user_id'] ?? null);
```

### 2. Secure Form Example

```php
// Initialize form security
$formSecurity = $security->initializeForm('contact_form');

// Handle form submission
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $securityCheck = $security->securityCheck('contact', $_POST, true, 0.6);

    if ($securityCheck['passed']) {
        // Process form safely
        $content = $security->validateContent($_POST['message']);
        echo "Message processed: " . htmlspecialchars($content);
    } else {
        echo "Security check failed: " . $securityCheck['reason'];
    }
}
?>

<form method="post" data-validate="true" id="contact_form">
    <?= $formSecurity['csrf_field'] ?>
    <?= $formSecurity['honeypot_field'] ?>

    <textarea name="message" placeholder="Your message"></textarea>
    <button type="submit">Submit</button>
</form>

<?= $formSecurity['honeypot_css'] ?>
<script src="public/assets/js/security-validator.js"></script>
```

## Configuration

### Basic Configuration (`config/security.php`)

```php
<?php
return [
    // File Storage Settings
    'storage' => [
        'type' => 'json',
        'directory' => __DIR__ . '/../database',
        'auto_cleanup' => true,
        'cleanup_interval' => 3600, // 1 hour
    ],

    // CSRF Protection
    'csrf' => [
        'enabled' => true,
        'expiration' => 1800, // 30 minutes
        'token_length' => 32,
    ],

    // Rate Limiting
    'rate_limiting' => [
        'enabled' => true,
        'login_max' => 5, // attempts per 15 minutes
        'per_ip' => 300, // requests per minute
        'block_duration' => 900, // 15 minutes
    ],

    // Spam Detection
    'spam_detection' => [
        'enabled' => true,
        'max_links' => 3,
        'max_capitals_percent' => 70,
    ],

    // Domain Configuration
    'domain' => [
        'base_url' => 'https://yoursite.com',
        'allowed_origins' => ['https://yoursite.com'],
    ],
];
```

## Components

### SecurityManager

The main coordination class that brings all security components together:

```php
$security = new SecurityManager($userId);

// Comprehensive security check
$result = $security->securityCheck('post', $_POST, true, 0.6);

// Individual component access
$csrf = $security->getCSRFToken();
$rateLimiter = $security->getRateLimiter();
$honeypot = $security->getHoneypot();
$spamDetector = $security->getSpamDetector();
```

### CSRF Protection

```php
$csrf = new CSRFToken();

// Generate token for form
$token = $csrf->generateToken('form_name');

// Validate token
if ($csrf->validateRequest('form_name')) {
    // Token is valid
}

// Get HTML field
echo $csrf->getHiddenField('form_name');
```

### Rate Limiting

```php
$rateLimiter = new RateLimiter();

// Check if request should be limited
if ($rateLimiter->isLimited($ipAddress, 'login', $userId)) {
    // Request is rate limited
    $remainingTime = $rateLimiter->getBlockTimeRemaining($identifier, 'login');
    echo "Try again in " . ceil($remainingTime / 60) . " minutes";
}
```

### Honeypot Detection

```php
$honeypot = new Honeypot();

// Initialize honeypot for form
$honeypotField = $honeypot->initialize('contact_form');

// Validate submission
$result = $honeypot->validate($_POST, 'contact_form');
if (!$result['passed']) {
    echo "Bot detected: " . $result['reason'];
}
```

### Spam Detection

```php
$spamDetector = new SpamDetector();

// Analyze content
$analysis = $spamDetector->analyzeContent($userContent);

if ($analysis['is_spam']) {
    echo "Spam detected (score: {$analysis['spam_score']})";
    echo "Reasons: " . implode(', ', $analysis['reasons']);
}

// Clean content
$cleanContent = $spamDetector->cleanContent($userContent);
```

## Frontend Integration

### JavaScript Security Validator

```html
<script src="public/assets/js/security-validator.js"></script>
<script>
SecurityValidator.init({
    enableBotDetection: true,
    enableTimingAnalysis: true,
    enableCSRFValidation: true,
    debugMode: false
});
</script>
```

## File Storage Structure

The library uses JSON files for data storage:

```
database/
├── csrf_tokens.json          # CSRF token storage
├── rate_limits.json          # Rate limiting data
├── spam_log.json             # Spam detection logs
├── honeypot_sessions.json    # Honeypot timing data
├── spam_keywords.json        # Spam keyword lists
├── profanity_list.json       # Profanity filter words
└── security_log.json         # General security events
```

## Directory Structure

```
yohns-stop-spam/
├── Yohns/
│   ├── Security/
│   │   ├── FileStorage.php
│   │   ├── CSRFToken.php
│   │   ├── RateLimiter.php
│   │   └── SecurityManager.php
│   └── AntiSpam/
│       ├── Honeypot.php
│       └── SpamDetector.php
├── config/
│   └── security.php
├── database/
├── docs/
├── examples/
│   └── bootstrap_form_example.php
├── public/assets/
│   ├── js/
│   │   └── security-validator.js
│   └── scss/
│       ├── main.scss
│       └── components/
└── composer.json
```

## API Reference

### SecurityManager Methods

- `securityCheck(string $actionType, array $postData, bool $requireCSRF = true, float $spamThreshold = 0.5, string $formId = 'default'): array`
- `initializeForm(string $formId = 'default'): array`
- `validateContent(string $content, bool $allowHtml = false, bool $cleanProfanity = true): string`
- `checkIPSecurity(string $ipAddress = null): array`
- `getSecurityStats(): array`
- `performMaintenance(): array`

### Rate Limiter Methods

- `isLimited(string $ipAddress, string $actionType, ?int $userId = null): bool`
- `isBlocked(string $identifier, string $actionType): bool`
- `getRemainingRequests(string $identifier, string $actionType): int`
- `getBlockTimeRemaining(string $identifier, string $actionType): int`

### Spam Detector Methods

- `analyzeContent(string $content): array`
- `cleanContent(string $content): string`
- `shouldAutoBlock(string $content): bool`
- `addSpamKeyword(string $keyword): bool`
- `removeSpamKeyword(string $keyword): bool`

## Examples

See the `examples/` directory for complete implementation examples:

- `bootstrap_form_example.php` - Complete Bootstrap 5.3.7 form with all security features
- `api_example.php` - API endpoint protection example
- `admin_dashboard.php` - Security statistics dashboard

## Performance

- **Lightweight**: Minimal memory footprint with efficient JSON storage
- **Fast**: Optimized algorithms with intelligent caching
- **Scalable**: File-based storage eliminates database dependencies
- **Configurable**: Adjust security levels based on your needs

## Security Best Practices

1. **Regular Updates**: Keep spam keywords and patterns updated
2. **Monitor Logs**: Review security logs regularly for patterns
3. **Adjust Thresholds**: Fine-tune detection thresholds based on your user base
4. **Backup Data**: Regularly backup your security configuration and logs
5. **HTTPS Only**: Always use HTTPS in production environments

## Contributing

1. Fork the repository
2. Create a feature branch
3. Add tests for new functionality
4. Follow PSR-12 coding standards
5. Submit a pull request

## License

MIT License - see LICENSE file for details.

## Support

- **Documentation**: Complete API documentation in `/docs`
- **Examples**: Working examples in `/examples`
- **Issues**: Report bugs and feature requests on GitHub

## Changelog

### v1.0.0
- Initial release
- Complete security suite with file-based storage
- Comprehensive JavaScript validation
- Full documentation and examples