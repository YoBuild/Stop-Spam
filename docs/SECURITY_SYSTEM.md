# Comprehensive Spam Prevention and Security System

A robust security system for social networks built with PHP 8.2+ OOP and vanilla JavaScript. This system provides comprehensive protection against spam, abuse, and security threats through multiple layers of defense.

## Features

### 🛡️ Core Security Components

- **Rate Limiting**: Progressive timeouts with customizable thresholds for different actions
- **CSRF Protection**: Token-based protection against cross-site request forgery
- **IP Security**: Blacklisting, whitelisting, and proxy-aware IP detection
- **Content Validation**: XSS prevention, spam detection, and profanity filtering
- **Token Management**: Secure token generation and validation for various purposes

### 🚀 Advanced Features

- **Progressive Rate Limiting**: Automatic escalation for repeat offenders
- **Client-side Validation**: JavaScript validation with server-side verification
- **Database Integration**: Persistent rate limiting and token storage
- **Configuration Management**: Easy-to-modify security settings
- **Comprehensive Logging**: Track security events and violations

## Installation

### 1. Database Setup

First, run the database schema to create the necessary tables:

```sql
-- Create rate limiting tables
CREATE TABLE `rate_limits` (
    `id` INT UNSIGNED NOT NULL AUTO_INCREMENT,
    `identifier` VARCHAR(255) NOT NULL COMMENT 'IP address or user ID',
    `action_type` VARCHAR(50) NOT NULL COMMENT 'Type of action (post, message, login, etc.)',
    `request_count` INT UNSIGNED NOT NULL DEFAULT 1,
    `first_request_time` TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    `last_request_time` TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    `blocked_until` TIMESTAMP NULL DEFAULT NULL,
    `created_at` TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    `updated_at` TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    PRIMARY KEY (`id`),
    UNIQUE KEY `identifier_action_idx` (`identifier`, `action_type`),
    INDEX `blocked_until_idx` (`blocked_until`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Create security tokens table
CREATE TABLE `security_tokens` (
    `id` INT UNSIGNED NOT NULL AUTO_INCREMENT,
    `token` VARCHAR(64) NOT NULL,
    `context` VARCHAR(50) NOT NULL,
    `expires_at` INT UNSIGNED NOT NULL,
    `data` TEXT NULL,
    `created_at` INT UNSIGNED NOT NULL,
    PRIMARY KEY (`id`),
    UNIQUE INDEX `token_idx` (`token`),
    INDEX `context_idx` (`context`),
    INDEX `expires_at_idx` (`expires_at`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
```

### 2. Configuration

Place the configuration files in your `config/` directory:

- `config/security.php` - Main security settings
- `config/rate_limits.php` - Rate limiting configuration

### 3. Basic Implementation

```php
<?php
use Yohns\Core\Config;
use Yohns\Core\Security\SecurityManager;
use PDOChainer\PDOChainer;

// Initialize configuration
$config = new Config(__DIR__ . '/config');

// Initialize database connection
$pdo = new PDOChainer([
    'host' => 'localhost',
    'dbname' => 'your_database',
    'user' => 'your_username',
    'pass' => 'your_password'
]);

// Initialize security manager
$security = new SecurityManager($pdo, $_SESSION['user_id'] ?? null);
```

## Usage Examples

### Rate Limiting

```php
// Check if user is rate limited for posting
if ($security->isRateLimited('post')) {
    echo "You're posting too frequently. Please wait a moment.";
    exit;
}

// Get rate limit information
$rateLimitInfo = $security->getRateLimitInfo('post');
echo "Remaining requests: " . $rateLimitInfo['remaining'];
```

### CSRF Protection

```php
// Generate CSRF token for forms
echo $security->csrfField();

// Validate CSRF token on form submission
if (!$security->validateCsrfToken($_POST)) {
    die('Invalid security token');
}
```

### Content Validation

```php
// Validate and sanitize user content
$cleanContent = $security->validateContent($_POST['message'], false, true);

// Check for spam
if ($security->containsSpam($_POST['message'], 0.6)) {
    echo "Content flagged as potential spam";
}
```

### IP Security

```php
// Check if IP is blacklisted
if ($security->isIpBlacklisted()) {
    die('Access denied');
}

// Get client IP (proxy-aware)
$clientIp = $security->getClientIp();
$anonymizedIp = $security->getClientIp(true); // For logging
```

### Comprehensive Security Check

```php
// Perform all security checks at once
$securityCheck = $security->securityCheck('post', $_POST, true, 0.6);

if (!$securityCheck['passed']) {
    echo "Security check failed: " . $securityCheck['reason'];
    // Handle failure appropriately
}
```

## Client-Side Integration

Include the JavaScript security client in your pages:

```html
<script src="assets/js/SecurityClient.js"></script>
```

### HTML Form Integration

```html
<form method="post" data-validate="true" data-action-type="post">
    <?php echo $security->csrfField(); ?>

    <textarea
        name="content"
        data-validate="required maxlength spam-check"
        data-maxlength="500"
        data-spam-keywords="spam,fake,scam"
        placeholder="What's on your mind?">
    </textarea>

    <button type="submit">Post</button>
</form>
```

### JavaScript Validation

```javascript
// Client-side spam detection
if (window.securityClient.containsSpam(userInput)) {
    alert('Content may contain spam');
}

// Secure AJAX requests
window.securityClient.secureFetch('/api/data', {
    method: 'POST',
    body: JSON.stringify(data)
});
```

## Configuration Options

### Rate Limiting Configuration

```php
// config/rate_limits.php
return [
    'post' => [
        'max_requests' => 10,       // Maximum posts
        'time_window' => 600,       // Time window in seconds (10 minutes)
        'block_duration' => 1800,   // Block duration in seconds (30 minutes)
        'block_multiplier' => 2.0,  // Multiplier for repeat offenders
    ],
    // ... more action types
];
```

### Security Configuration

```php
// config/security.php
return [
    'spam_keywords' => ['spam', 'fake', 'scam'],
    'spam_patterns' => [
        '/https?:\/\/.*\.(xyz|top|loan)\b/i',
        // ... more patterns
    ],
    'blacklisted_ips' => ['192.168.1.100'],
    'whitelisted_ips' => ['127.0.0.1'],
    // ... more settings
];
```

## Advanced Features

### Custom Rate Limiting

```php
// Add custom rate limit for a new action type
$rateLimiter = new RateLimiter($pdo);
if ($rateLimiter->isLimited($clientIp, 'custom_action', $userId)) {
    // Handle rate limit
}
```

### Token Management

```php
// Generate custom tokens
$passwordResetToken = $security->generateToken('password_reset', 3600, [
    'user_id' => 123,
    'email' => 'user@example.com'
]);

// Validate tokens
if ($security->validateToken($token, 'password_reset')) {
    // Token is valid, proceed with password reset
}
```

### Content Filtering

```php
// Add custom spam keywords
$contentValidator = new ContentValidator();
$contentValidator->addSpamKeyword('new-spam-word');

// Add custom spam patterns
$contentValidator->addSpamPattern('/custom-pattern/i');
```

### IP Management

```php
// Blacklist an IP
$security->blacklistIp('192.168.1.100');

// Whitelist an IP (bypasses rate limiting)
$ipSecurity = new IPSecurity();
$ipSecurity->addToWhitelist('trusted.server.ip');
```

## Security Best Practices

### 1. Server Configuration

- Use HTTPS in production
- Configure proper session settings
- Set appropriate file upload limits
- Enable proper error logging

### 2. Database Security

- Use prepared statements (handled by PDOChainer)
- Regularly clean up expired tokens and rate limit data
- Monitor for suspicious activity patterns

### 3. Rate Limiting Strategy

- Set reasonable limits for different actions
- Monitor and adjust thresholds based on usage patterns
- Consider user reputation when setting limits

### 4. Content Validation

- Always validate on both client and server side
- Keep spam patterns updated
- Monitor content for new spam techniques

### 5. Token Management

- Use appropriate expiration times
- Invalidate tokens after use when appropriate
- Monitor for token abuse

## Monitoring and Maintenance

### Regular Cleanup

```php
// Clean up expired data (run via cron job)
$cleanup = $security->cleanupExpiredData();
echo "Cleaned up {$cleanup['tokens_removed']} expired tokens";
```

### Monitoring Dashboard

```php
// Get security statistics
function getSecurityStats($pdo) {
    $dbal = new DBAL($pdo);

    // Count blocked IPs
    $blockedIps = $dbal->select(
        "SELECT COUNT(DISTINCT identifier) as count
         FROM rate_limits
         WHERE blocked_until > NOW()", 1
    );

    // Count rate limited actions in last hour
    $recentBlocks = $dbal->select(
        "SELECT COUNT(*) as count
         FROM rate_limits
         WHERE blocked_until > DATE_SUB(NOW(), INTERVAL 1 HOUR)", 1
    );

    return [
        'blocked_ips' => $blockedIps['count'] ?? 0,
        'recent_blocks' => $recentBlocks['count'] ?? 0
    ];
}
```

### Automated Alerts

```php
// Check for suspicious activity
function checkSuspiciousActivity($security) {
    $stats = getSecurityStats($security);

    // Alert if too many blocks in short time
    if ($stats['recent_blocks'] > 50) {
        // Send alert to administrators
        error_log("Security Alert: High number of rate limit blocks detected");
    }
}
```

## Troubleshooting

### Common Issues

1. **Rate Limiting Too Aggressive**
   - Adjust `max_requests` and `time_window` in config
   - Consider user patterns and legitimate usage

2. **False Spam Detection**
   - Review and refine spam keywords and patterns
   - Adjust spam threshold (lower = less strict)

3. **CSRF Token Validation Fails**
   - Ensure session is started before token generation
   - Check that forms include the CSRF field
   - Verify token isn't expired

4. **IP Detection Issues Behind Proxy**
   - Configure `trusted_proxies` in security config
   - Ensure proxy headers are being sent correctly

### Debug Mode

```php
// Enable debug logging
ini_set('log_errors', 1);
ini_set('error_log', '/path/to/security.log');

// Add debug output to security checks
$securityCheck = $security->securityCheck('post', $_POST, true, 0.6);
error_log('Security check result: ' . json_encode($securityCheck));
```

## Performance Optimization

### Database Indexes

Ensure proper indexes are created:

```sql
-- Additional indexes for performance
CREATE INDEX idx_rate_limits_expires ON rate_limits(blocked_until);
CREATE INDEX idx_security_tokens_expires ON security_tokens(expires_at);
CREATE INDEX idx_rate_limits_time ON rate_limits(first_request_time, action_type);
```

### Caching

```php
// Use APCu for in-memory caching of security configs
if (function_exists('apcu_fetch')) {
    $cacheKey = 'security_config_' . md5('security');
    $config = apcu_fetch($cacheKey);

    if ($config === false) {
        $config = Config::getAll('security');
        apcu_store($cacheKey, $config, 3600); // Cache for 1 hour
    }
}
```

### Cleanup Scheduling

Add to your crontab:

```bash
# Clean up expired security data every hour
0 * * * * /usr/bin/php /path/to/your/app/cleanup_security.php

# Daily security monitoring report
0 9 * * * /usr/bin/php /path/to/your/app/security_report.php
```

## API Integration

### RESTful API Security

```php
// API endpoint with security
header('Content-Type: application/json');

// Check rate limiting for API calls
if ($security->isRateLimited('api_call')) {
    http_response_code(429);
    echo json_encode(['error' => 'Rate limit exceeded']);
    exit;
}

// Validate API token
$apiToken = $_SERVER['HTTP_AUTHORIZATION'] ?? '';
if (!$security->validateToken($apiToken, 'api_access', false)) {
    http_response_code(401);
    echo json_encode(['error' => 'Invalid API token']);
    exit;
}

// Process API request...
```

### CORS Security

```php
// Secure CORS headers
$allowedOrigins = Config::get('allowed_origins', 'security') ?: [];
$origin = $_SERVER['HTTP_ORIGIN'] ?? '';

if (in_array($origin, $allowedOrigins)) {
    header("Access-Control-Allow-Origin: $origin");
    header('Access-Control-Allow-Credentials: true');
    header('Access-Control-Allow-Methods: GET, POST, PUT, DELETE, OPTIONS');
    header('Access-Control-Allow-Headers: Content-Type, Authorization, X-CSRF-Token');
}
```

## Testing

### Unit Tests Example

```php
// PHPUnit test example
class SecurityManagerTest extends PHPUnit\Framework\TestCase {
    private $security;

    public function setUp(): void {
        $pdo = new PDOChainer(['host' => 'localhost', 'dbname' => 'test_db']);
        $this->security = new SecurityManager($pdo);
    }

    public function testRateLimiting() {
        // Test that rate limiting works
        for ($i = 0; $i < 15; $i++) {
            $isLimited = $this->security->isRateLimited('test_action');
            if ($i >= 10) { // Assuming max 10 requests
                $this->assertTrue($isLimited);
            }
        }
    }

    public function testSpamDetection() {
        $spamContent = "BUY NOW! LIMITED TIME OFFER! CLICK HERE!";
        $normalContent = "This is a normal message.";

        $this->assertTrue($this->security->containsSpam($spamContent));
        $this->assertFalse($this->security->containsSpam($normalContent));
    }
}
```

## Contributing

When extending the security system:

1. **Follow PSR Standards**: Use PSR-12 coding standards
2. **Add Tests**: Include unit tests for new features
3. **Update Documentation**: Keep docs current with changes
4. **Security Review**: Have security-sensitive changes reviewed
5. **Performance Testing**: Test impact on application performance

## Security Considerations

### Important Notes

- **Regular Updates**: Keep spam patterns and security configs updated
- **Monitoring**: Implement comprehensive logging and monitoring
- **Backup**: Regularly backup security configurations and rate limit data
- **Access Control**: Restrict access to security management functions
- **SSL/TLS**: Always use HTTPS in production environments

### Reporting Security Issues

If you discover a security vulnerability:

1. **Do not** create a public issue
2. Email security concerns to your security team
3. Include detailed reproduction steps
4. Allow time for patch development before disclosure

## License

This security system is part of the Yohns framework and follows the same licensing terms.

## Support

For questions about implementation or configuration:

1. Check the examples in `examples/security_usage_example.php`
2. Review the inline documentation in each class
3. Test in a development environment before deploying
4. Monitor logs for unusual patterns after deployment