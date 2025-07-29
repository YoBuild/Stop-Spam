# Simple Real-World Examples: Using All Classes Through SecurityManager

This guide shows simple, practical examples of how to access and use each individual class through the `SecurityManager` for real-world applications.

## Basic Setup

```php
<?php
require_once 'vendor/autoload.php';

use Yohns\Security\SecurityManager;

// Start session for CSRF tokens
session_start();

// Initialize SecurityManager (this creates all component instances)
$security = new SecurityManager($_SESSION['user_id'] ?? null);
```

## 1. CSRFToken - Form Protection

**Purpose**: Protect forms against Cross-Site Request Forgery attacks

```php
// SIMPLE CONTACT FORM EXAMPLE
<?php
// Get the CSRF component
$csrf = $security->getCSRFToken();

if ($_POST) {
	// Validate CSRF token
	if (!$csrf->validateRequest('contact_form')) {
		die('Security validation failed!');
	}
	
	// Process form safely
	echo "Message sent successfully!";
}

// Generate form with CSRF protection
$token = $csrf->generateToken('contact_form');
?>

<form method="post">
	<input type="hidden" name="csrf_token" value="<?= $token ?>">
	<textarea name="message" required></textarea>
	<button type="submit">Send</button>
</form>
```

## 2. RateLimiter - Prevent Abuse

**Purpose**: Limit requests to prevent spam and brute force attacks

```php
// SIMPLE LOGIN RATE LIMITING
<?php
// Get the rate limiter component
$rateLimiter = $security->getRateLimiter();
$clientIP = $_SERVER['REMOTE_ADDR'];

if ($_POST) {
	// Check if IP is rate limited for login attempts
	if ($rateLimiter->isLimited($clientIP, 'login')) {
		$remaining = $rateLimiter->getBlockTimeRemaining($clientIP, 'login');
		die("Too many login attempts. Try again in " . ceil($remaining / 60) . " minutes.");
	}
	
	// Process login
	$loginSuccess = authenticate($_POST['username'], $_POST['password']);
	
	// Record the attempt (affects future rate limiting)
	$rateLimiter->recordAttempt($clientIP, 'login', $loginSuccess);
	
	if ($loginSuccess) {
		echo "Login successful!";
	} else {
		echo "Invalid credentials";
	}
}
?>

<form method="post">
	<input type="text" name="username" required>
	<input type="password" name="password" required>
	<button type="submit">Login</button>
</form>
```

## 3. SpamDetector - Content Analysis

**Purpose**: Detect and prevent spam content in user submissions

```php
// SIMPLE COMMENT SYSTEM WITH SPAM DETECTION
<?php
// Get the spam detector component
$spamDetector = $security->getSpamDetector();

if ($_POST) {
	$comment = $_POST['comment'] ?? '';
	
	// Analyze content for spam
	$analysis = $spamDetector->analyzeContent($comment);
	
	if ($analysis['spam_score'] > 0.7) {
		die("Comment flagged as spam (score: " . $analysis['spam_score'] . ")");
	}
	
	// Save comment to database
	saveComment($comment);
	echo "Comment posted successfully!";
}
?>

<form method="post">
	<textarea name="comment" placeholder="Write your comment..." required></textarea>
	<button type="submit">Post Comment</button>
</form>
```

## 4. Honeypot - Bot Detection

**Purpose**: Catch automated bots using hidden form fields

```php
// SIMPLE CONTACT FORM WITH BOT DETECTION
<?php
// Get the honeypot component
$honeypot = $security->getHoneypot();

if ($_POST) {
	// Check if submission is from a bot
	$result = $honeypot->validateSubmission($_POST, 'contact_form');
	
	if ($result['is_bot']) {
		die("Bot detected: " . $result['reason']);
	}
	
	// Process legitimate form
	echo "Thank you for your message!";
}

// Generate honeypot field
$honeypotField = $honeypot->generateField('contact_form');
?>

<style>
	/* Hide honeypot field from humans */
	.honeypot { display: none !important; }
</style>

<form method="post">
	<?= $honeypotField ?>
	<input type="text" name="name" placeholder="Your name" required>
	<textarea name="message" placeholder="Your message" required></textarea>
	<button type="submit">Send Message</button>
</form>
```

## 5. FileStorage - Data Management

**Purpose**: Store and retrieve security data using JSON files

```php
// SIMPLE SECURITY LOGGING
<?php
// Get the file storage component
$storage = $security->getStorage();

// Log a security event
function logSecurityEvent($eventType, $details) {
	global $storage;
	
	$storage->store('security_log', [
		'timestamp' => time(),
		'event_type' => $eventType,
		'ip_address' => $_SERVER['REMOTE_ADDR'],
		'details' => $details
	]);
}

// Log failed login attempt
logSecurityEvent('failed_login', [
	'username' => $_POST['username'] ?? '',
	'user_agent' => $_SERVER['HTTP_USER_AGENT']
]);

// Find recent security events
$recentEvents = $storage->find('security_log', [
	'event_type' => 'failed_login'
]);

echo "Recent failed login attempts: " . count($recentEvents);
?>
```

## 6. ContentValidator - Input Sanitization

**Purpose**: Validate and clean user input to prevent XSS and other attacks

```php
// SIMPLE BLOG POST VALIDATION
<?php
// Access through SecurityManager (recommended)
// Note: ContentValidator is accessed through other SecurityManager methods
// But here's how to get it directly if needed:

if ($_POST) {
	$title = $_POST['title'] ?? '';
	$content = $_POST['content'] ?? '';
	
	// Use SecurityManager's built-in content validation
	$cleanTitle = $security->validateContent($title, false, true);
	$cleanContent = $security->validateContent($content, true, true); // Allow HTML
	
	// Or access ContentValidator directly (advanced usage)
	// $validator = $security->getContentValidator(); // Not shown in docs but likely exists
	
	// Save cleaned content
	saveBlogPost($cleanTitle, $cleanContent);
	echo "Blog post published successfully!";
}
?>

<form method="post">
	<input type="text" name="title" placeholder="Post title" required>
	<textarea name="content" placeholder="Post content (HTML allowed)" required></textarea>
	<button type="submit">Publish</button>
</form>
```

## 7. IPSecurity - IP Management

**Purpose**: Block malicious IPs and track IP reputation

```php
// SIMPLE IP BLOCKING SYSTEM
<?php
// Access IPSecurity through SecurityManager
$clientIP = $_SERVER['REMOTE_ADDR'];

// Check if current IP is blocked
$ipCheck = $security->checkIPSecurity($clientIP);

if ($ipCheck['blocked']) {
	die("Access denied from your IP address: " . $ipCheck['reason']);
}

// For admin: Block an IP address
if ($_POST['action'] === 'block_ip' && isAdmin()) {
	$ipToBlock = $_POST['ip'];
	$reason = $_POST['reason'];
	
	// Note: Direct IPSecurity access not shown in docs, 
	// but would be through getter method like $security->getIPSecurity()
	// For now, use SecurityManager's methods
	
	echo "IP blocking functionality through SecurityManager";
}

echo "Welcome! Your IP: " . $clientIP . " (Trust score: " . ($ipCheck['trust_score'] * 100) . "%)";
?>
```

## 8. TokenManager - Token Lifecycle

**Purpose**: Generate and validate various types of security tokens

```php
// SIMPLE API TOKEN SYSTEM
<?php
if ($_POST['action'] === 'generate_token') {
	// Generate API token using SecurityManager
	$apiToken = $security->generateAPIToken($_SESSION['user_id'], 3600); // 1 hour
	
	echo "Your API token: " . $apiToken;
}

if ($_POST['action'] === 'validate_token') {
	$token = $_POST['token'];
	
	// Validate token using SecurityManager
	$tokenData = $security->validateAPIToken($token);
	
	if ($tokenData) {
		echo "Valid token for user: " . $tokenData['user_id'];
	} else {
		echo "Invalid or expired token";
	}
}
?>

<form method="post">
	<input type="hidden" name="action" value="generate_token">
	<button type="submit">Generate API Token</button>
</form>

<form method="post">
	<input type="hidden" name="action" value="validate_token">
	<input type="text" name="token" placeholder="Enter token to validate">
	<button type="submit">Validate Token</button>
</form>
```

## 9. ContentAnalyzer - Advanced Analysis

**Purpose**: Deep analysis of content for language detection, sentiment, etc.

```php
// SIMPLE CONTENT MODERATION
<?php
// Get the content analyzer through spam detector
$spamDetector = $security->getSpamDetector();

if ($_POST) {
	$userContent = $_POST['content'];
	
	// Basic spam analysis
	$spamAnalysis = $spamDetector->analyzeContent($userContent);
	
	// For advanced analysis, you'd access ContentAnalyzer directly
	// (not directly shown in SecurityManager docs)
	
	if ($spamAnalysis['spam_score'] > 0.5) {
		echo "Content needs moderation (score: " . $spamAnalysis['spam_score'] . ")";
		echo "Reasons: " . implode(', ', $spamAnalysis['reasons']);
	} else {
		echo "Content approved for publication";
	}
}
?>

<form method="post">
	<textarea name="content" placeholder="Enter content for analysis..." required></textarea>
	<button type="submit">Analyze Content</button>
</form>
```

## Complete Real-World Example: Secure Contact Form

Here's how to combine multiple components in one simple form:

```php
<?php
require_once 'vendor/autoload.php';
use Yohns\Security\SecurityManager;

session_start();
$security = new SecurityManager();

$message = '';

if ($_POST) {
	// Use SecurityManager's comprehensive security check
	$result = $security->securityCheck(
		'contact',        // Action type
		$_POST,          // Form data
		true,            // Require CSRF
		0.6,             // Spam threshold
		'contact_form'   // Form ID
	);
	
	if (!$result['passed']) {
		$message = "Security check failed: " . $result['reason'];
	} else {
		// Clean the content
		$cleanMessage = $security->validateContent($_POST['user_message'], false, true);
		
		// Process form
		$message = "Thank you! Your message has been sent.";
	}
}

// Initialize form security (generates CSRF + Honeypot)
$formSecurity = $security->initializeForm('contact_form');
?>

<!DOCTYPE html>
<html>
<head>
	<title>Secure Contact Form</title>
	<?= $formSecurity['csrf_meta'] ?>
	<?= $formSecurity['honeypot_css'] ?>
</head>
<body>
	<?php if ($message): ?>
		<div><?= htmlspecialchars($message) ?></div>
	<?php endif; ?>

	<form method="post">
		<?= $formSecurity['csrf_field'] ?>
		<?= $formSecurity['honeypot_field'] ?>
		
		<input type="text" name="name" placeholder="Your name" required>
		<input type="email" name="email" placeholder="Your email" required>
		<textarea name="user_message" placeholder="Your message" required></textarea>
		<button type="submit">Send Message</button>
	</form>
</body>
</html>
```

## Key Benefits of Using SecurityManager

1. **Single Entry Point**: One object gives you access to all security components
2. **Automatic Integration**: Components work together seamlessly
3. **Simplified API**: High-level methods handle complex security operations
4. **Consistent Configuration**: All components share the same configuration
5. **Easy Maintenance**: One place to manage all security features

## Component Access Pattern

```php
// Always start with SecurityManager
$security = new SecurityManager($userId);

// Access individual components when needed
$csrf = $security->getCSRFToken();
$rateLimiter = $security->getRateLimiter();
$honeypot = $security->getHoneypot();
$spamDetector = $security->getSpamDetector();
$storage = $security->getStorage();

// Use high-level SecurityManager methods for common operations
$formSecurity = $security->initializeForm('my_form');
$securityCheck = $security->securityCheck('action', $_POST, true, 0.5, 'my_form');
$cleanContent = $security->validateContent($userInput, false, true);
```

This approach ensures you're using the library correctly while maintaining clean, maintainable code that follows PHP 8.2+ standards with proper OOP design and tab indentation.
