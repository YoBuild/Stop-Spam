<?php

require_once __DIR__ . '/../Core/Config.php';
require_once __DIR__ . '/../Core/ConfigEditor.php';
require_once __DIR__ . '/../src/PDOChainer/PDOChainer.php';
require_once __DIR__ . '/../src/PDOChainer/DBAL.php';
require_once __DIR__ . '/../Core/Security/RateLimiter.php';
require_once __DIR__ . '/../Core/Security/TokenManager.php';
require_once __DIR__ . '/../Core/Security/IPSecurity.php';
require_once __DIR__ . '/../Core/Security/ContentValidator.php';
require_once __DIR__ . '/../Core/Security/SecurityManager.php';

use Yohns\Core\Config;
use Yohns\Core\Security\SecurityManager;
use PDOChainer\PDOChainer;

/**
 * Example usage of the comprehensive security system
 *
 * This file demonstrates how to integrate the security system
 * into your social network application.
 */

// Initialize configuration
$config = new Config(__DIR__ . '/../config');

// Database configuration
$dbConfig = [
	'host'   => Config::get('host', 'database') ?: 'localhost',
	'port'   => Config::get('port', 'database') ?: 3306,
	'dbname' => Config::get('dbname', 'database') ?: 'social_network',
	'user'   => Config::get('user', 'database') ?: 'root',
	'pass'   => Config::get('pass', 'database') ?: '',
];

// Initialize PDO connection
try {
	$pdo = new PDOChainer($dbConfig);
} catch (Exception $e) {
	die('Database connection failed: ' . $e->getMessage());
}

// Start session for CSRF protection
session_start();

// Get current user ID (replace with your authentication logic)
$currentUserId = $_SESSION['user_id'] ?? null;

// Initialize the security manager
$security = new SecurityManager($pdo, $currentUserId);

/**
 * Example 1: Basic security check for form submission
 */
function handlePostSubmission($security) {
	echo "<h2>Example 1: Post Submission with Security Check</h2>\n";

	// Perform comprehensive security check
	$securityCheck = $security->securityCheck('post', $_POST, true, 0.6);

	if (!$securityCheck['passed']) {
		echo "<p style='color: red;'>Security check failed: {$securityCheck['reason']}</p>\n";

		foreach ($securityCheck['details'] as $detail) {
			echo "<p style='color: red;'>- {$detail}</p>\n";
		}

		return false;
	}

	// Validate and sanitize content
	if (isset($_POST['content'])) {
		$cleanContent = $security->validateContent($_POST['content'], false, true);
		echo "<p style='color: green;'>Content validated and sanitized successfully.</p>\n";
		echo "<p><strong>Clean content:</strong> " . htmlspecialchars($cleanContent) . "</p>\n";
	}

	echo "<p style='color: green;'>Post submission would be processed here.</p>\n";
	return true;
}

/**
 * Example 2: CSRF protection for forms
 */
function generateSecureForm($security) {
	echo "<h2>Example 2: Form with CSRF Protection</h2>\n";

	echo '<form method="post" action="" data-validate="true" data-action-type="post">' . "\n";
	echo $security->csrfField() . "\n";
	echo '<textarea name="content" placeholder="What\'s on your mind?" data-validate="required maxlength spam-check" data-maxlength="500" data-spam-keywords="spam,fake,scam"></textarea><br>' . "\n";
	echo '<button type="submit" name="submit_post">Post</button>' . "\n";
	echo '</form>' . "\n";
}

/**
 * Example 3: Rate limiting check
 */
function checkRateLimits($security) {
	echo "<h2>Example 3: Rate Limiting Status</h2>\n";

	$actions = ['post', 'message', 'search', 'login'];

	foreach ($actions as $action) {
		$rateLimitInfo = $security->getRateLimitInfo($action);

		echo "<h3>{$action} Rate Limit:</h3>\n";
		echo "<ul>\n";
		echo "<li>Remaining requests: {$rateLimitInfo['remaining']}</li>\n";
		echo "<li>Blocked: " . ($rateLimitInfo['blocked'] ? 'Yes' : 'No') . "</li>\n";

		if ($rateLimitInfo['wait_seconds'] > 0) {
			echo "<li>Wait time: {$rateLimitInfo['wait_seconds']} seconds</li>\n";
		}

		echo "</ul>\n";
	}
}

/**
 * Example 4: Token generation and validation
 */
function demonstrateTokens($security) {
	echo "<h2>Example 4: Token Management</h2>\n";

	// Generate a password reset token
	$resetToken = $security->generateToken('password_reset', 3600, ['user_id' => 123]);
	echo "<p><strong>Password reset token:</strong> {$resetToken}</p>\n";

	// Validate the token
	if ($security->validateToken($resetToken, 'password_reset', false)) {
		echo "<p style='color: green;'>Token is valid!</p>\n";
	} else {
		echo "<p style='color: red;'>Token is invalid!</p>\n";
	}

	// Generate an email verification token
	$emailToken = $security->generateToken('email_verification', 86400, ['email' => 'user@example.com']);
	echo "<p><strong>Email verification token:</strong> {$emailToken}</p>\n";
}

/**
 * Example 5: IP security checks
 */
function demonstrateIPSecurity($security) {
	echo "<h2>Example 5: IP Security</h2>\n";

	$clientIp = $security->getClientIp();
	echo "<p><strong>Client IP:</strong> {$clientIp}</p>\n";
	echo "<p><strong>Anonymized IP:</strong> " . $security->getClientIp(true) . "</p>\n";

	if ($security->isIpBlacklisted()) {
		echo "<p style='color: red;'>Your IP is blacklisted!</p>\n";
	} else {
		echo "<p style='color: green;'>Your IP is not blacklisted.</p>\n";
	}
}

/**
 * Example 6: Content validation
 */
function demonstrateContentValidation($security) {
	echo "<h2>Example 6: Content Validation</h2>\n";

	$testContent = [
		"This is a normal message.",
		"BUY NOW! LIMITED TIME OFFER! CLICK HERE FOR FREE MONEY!",
		"Check out this amazing deal at http://suspicious.xyz/offer",
		"Hello <script>alert('xss')</script> world!",
	];

	foreach ($testContent as $index => $content) {
		echo "<h4>Test Content " . ($index + 1) . ":</h4>\n";
		echo "<p><strong>Original:</strong> " . htmlspecialchars($content) . "</p>\n";

		$sanitized = $security->validateContent($content, false, true);
		echo "<p><strong>Sanitized:</strong> " . htmlspecialchars($sanitized) . "</p>\n";

		$isSpam = $security->containsSpam($content, 0.5);
		echo "<p><strong>Is Spam:</strong> " . ($isSpam ? 'Yes' : 'No') . "</p>\n";
		echo "<hr>\n";
	}
}

/**
 * Example 7: Administrative functions
 */
function demonstrateAdminFunctions($security) {
	echo "<h2>Example 7: Administrative Functions</h2>\n";

	// Cleanup expired data
	$cleanup = $security->cleanupExpiredData();
	echo "<p>Cleaned up {$cleanup['tokens_removed']} expired tokens.</p>\n";

	// Example: Blacklist an IP (be careful with this!)
	// $security->blacklistIp('192.168.1.100');
	// echo "<p>IP 192.168.1.100 has been blacklisted.</p>\n";
}

// Process form submission if present
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['submit_post'])) {
	handlePostSubmission($security);
	echo "<hr>\n";
}

?>
<!DOCTYPE html>
<html lang="en">
<head>
	<meta charset="UTF-8">
	<meta name="viewport" content="width=device-width, initial-scale=1.0">
	<title>Security System Demo</title>
	<meta name="csrf-token" content="<?php echo $security->generateCsrfToken(); ?>">
	<style>
		body {
			font-family: Arial, sans-serif;
			max-width: 800px;
			margin: 0 auto;
			padding: 20px;
		}

		textarea {
			width: 100%;
			height: 100px;
			margin: 10px 0;
		}

		button {
			padding: 10px 20px;
			background: #007cba;
			color: white;
			border: none;
			border-radius: 4px;
			cursor: pointer;
		}

		button:hover {
			background: #005a8b;
		}

		hr {
			margin: 30px 0;
		}
	</style>
</head>
<body>
	<h1>Comprehensive Security System Demo</h1>
	<?php
	// Run all demonstrations
	generateSecureForm($security);
	echo "<hr>\n";

	checkRateLimits($security);
	echo "<hr>\n";

	demonstrateTokens($security);
	echo "<hr>\n";

	demonstrateIPSecurity($security);
	echo "<hr>\n";

	demonstrateContentValidation($security);
	echo "<hr>\n";

	demonstrateAdminFunctions($security);
	?>
	<!-- Include the client-side security JavaScript -->
	<script src="../assets/js/SecurityClient.js"></script>
	<script>
		// Example of using the JavaScript security client
		document.addEventListener('DOMContentLoaded', function () {
			// Test client-side spam detection
			const testText = "BUY NOW! LIMITED TIME OFFER! CLICK HERE!";

			if (window.securityClient && window.securityClient.containsSpam(testText)) {
				console.log('Client-side spam detection working!');
			}

			// Test secure fetch
			if (window.securityClient) {
				// Example: window.securityClient.secureFetch('/api/data', { method: 'GET' });
			}
		});
	</script>
</body>
</html>