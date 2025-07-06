<?php
/**
 * Example implementation file showing how to use the security system components together
 */

// Include autoloader or require necessary files
// require_once 'path/to/autoloader.php';

use Yohns\Core\Config;
use Yohns\Security\SecurityConfig;
use Yohns\Security\CSRFToken;
use Yohns\Security\Honeypot;
use Yohns\Security\SpamDetector;
use Yohns\Security\TokenStorage;
use PDOChainer\PDOChainer;

// Step 1: Initialize configuration
SecurityConfig::load();

// Step 2: Initialize database connection (for database token storage)
$dbOptions = [
	'host' => Config::get('db_host', 'database'),
	'dbname' => Config::get('db_name', 'database'),
	'user' => Config::get('db_user', 'database'),
	'pass' => Config::get('db_pass', 'database')
];

$pdo = new PDOChainer($dbOptions);

// Step 3: Initialize token storage (optional, for database-based tokens)
if (SecurityConfig::get('token_storage') === 'database') {
	TokenStorage::init($pdo);
}

// Step 4: Create a SpamDetector instance
$detector = new SpamDetector([
	'use_honeypot' => SecurityConfig::get('honeypot_enabled', true),
	'use_timing' => true,
	'use_csrf' => SecurityConfig::get('csrf_enabled', true),
	'use_challenge' => SecurityConfig::get('challenge_enabled', false),
	'log_detections' => SecurityConfig::get('spam_log_enabled', true),
	'log_file' => SecurityConfig::get('spam_log_file', '../logs/spam_detection.log')
]);

// Step 5: Handle form submission
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
	$formId = 'contact_form'; // Identifier for this form

	if ($detector->validateRequest($_POST, $formId)) {
		// Form validation passed, process the submission
		$name = $_POST['name'] ?? '';
		$email = $_POST['email'] ?? '';
		$message = $_POST['message'] ?? '';

		// Process the form data...
		$success = true;
		$error = '';
	} else {
		// Spam detected, reject the submission
		$success = false;
		$error = 'Your submission was flagged as potential spam. Please try again.';
	}
}

// Step 6: Generate the form with security measures
?>
<!DOCTYPE html>
<html lang="en">
<head>
	<meta charset="UTF-8">
	<meta name="viewport" content="width=device-width, initial-scale=1.0">
	<title>Contact Form Example</title>
	<style>
		body { font-family: Arial, sans-serif; line-height: 1.6; max-width: 800px; margin: 0 auto; padding: 20px; }
		.form-group { margin-bottom: 15px; }
		label { display: block; margin-bottom: 5px; }
		input, textarea { width: 100%; padding: 8px; }
		button { padding: 10px 15px; background: #4CAF50; color: white; border: none; cursor: pointer; }
		.error { color: red; }
		.success { color: green; }
	</style>
</head>
<body>
	<h1>Contact Form</h1>

	<?php if (isset($success)): ?>
		<?php if ($success): ?>
			<div class="success">Your message was sent successfully!</div>
		<?php else: ?>
			<div class="error"><?= htmlspecialchars($error) ?></div>
		<?php endif; ?>
	<?php endif; ?>

	<form method="post" action="">
		<div class="form-group">
			<label for="name">Name:</label>
			<input type="text" id="name" name="name" required>
		</div>

		<div class="form-group">
			<label for="email">Email:</label>
			<input type="email" id="email" name="email" required>
		</div>

		<div class="form-group">
			<label for="message">Message:</label>
			<textarea id="message" name="message" rows="5" required></textarea>
		</div>

		<?= $detector->protectForm('contact_form') ?>

		<button type="submit">Send Message</button>
	</form>

	<!-- Include the JavaScript validator -->
	<script src="/js/SecurityValidator.js"></script>
	<script>
		// Initialize with custom options
		document.addEventListener('DOMContentLoaded', () => {
			new SecurityValidator('form', {
				minSubmitTime: 1500 // 1.5 seconds
			});
		});
	</script>
</body>
</html>