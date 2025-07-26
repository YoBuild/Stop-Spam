<?php

require_once __DIR__ . '/../vendor/autoload.php';

use Yohns\Core\Config;
use Yohns\Security\SecurityManager;

// Initialize configuration
$config = new Config(__DIR__ . '/../config');

// Start session
session_start();

// Initialize security manager
$security = new SecurityManager($_SESSION['user_id'] ?? null);

// Handle form submission
$message = '';
$alertClass = 'alert-info';

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
	$securityCheck = $security->securityCheck('post', $_POST, true, 0.6);

	if ($securityCheck['passed']) {
		$content = $security->validateContent($_POST['content'] ?? '', false, true);
		$message = 'Post submitted successfully! Content: ' . htmlspecialchars($content);
		$alertClass = 'alert-success';
	} else {
		$message = 'Security check failed: ' . $securityCheck['reason'];
		if (!empty($securityCheck['details'])) {
			$message .= '<br>Details: ' . implode('<br>', $securityCheck['details']);
		}
		$alertClass = 'alert-danger';
	}
}

// Initialize form security
$formSecurity = $security->initializeForm('post_form');

// Apply security headers
$security->applySecurityHeaders();

?>
<!DOCTYPE html>
<html lang="en">
<head>
	<meta charset="UTF-8">
	<meta name="viewport" content="width=device-width, initial-scale=1.0">
	<title>Yohns Stop Spam - Bootstrap Example</title>
	<!-- Bootstrap 5.3.7 CSS -->
	<link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.7/dist/css/bootstrap.min.css" rel="stylesheet">
	<!-- CSRF Meta Tag -->
	<?= $formSecurity['csrf_meta'] ?>
	<!-- Honeypot CSS -->
	<?= $formSecurity['honeypot_css'] ?>
	<style>
		.security-info {
			font-size: 0.875rem;
			color: #6c757d;
		}

		.security-stats {
			background-color: #f8f9fa;
			border-radius: 0.375rem;
			padding: 1rem;
			margin-top: 1rem;
		}

		.form-demo {
			background: white;
			border-radius: 0.5rem;
			box-shadow: 0 0.125rem 0.25rem rgba(0, 0, 0, 0.075);
			padding: 2rem;
			margin-bottom: 2rem;
		}
	</style>
</head>
<body class="bg-light">
	<nav class="navbar navbar-expand-lg navbar-dark bg-dark">
		<div class="container">
			<a class="navbar-brand" href="#">
				<i class="bi bi-shield-check"></i> Yohns Stop Spam </a>
			<div class="navbar-nav ms-auto">
				<span class="navbar-text"> Security Demo </span>
			</div>
		</div>
	</nav>
	<div class="container mt-4">
		<div class="row">
			<div class="col-lg-8">
				<!-- Page Header -->
				<div class="mb-4">
					<h1 class="display-5">Security Form Example</h1>
					<p class="lead text-muted"> This form demonstrates comprehensive spam prevention and security features
						including CSRF protection, honeypot fields, timing analysis, and content validation. </p>
				</div>
				<!-- Alert Messages -->
				<?php if ($message): ?>
					<div class="alert <?= $alertClass ?> alert-dismissible fade show" role="alert">
						<?= $message ?>
						<button type="button" class="btn-close" data-bs-dismiss="alert"></button>
					</div>
				<?php endif; ?>
				<!-- Main Form -->
				<div class="form-demo">
					<h3 class="mb-3">Create a Post</h3>
					<form method="post" data-validate="true" data-action-type="post" id="post_form" class="needs-validation"
						novalidate>
						<!-- CSRF Token -->
						<?= $formSecurity['csrf_field'] ?>
						<!-- Honeypot Field -->
						<?= $formSecurity['honeypot_field'] ?>
						<!-- Title Field -->
						<div class="mb-3">
							<label for="title" class="form-label">Post Title</label>
							<input type="text" class="form-control" id="title" name="title" placeholder="Enter your post title"
								maxlength="200" required>
							<div class="invalid-feedback"> Please provide a valid title. </div>
						</div>
						<!-- Content Field -->
						<div class="mb-3">
							<label for="content" class="form-label">Post Content</label>
							<textarea class="form-control" id="content" name="content" rows="6"
								placeholder="Write your post content here..." maxlength="5000" required></textarea>
							<div class="form-text"> Maximum 5000 characters. HTML tags will be stripped for security. </div>
							<div class="invalid-feedback"> Please provide some content for your post. </div>
						</div>
						<!-- Category Field -->
						<div class="mb-3">
							<label for="category" class="form-label">Category</label>
							<select class="form-select" id="category" name="category" required>
								<option value="">Choose a category...</option>
								<option value="general">General</option>
								<option value="technology">Technology</option>
								<option value="science">Science</option>
								<option value="business">Business</option>
								<option value="entertainment">Entertainment</option>
							</select>
							<div class="invalid-feedback"> Please select a category. </div>
						</div>
						<!-- Tags Field -->
						<div class="mb-3">
							<label for="tags" class="form-label">Tags (Optional)</label>
							<input type="text" class="form-control" id="tags" name="tags"
								placeholder="e.g., technology, programming, web" data-bs-toggle="tooltip"
								title="Separate tags with commas">
							<div class="form-text"> Separate multiple tags with commas. </div>
						</div>
						<!-- Privacy Options -->
						<div class="mb-3">
							<label class="form-label">Privacy Settings</label>
							<div class="form-check">
								<input class="form-check-input" type="radio" name="privacy" id="privacy_public" value="public" checked>
								<label class="form-check-label" for="privacy_public"> Public - Anyone can see this post </label>
							</div>
							<div class="form-check">
								<input class="form-check-input" type="radio" name="privacy" id="privacy_friends" value="friends">
								<label class="form-check-label" for="privacy_friends"> Friends only - Only your friends can see this
								</label>
							</div>
							<div class="form-check">
								<input class="form-check-input" type="radio" name="privacy" id="privacy_private" value="private">
								<label class="form-check-label" for="privacy_private"> Private - Only you can see this post </label>
							</div>
						</div>
						<!-- Submit Button -->
						<div class="d-grid gap-2 d-md-flex justify-content-md-end">
							<button type="button" class="btn btn-outline-secondary me-md-2" onclick="clearForm()"> Clear Form
							</button>
							<button type="submit" class="btn btn-primary">
								<i class="bi bi-send"></i> Submit Post </button>
						</div>
						<!-- Security Information -->
						<div class="security-info mt-3">
							<small>
								<i class="bi bi-shield-check text-success"></i> This form is protected by CSRF tokens, honeypot fields,
								timing analysis, and content filtering. </small>
						</div>
					</form>
				</div>
			</div>
			<div class="col-lg-4">
				<!-- Security Status Card -->
				<div class="card mb-4">
					<div class="card-header">
						<h5 class="card-title mb-0">
							<i class="bi bi-shield-fill text-primary"></i> Security Status
						</h5>
					</div>
					<div class="card-body">
						<div class="row text-center">
							<div class="col-6">
								<div class="border-end">
									<h6 class="text-success mb-1">✓ CSRF</h6>
									<small class="text-muted">Protected</small>
								</div>
							</div>
							<div class="col-6">
								<h6 class="text-success mb-1">✓ Honeypot</h6>
								<small class="text-muted">Active</small>
							</div>
						</div>
						<hr>
						<div class="row text-center">
							<div class="col-6">
								<div class="border-end">
									<h6 class="text-success mb-1">✓ Rate Limit</h6>
									<small class="text-muted">Monitored</small>
								</div>
							</div>
							<div class="col-6">
								<h6 class="text-success mb-1">✓ Spam Filter</h6>
								<small class="text-muted">Enabled</small>
							</div>
						</div>
					</div>
				</div>
				<!-- Security Statistics -->
				<?php
				$stats = $security->getSecurityStats();
				?>
				<div class="card">
					<div class="card-header">
						<h5 class="card-title mb-0">
							<i class="bi bi-graph-up"></i> Security Statistics
						</h5>
					</div>
					<div class="card-body">
						<div class="security-stats">
							<h6>CSRF Tokens</h6>
							<ul class="list-unstyled small">
								<li>Active: <?= $stats['csrf']['active'] ?? 0 ?></li>
								<li>Total: <?= $stats['csrf']['total'] ?? 0 ?></li>
							</ul>
						</div>
						<div class="security-stats">
							<h6>Rate Limiting</h6>
							<ul class="list-unstyled small">
								<li>Blocked IPs: <?= $stats['rate_limiting']['currently_blocked'] ?? 0 ?></li>
								<li>Total Records: <?= $stats['rate_limiting']['total_records'] ?? 0 ?></li>
							</ul>
						</div>
						<div class="security-stats">
							<h6>Spam Detection</h6>
							<ul class="list-unstyled small">
								<li>Recent Attempts: <?= $stats['spam_detection']['recent_detections'] ?? 0 ?></li>
								<li>Keywords: <?= $stats['spam_detection']['spam_keywords_count'] ?? 0 ?></li>
							</ul>
						</div>
					</div>
				</div>
			</div>
		</div>
	</div>
	<!-- Bootstrap 5.3.7 JavaScript -->
	<script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.7/dist/js/bootstrap.bundle.min.js"></script>
	<!-- Security Validator JavaScript -->
	<script src="../public/assets/js/security-validator.js"></script>
	<script>
		// Initialize tooltips
		const tooltipTriggerList = document.querySelectorAll('[data-bs-toggle="tooltip"]');
		const tooltipList = [...tooltipTriggerList].map(tooltipTriggerEl => new bootstrap.Tooltip(tooltipTriggerEl));

		// Form validation
		(function () {
			'use strict';
			window.addEventListener('load', function () {
				const forms = document.getElementsByClassName('needs-validation');
				Array.prototype.filter.call(forms, function (form) {
					form.addEventListener('submit', function (event) {
						if (form.checkValidity() === false) {
							event.preventDefault();
							event.stopPropagation();
						}
						form.classList.add('was-validated');
					}, false);
				});
			}, false);
		})();

		// Clear form function
		function clearForm() {
			const form = document.getElementById('post_form');
			form.reset();
			form.classList.remove('was-validated');

			// Clear any security error messages
			const errors = form.querySelectorAll('.security-error');
			errors.forEach(error => error.remove());
		}

		// Character counter for content textarea
		const contentTextarea = document.getElementById('content');
		const maxLength = parseInt(contentTextarea.getAttribute('maxlength'));

		// Create character counter
		const charCounter = document.createElement('div');
		charCounter.className = 'form-text text-end';
		charCounter.innerHTML = `<span id="char-count">0</span>/${maxLength} characters`;
		contentTextarea.parentNode.appendChild(charCounter);

		// Update character count
		contentTextarea.addEventListener('input', function () {
			const currentLength = this.value.length;
			const charCountSpan = document.getElementById('char-count');
			charCountSpan.textContent = currentLength;

			if (currentLength > maxLength * 0.9) {
				charCountSpan.className = 'text-warning';
			} else {
				charCountSpan.className = '';
			}
		});

		// Initialize security validator with debug mode
		SecurityValidator.init({
			debugMode: true,
			enableBotDetection: true,
			enableTimingAnalysis: true,
			enableCSRFValidation: true
		});

		console.log('Security validator initialized');
	</script>
</body>
</html>