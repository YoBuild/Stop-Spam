<?php

require_once __DIR__ . '/../vendor/autoload.php';

use Yohns\Core\Config;
use Yohns\Security\SecurityManager;
use Yohns\Security\ContentValidator;
use Yohns\AntiSpam\SpamDetector;
use Yohns\AntiSpam\ContentAnalyzer;

// Initialize configuration
$config = new Config(__DIR__ . '/../config');

// Start session
session_start();

// Initialize security components
$security = new SecurityManager($_SESSION['user_id'] ?? null);
$contentValidator = new ContentValidator();
$spamDetector = new SpamDetector();
$contentAnalyzer = new ContentAnalyzer();

// Sample content for analysis
$sampleTexts = [
	'good'       => "This is a well-written, professional message about our new product launch. We're excited to share this innovation with our customers and believe it will provide significant value. The development team has worked hard to ensure quality and user satisfaction.",
	'suspicious' => "BUY NOW!!! AMAZING DEAL!!! Limited time offer expires soon! Click here immediately to get FREE money and prizes! Don't miss out on this incredible opportunity to make money fast!",
	'malicious'  => "<script>alert('xss')</script>Buy cheap products at http://suspicious-site.tk/offers?ref=spam123 and get instant access to exclusive deals!",
	'multilang'  => "Hello world! Bonjour le monde! Hola mundo! This text contains multiple languages mixed together für eine bessere Analyse.",
];

$analysisResults = [];
$message = '';
$alertClass = 'alert-info';

// Handle form submission
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
	// Debug CSRF token validation
	$csrfValid = $security->getCSRFToken()->validateRequest('content_analysis');

	if (!$csrfValid) {
		// Try to get more specific error information
		$submittedToken = $_POST['csrf_token'] ?? '';
		$sessionToken = $_SESSION['csrf_token_content_analysis']['token'] ?? 'none';

		$message = 'CSRF token validation failed. Please refresh the page and try again.';
		$alertClass = 'alert-danger';

		// Add debug info in development
		if (Config::get('app.debug', 'security') === true) {
			$message .= " (Debug: Submitted: " . substr($submittedToken, 0, 8) . "..., Session: " . substr($sessionToken, 0, 8) . "...)";
		}
	} else {
		$content = $_POST['content'] ?? '';
		$analysisType = $_POST['analysis_type'] ?? 'comprehensive';

		if (!empty($content)) {
			// Perform different types of analysis
			switch ($analysisType) {
				case 'spam':
					$analysisResults['spam'] = $spamDetector->analyzeContent($content);
					break;

				case 'validation':
					$analysisResults['validation'] = $contentValidator->validate($content, [
						'allow_html'           => isset($_POST['allow_html']),
						'check_xss'            => true,
						'normalize_whitespace' => true,
					]);
					break;

				case 'language':
					$analysisResults['language'] = $contentAnalyzer->analyzeContent($content);
					break;

				case 'comprehensive':
				default:
					$analysisResults['spam'] = $spamDetector->analyzeContent($content);
					$analysisResults['validation'] = $contentValidator->validate($content);
					$analysisResults['analysis'] = $contentAnalyzer->analyzeContent($content);
					break;
			}

			$message = 'Content analysis completed successfully!';
			$alertClass = 'alert-success';
		} else {
			$message = 'Please provide content to analyze.';
			$alertClass = 'alert-warning';
		}
	}
}

// Initialize form security
$formSecurity = $security->initializeForm('content_analysis');

// Apply security headers
$security->applySecurityHeaders();

?>
<!DOCTYPE html>
<html lang="en">
<head>
	<meta charset="UTF-8">
	<meta name="viewport" content="width=device-width, initial-scale=1.0">
	<title>Content Analysis Examples - Yohns Stop Spam</title>
	<!-- Bootstrap 5.3.7 CSS -->
	<link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.7/dist/css/bootstrap.min.css" rel="stylesheet">
	<link href="https://cdn.jsdelivr.net/npm/bootstrap-icons@1.11.0/font/bootstrap-icons.css" rel="stylesheet">
	<style>
		.analysis-card {
			background: white;
			border-radius: 0.75rem;
			box-shadow: 0 0.125rem 0.25rem rgba(0, 0, 0, 0.075);
			margin-bottom: 2rem;
			overflow: hidden;
		}

		.analysis-header {
			background: linear-gradient(135deg, #6f42c1, #5a32a3);
			color: white;
			padding: 1.5rem;
		}

		.sample-card {
			border: 2px solid #e9ecef;
			border-radius: 0.5rem;
			padding: 1rem;
			margin-bottom: 1rem;
			cursor: pointer;
			transition: all 0.15s ease-in-out;
		}

		.sample-card:hover {
			border-color: var(--bs-primary);
			background-color: rgba(var(--bs-primary-rgb), 0.05);
		}

		.sample-card.active {
			border-color: var(--bs-primary);
			background-color: rgba(var(--bs-primary-rgb), 0.1);
		}

		.result-section {
			border: 1px solid #dee2e6;
			border-radius: 0.5rem;
			margin-bottom: 1.5rem;
		}

		.result-header {
			background-color: #f8f9fa;
			padding: 1rem;
			border-bottom: 1px solid #dee2e6;
			font-weight: 600;
		}

		.result-body {
			padding: 1.5rem;
		}

		.score-badge {
			padding: 0.5rem 1rem;
			border-radius: 0.5rem;
			font-weight: 600;
			font-size: 1.1rem;
		}

		.score-low {
			background-color: #d4edda;
			color: #155724;
		}

		.score-medium {
			background-color: #fff3cd;
			color: #856404;
		}

		.score-high {
			background-color: #f8d7da;
			color: #721c24;
		}

		.metrics-grid {
			display: grid;
			grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
			gap: 1rem;
			margin-top: 1rem;
		}

		.metric-item {
			background-color: #f8f9fa;
			padding: 1rem;
			border-radius: 0.5rem;
			text-align: center;
		}

		.metric-value {
			font-size: 1.5rem;
			font-weight: 700;
			color: var(--bs-primary);
		}

		.metric-label {
			font-size: 0.875rem;
			color: var(--bs-secondary);
			margin-top: 0.25rem;
		}

		.recommendation-list {
			background-color: #e7f3ff;
			border: 1px solid #b8daff;
			border-radius: 0.5rem;
			padding: 1rem;
			margin-top: 1rem;
		}

		.pattern-item {
			background-color: #fff;
			border: 1px solid #dee2e6;
			border-radius: 0.375rem;
			padding: 0.75rem;
			margin-bottom: 0.5rem;
		}

		.pattern-severity {
			padding: 0.25rem 0.5rem;
			border-radius: 0.25rem;
			font-size: 0.75rem;
			font-weight: 600;
		}

		.severity-high {
			background-color: #f8d7da;
			color: #721c24;
		}

		.severity-medium {
			background-color: #fff3cd;
			color: #856404;
		}

		.severity-low {
			background-color: #d1ecf1;
			color: #0c5460;
		}
	</style>
</head>
<body class="bg-light">
	<nav class="navbar navbar-expand-lg navbar-dark bg-dark">
		<div class="container">
			<a class="navbar-brand" href="#">
				<i class="bi bi-search"></i> Content Analysis Examples </a>
			<div class="navbar-nav ms-auto">
				<a class="nav-link" href="bootstrap_form_example.php">Form Examples</a>
				<a class="nav-link" href="api_example.php">API Examples</a>
				<a class="nav-link" href="admin_dashboard.php">Dashboard</a>
			</div>
		</div>
	</nav>
	<div class="container mt-4">
		<!-- Page Header -->
		<div class="row mb-5">
			<div class="col-12">
				<h1 class="display-6">Content Analysis & Validation</h1>
				<p class="lead text-muted"> Analyze content for spam, validate input for security threats, and perform
					comprehensive content analysis including language detection and sentiment analysis. </p>
			</div>
		</div>
		<!-- Alert Messages -->
		<?php if ($message): ?>
			<div class="alert <?= $alertClass ?> alert-dismissible fade show" role="alert">
				<?= htmlspecialchars($message) ?>
				<button type="button" class="btn-close" data-bs-dismiss="alert"></button>
			</div>
		<?php endif; ?>
		<div class="row">
			<!-- Input Section -->
			<div class="col-lg-6">
				<div class="analysis-card">
					<div class="analysis-header">
						<h3 class="mb-2">
							<i class="bi bi-pencil-square"></i> Content Input
						</h3>
						<p class="mb-0">Enter or select content to analyze</p>
					</div>
					<div class="p-4">
						<!-- Sample Content Selection -->
						<h6 class="mb-3">Quick Samples:</h6>
						<?php foreach ($sampleTexts as $type => $text): ?>
							<div class="sample-card" data-content="<?= htmlspecialchars($text) ?>" data-type="<?= $type ?>">
								<strong><?= ucfirst($type) ?> Content</strong>
								<p class="text-muted small mb-0 mt-1">
									<?= substr(htmlspecialchars($text), 0, 100) ?>...
								</p>
							</div>
						<?php endforeach; ?>
						<!-- Analysis Form -->
						<form method="post" id="analysisForm" class="mt-4">
							<?= $formSecurity['csrf_field'] ?>
							<?= $formSecurity['honeypot_field'] ?>
							<div class="mb-3">
								<label for="content" class="form-label">Content to Analyze</label>
								<textarea class="form-control" id="content" name="content" rows="8"
									placeholder="Enter the content you want to analyze..." required></textarea>
								<div class="form-text"> Enter any text content for analysis - posts, comments, messages, etc. </div>
							</div>
							<div class="mb-3">
								<label for="analysis_type" class="form-label">Analysis Type</label>
								<select class="form-select" id="analysis_type" name="analysis_type">
									<option value="comprehensive">Comprehensive Analysis</option>
									<option value="spam">Spam Detection Only</option>
									<option value="validation">Security Validation Only</option>
									<option value="language">Language Analysis Only</option>
								</select>
							</div>
							<div class="mb-3">
								<div class="form-check">
									<input class="form-check-input" type="checkbox" id="allow_html" name="allow_html">
									<label class="form-check-label" for="allow_html"> Allow HTML content (for validation testing) </label>
								</div>
							</div>
							<div class="d-grid">
								<button type="submit" class="btn btn-primary btn-lg">
									<i class="bi bi-search"></i> Analyze Content </button>
							</div>
						</form>
					</div>
				</div>
			</div>
			<!-- Results Section -->
			<div class="col-lg-6">
				<?php if (!empty($analysisResults)): ?>
					<!-- Spam Analysis Results -->
					<?php if (isset($analysisResults['spam'])): ?>
						<div class="result-section">
							<div class="result-header">
								<i class="bi bi-funnel"></i> Spam Detection Results
							</div>
							<div class="result-body">
								<?php $spam = $analysisResults['spam']; ?>
								<div class="d-flex align-items-center mb-3">
									<span class="me-3">Spam Score:</span>
									<span
										class="score-badge <?= $spam['spam_score'] >= 0.7 ? 'score-high' : ($spam['spam_score'] >= 0.4 ? 'score-medium' : 'score-low') ?>">
										<?= number_format($spam['spam_score'] * 100, 1) ?>% </span>
								</div>
								<div class="mb-3">
									<strong>Status:</strong>
									<span class="badge <?= $spam['is_spam'] ? 'bg-danger' : 'bg-success' ?> ms-2">
										<?= $spam['is_spam'] ? 'SPAM DETECTED' : 'CLEAN' ?>
									</span>
								</div>
								<?php if (!empty($spam['reasons'])): ?>
									<div class="mb-3">
										<strong>Issues Found:</strong>
										<ul class="mt-2">
											<?php foreach ($spam['reasons'] as $reason): ?>
												<li><?= htmlspecialchars($reason) ?></li>
											<?php endforeach; ?>
										</ul>
									</div>
								<?php endif; ?>
								<div class="severity-indicator">
									<strong>Severity:</strong>
									<span
										class="badge bg-<?= $spam['severity'] === 'high' ? 'danger' : ($spam['severity'] === 'medium' ? 'warning' : 'info') ?> ms-2">
										<?= strtoupper($spam['severity']) ?>
									</span>
								</div>
							</div>
						</div>
					<?php endif; ?>
					<!-- Validation Results -->
					<?php if (isset($analysisResults['validation'])): ?>
						<div class="result-section">
							<div class="result-header">
								<i class="bi bi-shield-check"></i> Security Validation Results
							</div>
							<div class="result-body">
								<?php $validation = $analysisResults['validation']; ?>
								<div class="mb-3">
									<strong>Validation Status:</strong>
									<span class="badge <?= $validation['is_valid'] ? 'bg-success' : 'bg-danger' ?> ms-2">
										<?= $validation['is_valid'] ? 'VALID' : 'INVALID' ?>
									</span>
								</div>
								<?php if (!empty($validation['errors'])): ?>
									<div class="mb-3">
										<strong>Errors:</strong>
										<ul class="text-danger mt-2">
											<?php foreach ($validation['errors'] as $error): ?>
												<li><?= htmlspecialchars($error) ?></li>
											<?php endforeach; ?>
										</ul>
									</div>
								<?php endif; ?>
								<?php if (!empty($validation['warnings'])): ?>
									<div class="mb-3">
										<strong>Warnings:</strong>
										<ul class="text-warning mt-2">
											<?php foreach ($validation['warnings'] as $warning): ?>
												<li><?= htmlspecialchars($warning) ?></li>
											<?php endforeach; ?>
										</ul>
									</div>
								<?php endif; ?>
								<?php if (!empty($validation['changes_made'])): ?>
									<div class="mb-3">
										<strong>Changes Made:</strong>
										<ul class="text-info mt-2">
											<?php foreach ($validation['changes_made'] as $change): ?>
												<li><?= htmlspecialchars($change) ?></li>
											<?php endforeach; ?>
										</ul>
									</div>
								<?php endif; ?>
								<?php if (!empty($validation['security_issues'])): ?>
									<div class="mb-3">
										<strong>Security Issues:</strong>
										<div class="mt-2">
											<?php foreach ($validation['security_issues'] as $issue): ?>
												<div class="pattern-item">
													<span class="pattern-severity severity-<?= $issue['severity'] ?? 'medium' ?>">
														<?= strtoupper($issue['severity'] ?? 'MEDIUM') ?>
													</span>
													<strong class="ms-2"><?= htmlspecialchars($issue['type'] ?? 'Unknown') ?></strong>
													<p class="mb-0 mt-1 text-muted small">
														<?= htmlspecialchars($issue['description'] ?? '') ?>
													</p>
												</div>
											<?php endforeach; ?>
										</div>
									</div>
								<?php endif; ?>
								<div class="mt-3">
									<strong>Sanitized Content:</strong>
									<div class="bg-light p-2 rounded mt-1" style="max-height: 150px; overflow-y: auto;">
										<code><?= htmlspecialchars($validation['sanitized_content']) ?></code>
									</div>
								</div>
							</div>
						</div>
					<?php endif; ?>
					<!-- Content Analysis Results -->
					<?php if (isset($analysisResults['analysis'])): ?>
						<div class="result-section">
							<div class="result-header">
								<i class="bi bi-graph-up"></i> Comprehensive Content Analysis
							</div>
							<div class="result-body">
								<?php $analysis = $analysisResults['analysis']; ?>
								<!-- Basic Metrics -->
								<div class="metrics-grid">
									<div class="metric-item">
										<div class="metric-value"><?= $analysis['word_count'] ?></div>
										<div class="metric-label">Words</div>
									</div>
									<div class="metric-item">
										<div class="metric-value"><?= $analysis['content_length'] ?></div>
										<div class="metric-label">Characters</div>
									</div>
									<div class="metric-item">
										<div class="metric-value"><?= number_format($analysis['suspicious_score'] * 100, 1) ?>%</div>
										<div class="metric-label">Suspicion Score</div>
									</div>
									<div class="metric-item">
										<div class="metric-value"><?= $analysis['links']['count'] ?></div>
										<div class="metric-label">Links Found</div>
									</div>
								</div>
								<!-- Language Detection -->
								<?php if (isset($analysis['language'])): ?>
									<div class="mt-4">
										<strong>Language Detection:</strong>
										<div class="mt-2">
											<span class="badge bg-primary me-2">
												<?= strtoupper($analysis['language']['primary']) ?>
											</span>
											<small class="text-muted"> Confidence:
												<?= number_format($analysis['language']['confidence'] * 100, 1) ?>% </small>
										</div>
									</div>
								<?php endif; ?>
								<!-- Sentiment Analysis -->
								<?php if (isset($analysis['sentiment'])): ?>
									<div class="mt-3">
										<strong>Sentiment Analysis:</strong>
										<div class="mt-2">
											<?php
											$sentiment = $analysis['sentiment']['sentiment'];
											$badgeClass = $sentiment === 'positive' ? 'bg-success' : ($sentiment === 'negative' ? 'bg-danger' : 'bg-secondary');
											?>
											<span class="badge <?= $badgeClass ?> me-2">
												<?= strtoupper($sentiment) ?>
											</span>
											<small class="text-muted"> Confidence:
												<?= number_format($analysis['sentiment']['confidence'] * 100, 1) ?>% </small>
										</div>
									</div>
								<?php endif; ?>
								<!-- Readability -->
								<?php if (isset($analysis['readability'])): ?>
									<div class="mt-3">
										<strong>Readability:</strong>
										<div class="mt-2">
											<span class="badge bg-info me-2"> Score: <?= $analysis['readability']['score'] ?>
											</span>
											<span class="badge bg-secondary"> Level:
												<?= str_replace('_', ' ', ucwords($analysis['readability']['level'])) ?>
											</span>
										</div>
									</div>
								<?php endif; ?>
								<!-- Detected Patterns -->
								<?php if (!empty($analysis['patterns'])): ?>
									<div class="mt-4">
										<strong>Suspicious Patterns:</strong>
										<div class="mt-2">
											<?php foreach ($analysis['patterns'] as $patternName => $pattern): ?>
												<div class="pattern-item">
													<span class="pattern-severity severity-<?= $pattern['severity'] ?>">
														<?= strtoupper($pattern['severity']) ?>
													</span>
													<strong class="ms-2"><?= htmlspecialchars($patternName) ?></strong>
													<p class="mb-1 mt-1"><?= htmlspecialchars($pattern['description']) ?></p>
													<small class="text-muted">Found <?= $pattern['count'] ?> occurrence(s)</small>
												</div>
											<?php endforeach; ?>
										</div>
									</div>
								<?php endif; ?>
								<!-- Link Analysis -->
								<?php if (!empty($analysis['links']['domains'])): ?>
									<div class="mt-4">
										<strong>Link Analysis:</strong>
										<div class="mt-2">
											<div class="row">
												<div class="col-6">
													<small class="text-muted">Total Links:</small> <?= $analysis['links']['count'] ?>
												</div>
												<div class="col-6">
													<small class="text-muted">Unique Domains:</small> <?= $analysis['links']['unique_domains'] ?>
												</div>
											</div>
											<?php if (!empty($analysis['links']['suspicious_domains'])): ?>
												<div class="mt-2">
													<small class="text-danger">Suspicious Domains:</small>
													<ul class="small">
														<?php foreach ($analysis['links']['suspicious_domains'] as $domain): ?>
															<li><?= htmlspecialchars($domain) ?></li>
														<?php endforeach; ?>
													</ul>
												</div>
											<?php endif; ?>
											<?php if (!empty($analysis['links']['shortened_urls'])): ?>
												<div class="mt-2">
													<small class="text-warning">Shortened URLs:</small>
													<ul class="small">
														<?php foreach ($analysis['links']['shortened_urls'] as $url): ?>
															<li><?= htmlspecialchars($url) ?></li>
														<?php endforeach; ?>
													</ul>
												</div>
											<?php endif; ?>
										</div>
									</div>
								<?php endif; ?>
								<!-- Recommendations -->
								<?php if (!empty($analysis['recommendations'])): ?>
									<div class="recommendation-list">
										<strong><i class="bi bi-lightbulb"></i> Recommendations:</strong>
										<ul class="mt-2 mb-0">
											<?php foreach ($analysis['recommendations'] as $recommendation): ?>
												<li><?= htmlspecialchars($recommendation) ?></li>
											<?php endforeach; ?>
										</ul>
									</div>
								<?php endif; ?>
							</div>
						</div>
					<?php endif; ?>
				<?php else: ?>
					<div class="analysis-card">
						<div class="analysis-header">
							<h3 class="mb-2">
								<i class="bi bi-info-circle"></i> Analysis Results
							</h3>
							<p class="mb-0">Results will appear here after analysis</p>
						</div>
						<div class="p-4 text-center text-muted">
							<i class="bi bi-arrow-left" style="font-size: 2rem;"></i>
							<p class="mt-3">Submit content for analysis to see detailed results including spam detection, security
								validation, and content insights.</p>
						</div>
					</div>
				<?php endif; ?>
			</div>
		</div>
		<!-- Information Section -->
		<div class="row mt-5">
			<div class="col-12">
				<div class="analysis-card">
					<div class="analysis-header">
						<h3 class="mb-2">
							<i class="bi bi-info-square"></i> About Content Analysis
						</h3>
						<p class="mb-0">Understanding the analysis features</p>
					</div>
					<div class="p-4">
						<div class="row">
							<div class="col-md-4">
								<h5><i class="bi bi-funnel text-danger"></i> Spam Detection</h5>
								<p>Analyzes content for spam patterns, suspicious keywords, excessive links, and other spam indicators.
									Provides a spam score and detailed reasoning.</p>
							</div>
							<div class="col-md-4">
								<h5><i class="bi bi-shield text-success"></i> Security Validation</h5>
								<p>Validates content for XSS attacks, malicious scripts, and other security threats. Sanitizes content
									and removes dangerous elements.</p>
							</div>
							<div class="col-md-4">
								<h5><i class="bi bi-graph-up text-primary"></i> Content Analysis</h5>
								<p>Comprehensive analysis including language detection, sentiment analysis, readability scoring, and
									pattern recognition.</p>
							</div>
						</div>
					</div>
				</div>
			</div>
		</div>
	</div>
	<?= $formSecurity['honeypot_css'] ?>
	<!-- Bootstrap 5.3.7 JavaScript -->
	<script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.7/dist/js/bootstrap.bundle.min.js"></script>
	<script>
		// Sample content selection
		document.querySelectorAll('.sample-card').forEach(card => {
			card.addEventListener('click', function () {
				// Remove active class from all cards
				document.querySelectorAll('.sample-card').forEach(c => c.classList.remove('active'));

				// Add active class to clicked card
				this.classList.add('active');

				// Set content in textarea
				const content = this.dataset.content;
				document.getElementById('content').value = content;

				// Auto-select appropriate analysis type
				const type = this.dataset.type;
				const analysisSelect = document.getElementById('analysis_type');

				switch (type) {
					case 'malicious':
						analysisSelect.value = 'validation';
						document.getElementById('allow_html').checked = true;
						break;
					case 'suspicious':
						analysisSelect.value = 'spam';
						break;
					case 'multilang':
						analysisSelect.value = 'language';
						break;
					default:
						analysisSelect.value = 'comprehensive';
				}
			});
		});

		// Character counter
		const contentTextarea = document.getElementById('content');
		const maxLength = 10000;

		function updateCharCount() {
			const current = contentTextarea.value.length;
			const remaining = maxLength - current;

			let countText = `${current}/${maxLength} characters`;
			if (remaining < 500) {
				countText += ` (${remaining} remaining)`;
			}

			// Create or update character counter
			let counter = document.getElementById('char-counter');
			if (!counter) {
				counter = document.createElement('div');
				counter.id = 'char-counter';
				counter.className = 'form-text text-end mt-1';
				contentTextarea.parentNode.appendChild(counter);
			}

			counter.textContent = countText;
			counter.className = remaining < 100 ? 'form-text text-end mt-1 text-warning' : 'form-text text-end mt-1';
		}

		contentTextarea.addEventListener('input', updateCharCount);
		updateCharCount();

		// Form submission with loading state
		document.getElementById('analysisForm').addEventListener('submit', function () {
			const submitBtn = this.querySelector('button[type="submit"]');
			submitBtn.innerHTML = '<span class="spinner-border spinner-border-sm me-2"></span>Analyzing...';
			submitBtn.disabled = true;
		});

		// Auto-scroll to results when they exist
		<?php if (!empty($analysisResults)): ?>
			setTimeout(function () {
				const resultSection = document.querySelector('.result-section');
				if (resultSection) {
					resultSection.scrollIntoView({
						behavior: 'smooth',
						block: 'start'
					});
				}
			}, 500);
		<?php endif; ?>
	</script>
</body>
</html>