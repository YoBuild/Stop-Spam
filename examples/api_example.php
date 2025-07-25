<?php

require_once __DIR__ . '/../vendor/autoload.php';

use Yohns\Core\Config;
use Yohns\Security\SecurityManager;
use Yohns\Security\TokenManager;
use Yohns\Security\IPSecurity;

// Initialize configuration
$config = new Config(__DIR__ . '/../config');

// Start session
session_start();

// Initialize security components
$security = new SecurityManager($_SESSION['user_id'] ?? null);
$tokenManager = new TokenManager();
$ipSecurity = new IPSecurity();

// Apply security headers
$security->applySecurityHeaders();

// Handle different API endpoints
$endpoint = $_GET['endpoint'] ?? 'dashboard';
$method = $_SERVER['REQUEST_METHOD'];

/**
 * API Token Generation Example
 */
function handleTokenGeneration($tokenManager, $security): array {
	if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
		http_response_code(405);
		return ['error' => 'Method not allowed'];
	}

	// Validate request
	$securityCheck = $security->securityCheck('api_token_generation', $_POST, true, 0.8);

	if (!$securityCheck['passed']) {
		http_response_code(403);
		return [
			'error'   => 'Security check failed',
			'reason'  => $securityCheck['reason'],
			'details' => $securityCheck['details']
		];
	}

	$userId = $_POST['user_id'] ?? null;
	$permissions = $_POST['permissions'] ?? ['read'];
	$expiresIn = (int) ($_POST['expires_in'] ?? 86400); // 24 hours default

	if (!$userId) {
		http_response_code(400);
		return ['error' => 'User ID is required'];
	}

	// Generate API token
	$apiToken = $tokenManager->generateAPIToken($userId, $permissions, $expiresIn);

	return [
		'success'     => true,
		'token'       => $apiToken,
		'expires_in'  => $expiresIn,
		'permissions' => $permissions
	];
}

/**
 * API Token Validation Example
 */
function handleTokenValidation($tokenManager): array {
	$authHeader = $_SERVER['HTTP_AUTHORIZATION'] ?? '';
	$token = str_replace('Bearer ', '', $authHeader);

	if (empty($token)) {
		http_response_code(401);
		return ['error' => 'No token provided'];
	}

	$validation = $tokenManager->validateToken($token, 'api_access');

	if (!$validation['is_valid']) {
		http_response_code(401);
		return [
			'error'  => 'Invalid token',
			'reason' => $validation['error']
		];
	}

	return [
		'success'        => true,
		'valid'          => true,
		'token_data'     => $validation['token_data'],
		'remaining_uses' => $validation['remaining_uses']
	];
}

/**
 * IP Security Analysis Example
 */
function handleIPAnalysis($ipSecurity): array {
	$ip = $_GET['ip'] ?? null;
	$analysis = $ipSecurity->analyzeIP($ip);

	return [
		'success'     => true,
		'ip_analysis' => $analysis
	];
}

/**
 * Rate Limiting Status Example
 */
function handleRateLimitStatus($security): array {
	$rateLimiter = $security->getRateLimiter();
	$clientIP = $security->getClientIP();
	$action = $_GET['action'] ?? 'api_call';

	$isLimited = $rateLimiter->isLimited($clientIP, $action);
	$remaining = $rateLimiter->getRemainingRequests("ip_{$clientIP}", $action);
	$blockTime = $rateLimiter->getBlockTimeRemaining("ip_{$clientIP}", $action);

	return [
		'success'              => true,
		'is_limited'           => $isLimited,
		'remaining_requests'   => $remaining,
		'block_time_remaining' => $blockTime,
		'client_ip'            => $clientIP
	];
}

/**
 * Security Statistics Example
 */
function handleSecurityStats($security): array {
	$stats = $security->getSecurityStats();

	return [
		'success'    => true,
		'statistics' => $stats
	];
}

// Handle API requests
header('Content-Type: application/json');

try {
	switch ($endpoint) {
		case 'generate-token':
			$response = handleTokenGeneration($tokenManager, $security);
			break;

		case 'validate-token':
			$response = handleTokenValidation($tokenManager);
			break;

		case 'ip-analysis':
			$response = handleIPAnalysis($ipSecurity);
			break;

		case 'rate-limit-status':
			$response = handleRateLimitStatus($security);
			break;

		case 'security-stats':
			$response = handleSecurityStats($security);
			break;

		case 'dashboard':
		default:
			// Show API documentation dashboard
			$response = null;
			break;
	}

	if ($response) {
		echo json_encode($response, JSON_PRETTY_PRINT);
		exit;
	}

} catch (Exception $e) {
	http_response_code(500);
	echo json_encode([
		'error'   => 'Internal server error',
		'message' => $e->getMessage()
	], JSON_PRETTY_PRINT);
	exit;
}

// If we reach here, show the dashboard
?>
<!DOCTYPE html>
<html lang="en">
<head>
	<meta charset="UTF-8">
	<meta name="viewport" content="width=device-width, initial-scale=1.0">
	<title>API Security Examples - Yohns Stop Spam</title>
	<!-- Bootstrap 5.3.7 CSS -->
	<link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.7/dist/css/bootstrap.min.css" rel="stylesheet">
	<link href="https://cdn.jsdelivr.net/npm/bootstrap-icons@1.11.0/font/bootstrap-icons.css" rel="stylesheet">
	<style>
		.api-section {
			background: white;
			border-radius: 0.75rem;
			box-shadow: 0 0.125rem 0.25rem rgba(0, 0, 0, 0.075);
			margin-bottom: 2rem;
			overflow: hidden;
		}

		.api-header {
			background: linear-gradient(135deg, #6c757d, #495057);
			color: white;
			padding: 1.5rem;
		}

		.code-block {
			background: #f8f9fa;
			border: 1px solid #dee2e6;
			border-radius: 0.5rem;
			padding: 1rem;
			margin: 1rem 0;
			font-family: 'Courier New', monospace;
			font-size: 0.875rem;
			overflow-x: auto;
		}

		.endpoint-badge {
			display: inline-block;
			padding: 0.25rem 0.5rem;
			border-radius: 0.375rem;
			font-size: 0.75rem;
			font-weight: 600;
			margin-right: 0.5rem;
		}

		.method-get {
			background-color: #d4edda;
			color: #155724;
		}

		.method-post {
			background-color: #cce7ff;
			color: #004085;
		}

		.method-put {
			background-color: #fff3cd;
			color: #856404;
		}

		.method-delete {
			background-color: #f8d7da;
			color: #721c24;
		}

		.response-example {
			max-height: 300px;
			overflow-y: auto;
		}
	</style>
</head>
<body class="bg-light">
	<nav class="navbar navbar-expand-lg navbar-dark bg-dark">
		<div class="container">
			<a class="navbar-brand" href="#">
				<i class="bi bi-shield-check"></i> Yohns Stop Spam - API Examples </a>
			<div class="navbar-nav ms-auto">
				<a class="nav-link" href="bootstrap_form_example.php">Form Examples</a>
				<a class="nav-link" href="admin_dashboard.php">Dashboard</a>
			</div>
		</div>
	</nav>
	<div class="container mt-4">
		<div class="row">
			<div class="col-12">
				<h1 class="display-6 mb-4">API Security Examples</h1>
				<p class="lead text-muted mb-5"> Explore the security API endpoints and test various security features including
					token management, IP analysis, rate limiting, and more. </p>
			</div>
		</div>
		<!-- Token Generation -->
		<div class="api-section">
			<div class="api-header">
				<h3 class="mb-2">
					<i class="bi bi-key"></i> API Token Generation
				</h3>
				<p class="mb-0">Generate secure API tokens with custom permissions and expiration.</p>
			</div>
			<div class="p-4">
				<div class="mb-3">
					<span class="endpoint-badge method-post">POST</span>
					<code>/api_example.php?endpoint=generate-token</code>
				</div>
				<h6>Request Example:</h6>
				<div class="code-block"> curl -X POST
					"<?= $_SERVER['HTTP_HOST'] . $_SERVER['PHP_SELF'] ?>?endpoint=generate-token" \\ -H "Content-Type:
					application/x-www-form-urlencoded" \\ -d "user_id=123&permissions[]=read&permissions[]=write&expires_in=86400"
				</div>
				<h6>Try it out:</h6>
				<form id="tokenForm" class="row g-3">
					<div class="col-md-4">
						<label class="form-label">User ID</label>
						<input type="number" class="form-control" name="user_id" value="123" required>
					</div>
					<div class="col-md-4">
						<label class="form-label">Permissions</label>
						<select class="form-select" name="permissions[]" multiple>
							<option value="read" selected>Read</option>
							<option value="write">Write</option>
							<option value="delete">Delete</option>
							<option value="admin">Admin</option>
						</select>
					</div>
					<div class="col-md-4">
						<label class="form-label">Expires In (seconds)</label>
						<input type="number" class="form-control" name="expires_in" value="86400">
					</div>
					<div class="col-12">
						<button type="submit" class="btn btn-primary">Generate Token</button>
					</div>
				</form>
				<div id="tokenResponse" class="response-example mt-3" style="display: none;">
					<h6>Response:</h6>
					<div class="code-block">
						<pre id="tokenResponseContent"></pre>
					</div>
				</div>
			</div>
		</div>
		<!-- Token Validation -->
		<div class="api-section">
			<div class="api-header">
				<h3 class="mb-2">
					<i class="bi bi-check-circle"></i> Token Validation
				</h3>
				<p class="mb-0">Validate API tokens and check their permissions.</p>
			</div>
			<div class="p-4">
				<div class="mb-3">
					<span class="endpoint-badge method-get">GET</span>
					<code>/api_example.php?endpoint=validate-token</code>
				</div>
				<h6>Request Example:</h6>
				<div class="code-block"> curl -X GET
					"<?= $_SERVER['HTTP_HOST'] . $_SERVER['PHP_SELF'] ?>?endpoint=validate-token" \\ -H "Authorization: Bearer
					YOUR_TOKEN_HERE" </div>
				<h6>Try it out:</h6>
				<form id="validateForm" class="row g-3">
					<div class="col-12">
						<label class="form-label">API Token</label>
						<input type="text" class="form-control" name="token" placeholder="Enter token from generation above"
							required>
					</div>
					<div class="col-12">
						<button type="submit" class="btn btn-success">Validate Token</button>
					</div>
				</form>
				<div id="validateResponse" class="response-example mt-3" style="display: none;">
					<h6>Response:</h6>
					<div class="code-block">
						<pre id="validateResponseContent"></pre>
					</div>
				</div>
			</div>
		</div>
		<!-- IP Analysis -->
		<div class="api-section">
			<div class="api-header">
				<h3 class="mb-2">
					<i class="bi bi-globe"></i> IP Security Analysis
				</h3>
				<p class="mb-0">Analyze IP addresses for security threats and reputation.</p>
			</div>
			<div class="p-4">
				<div class="mb-3">
					<span class="endpoint-badge method-get">GET</span>
					<code>/api_example.php?endpoint=ip-analysis&ip={ip_address}</code>
				</div>
				<h6>Try it out:</h6>
				<form id="ipForm" class="row g-3">
					<div class="col-md-8">
						<label class="form-label">IP Address (leave empty for current IP)</label>
						<input type="text" class="form-control" name="ip" placeholder="e.g., 192.168.1.1">
					</div>
					<div class="col-md-4 d-flex align-items-end">
						<button type="submit" class="btn btn-info w-100">Analyze IP</button>
					</div>
				</form>
				<div id="ipResponse" class="response-example mt-3" style="display: none;">
					<h6>Response:</h6>
					<div class="code-block">
						<pre id="ipResponseContent"></pre>
					</div>
				</div>
			</div>
		</div>
		<!-- Rate Limiting Status -->
		<div class="api-section">
			<div class="api-header">
				<h3 class="mb-2">
					<i class="bi bi-speedometer2"></i> Rate Limiting Status
				</h3>
				<p class="mb-0">Check current rate limiting status and remaining requests.</p>
			</div>
			<div class="p-4">
				<div class="mb-3">
					<span class="endpoint-badge method-get">GET</span>
					<code>/api_example.php?endpoint=rate-limit-status&action={action_type}</code>
				</div>
				<h6>Try it out:</h6>
				<form id="rateLimitForm" class="row g-3">
					<div class="col-md-6">
						<label class="form-label">Action Type</label>
						<select class="form-select" name="action">
							<option value="api_call">API Call</option>
							<option value="login">Login</option>
							<option value="post">Post</option>
							<option value="message">Message</option>
						</select>
					</div>
					<div class="col-md-6 d-flex align-items-end">
						<button type="submit" class="btn btn-warning w-100">Check Status</button>
					</div>
				</form>
				<div id="rateLimitResponse" class="response-example mt-3" style="display: none;">
					<h6>Response:</h6>
					<div class="code-block">
						<pre id="rateLimitResponseContent"></pre>
					</div>
				</div>
			</div>
		</div>
		<!-- Security Statistics -->
		<div class="api-section">
			<div class="api-header">
				<h3 class="mb-2">
					<i class="bi bi-graph-up"></i> Security Statistics
				</h3>
				<p class="mb-0">Get comprehensive security statistics and metrics.</p>
			</div>
			<div class="p-4">
				<div class="mb-3">
					<span class="endpoint-badge method-get">GET</span>
					<code>/api_example.php?endpoint=security-stats</code>
				</div>
				<h6>Try it out:</h6>
				<button id="statsBtn" class="btn btn-secondary">Get Statistics</button>
				<div id="statsResponse" class="response-example mt-3" style="display: none;">
					<h6>Response:</h6>
					<div class="code-block">
						<pre id="statsResponseContent"></pre>
					</div>
				</div>
			</div>
		</div>
	</div>
	<!-- Bootstrap 5.3.7 JavaScript -->
	<script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.7/dist/js/bootstrap.bundle.min.js"></script>
	<script>
		// Helper function to make API calls
		async function makeAPICall(url, options = {}) {
			try {
				const response = await fetch(url, options);
				const data = await response.json();
				return { response, data };
			} catch (error) {
				return { error: error.message };
			}
		}

		// Token Generation
		document.getElementById('tokenForm').addEventListener('submit', async (e) => {
			e.preventDefault();
			const formData = new FormData(e.target);

			const { response, data, error } = await makeAPICall(
				'?endpoint=generate-token',
				{
					method: 'POST',
					body: formData
				}
			);

			const responseDiv = document.getElementById('tokenResponse');
			const responseContent = document.getElementById('tokenResponseContent');

			if (error) {
				responseContent.textContent = JSON.stringify({ error }, null, 2);
			} else {
				responseContent.textContent = JSON.stringify(data, null, 2);

				// Auto-fill the token in validation form
				if (data.success && data.token) {
					document.querySelector('input[name="token"]').value = data.token;
				}
			}

			responseDiv.style.display = 'block';
		});

		// Token Validation
		document.getElementById('validateForm').addEventListener('submit', async (e) => {
			e.preventDefault();
			const token = e.target.token.value;

			const { response, data, error } = await makeAPICall(
				'?endpoint=validate-token',
				{
					method: 'GET',
					headers: {
						'Authorization': `Bearer ${token}`
					}
				}
			);

			const responseDiv = document.getElementById('validateResponse');
			const responseContent = document.getElementById('validateResponseContent');

			if (error) {
				responseContent.textContent = JSON.stringify({ error }, null, 2);
			} else {
				responseContent.textContent = JSON.stringify(data, null, 2);
			}

			responseDiv.style.display = 'block';
		});

		// IP Analysis
		document.getElementById('ipForm').addEventListener('submit', async (e) => {
			e.preventDefault();
			const ip = e.target.ip.value;
			const url = ip ? `?endpoint=ip-analysis&ip=${encodeURIComponent(ip)}` : '?endpoint=ip-analysis';

			const { response, data, error } = await makeAPICall(url);

			const responseDiv = document.getElementById('ipResponse');
			const responseContent = document.getElementById('ipResponseContent');

			if (error) {
				responseContent.textContent = JSON.stringify({ error }, null, 2);
			} else {
				responseContent.textContent = JSON.stringify(data, null, 2);
			}

			responseDiv.style.display = 'block';
		});

		// Rate Limit Status
		document.getElementById('rateLimitForm').addEventListener('submit', async (e) => {
			e.preventDefault();
			const action = e.target.action.value;

			const { response, data, error } = await makeAPICall(`?endpoint=rate-limit-status&action=${action}`);

			const responseDiv = document.getElementById('rateLimitResponse');
			const responseContent = document.getElementById('rateLimitResponseContent');

			if (error) {
				responseContent.textContent = JSON.stringify({ error }, null, 2);
			} else {
				responseContent.textContent = JSON.stringify(data, null, 2);
			}

			responseDiv.style.display = 'block';
		});

		// Security Statistics
		document.getElementById('statsBtn').addEventListener('click', async () => {
			const { response, data, error } = await makeAPICall('?endpoint=security-stats');

			const responseDiv = document.getElementById('statsResponse');
			const responseContent = document.getElementById('statsResponseContent');

			if (error) {
				responseContent.textContent = JSON.stringify({ error }, null, 2);
			} else {
				responseContent.textContent = JSON.stringify(data, null, 2);
			}

			responseDiv.style.display = 'block';
		});
	</script>
</body>
</html>