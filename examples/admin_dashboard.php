<?php

require_once __DIR__ . '/../vendor/autoload.php';

use Yohns\Core\Config;
use Yohns\Security\SecurityManager;
use Yohns\Security\IPSecurity;
use Yohns\Security\TokenManager;
use Yohns\AntiSpam\SpamDetector;
use Yohns\AntiSpam\ContentAnalyzer;

// Start output buffering to prevent header issues
ob_start();

// Initialize configuration
$config = new Config(__DIR__ . '/../config');

// Start session
session_start();

// Initialize security components
$security = new SecurityManager($_SESSION['user_id'] ?? 1);
$ipSecurity = new IPSecurity();
$tokenManager = new TokenManager();
$spamDetector = new SpamDetector();
$contentAnalyzer = new ContentAnalyzer();

// Handle admin actions first, before any output
$action = $_POST['action'] ?? $_GET['action'] ?? '';
$message = '';
$alertClass = 'alert-info';

if ($_SERVER['REQUEST_METHOD'] === 'POST' && $action) {
	// Verify CSRF token for admin actions
	if (!$security->getCSRFToken()->validateRequest('admin_actions')) {
		$message = 'Invalid security token';
		$alertClass = 'alert-danger';
	} else {
		switch ($action) {
			case 'add_to_blacklist':
				$ip = $_POST['ip'] ?? '';
				$reason = $_POST['reason'] ?? 'Admin added';
				if (filter_var($ip, FILTER_VALIDATE_IP)) {
					$ipSecurity->addToBlacklist($ip, $reason);
					$message = "IP {$ip} added to blacklist";
					$alertClass = 'alert-success';
				} else {
					$message = 'Invalid IP address';
					$alertClass = 'alert-danger';
				}
				break;

			case 'remove_from_blacklist':
				$ip = $_POST['ip'] ?? '';
				if ($ipSecurity->removeFromBlacklist($ip)) {
					$message = "IP {$ip} removed from blacklist";
					$alertClass = 'alert-success';
				} else {
					$message = 'IP not found in blacklist';
					$alertClass = 'alert-warning';
				}
				break;

			case 'add_spam_keyword':
				$keyword = $_POST['keyword'] ?? '';
				if ($spamDetector->addSpamKeyword($keyword)) {
					$message = "Keyword '{$keyword}' added to spam list";
					$alertClass = 'alert-success';
				} else {
					$message = 'Keyword already exists or invalid';
					$alertClass = 'alert-warning';
				}
				break;

			case 'cleanup_expired':
				$results = $security->performMaintenance();
				$message = "Cleanup completed: " . json_encode($results);
				$alertClass = 'alert-success';
				break;
		}
	}
}

// Apply security headers after processing
$security->applySecurityHeaders();

// Generate CSRF token for JavaScript (after headers are set)
$adminCsrfToken = $security->getCSRFToken()->generateToken('admin_actions');

// Get statistics and data
$securityStats = $security->getSecurityStats();
$ipStats = $ipSecurity->getSecurityStats();
$tokenStats = $tokenManager->getTokenStats();
$spamStats = $spamDetector->getStats();

// Get recent activity (mock data for demo)
$recentActivity = [
	[
		'type'     => 'spam_detected',
		'message'  => 'Spam content blocked from IP 192.168.1.100',
		'time'     => time() - 300,
		'severity' => 'warning'
	],
	[
		'type'     => 'rate_limit',
		'message'  => 'Rate limit triggered for user login attempts',
		'time'     => time() - 600,
		'severity' => 'info'
	],
	[
		'type'     => 'ip_blocked',
		'message'  => 'IP 10.0.0.50 automatically blocked due to low trust score',
		'time'     => time() - 900,
		'severity' => 'danger'
	],
	[
		'type'     => 'token_generated',
		'message'  => 'New API token generated for user #123',
		'time'     => time() - 1200,
		'severity' => 'success'
	],
];

?>
<!DOCTYPE html>
<html lang="en">
<head>
	<meta charset="UTF-8">
	<meta name="viewport" content="width=device-width, initial-scale=1.0">
	<title>Security Admin Dashboard - Yohns Stop Spam</title>
	<!-- Bootstrap 5.3.7 CSS -->
	<link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.7/dist/css/bootstrap.min.css" rel="stylesheet">
	<link href="https://cdn.jsdelivr.net/npm/bootstrap-icons@1.11.0/font/bootstrap-icons.css" rel="stylesheet">
	<!-- Chart.js -->
	<script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
	<style>
		.dashboard-card {
			border: none;
			border-radius: 0.75rem;
			box-shadow: 0 0.125rem 0.25rem rgba(0, 0, 0, 0.075);
			margin-bottom: 1.5rem;
		}

		.stat-card {
			background: linear-gradient(135deg, var(--bs-primary), #4c63d2);
			color: white;
			border-radius: 0.75rem;
			padding: 1.5rem;
			margin-bottom: 1.5rem;
		}

		.stat-card.success {
			background: linear-gradient(135deg, var(--bs-success), #157347);
		}

		.stat-card.warning {
			background: linear-gradient(135deg, var(--bs-warning), #f59e0b);
		}

		.stat-card.danger {
			background: linear-gradient(135deg, var(--bs-danger), #dc2626);
		}

		.stat-number {
			font-size: 2.5rem;
			font-weight: 700;
			margin-bottom: 0.5rem;
		}

		.stat-label {
			font-size: 0.9rem;
			opacity: 0.9;
		}

		.activity-item {
			padding: 1rem;
			border-bottom: 1px solid #e9ecef;
			display: flex;
			align-items: center;
		}

		.activity-item:last-child {
			border-bottom: none;
		}

		.activity-icon {
			width: 40px;
			height: 40px;
			border-radius: 50%;
			display: flex;
			align-items: center;
			justify-content: center;
			margin-right: 1rem;
		}

		.activity-icon.success {
			background-color: rgba(var(--bs-success-rgb), 0.1);
			color: var(--bs-success);
		}

		.activity-icon.warning {
			background-color: rgba(var(--bs-warning-rgb), 0.1);
			color: var(--bs-warning);
		}

		.activity-icon.danger {
			background-color: rgba(var(--bs-danger-rgb), 0.1);
			color: var(--bs-danger);
		}

		.activity-icon.info {
			background-color: rgba(var(--bs-info-rgb), 0.1);
			color: var(--bs-info);
		}

		.quick-action-card {
			border: 2px dashed #dee2e6;
			border-radius: 0.75rem;
			padding: 1.5rem;
			text-align: center;
			transition: all 0.15s ease-in-out;
			cursor: pointer;
			margin-bottom: 1rem;
		}

		.quick-action-card:hover {
			border-color: var(--bs-primary);
			background-color: rgba(var(--bs-primary-rgb), 0.05);
		}

		.table-responsive {
			border-radius: 0.5rem;
		}

		.navbar-brand {
			font-weight: 700;
		}

		.sidebar {
			min-height: calc(100vh - 56px);
			background-color: #f8f9fa;
			border-right: 1px solid #dee2e6;
		}

		.sidebar .nav-link {
			color: #495057;
			padding: 0.75rem 1rem;
			border-radius: 0.5rem;
			margin-bottom: 0.25rem;
		}

		.sidebar .nav-link:hover,
		.sidebar .nav-link.active {
			color: var(--bs-primary);
			background-color: rgba(var(--bs-primary-rgb), 0.1);
		}

		.chart-container {
			position: relative;
			height: 300px;
		}
	</style>
</head>
<body>
	<!-- Navigation -->
	<nav class="navbar navbar-expand-lg navbar-dark bg-dark">
		<div class="container-fluid">
			<a class="navbar-brand" href="#">
				<i class="bi bi-shield-check"></i> Security Admin Dashboard </a>
			<div class="navbar-nav ms-auto">
				<a class="nav-link" href="bootstrap_form_example.php">
					<i class="bi bi-form"></i> Form Examples </a>
				<a class="nav-link" href="api_example.php">
					<i class="bi bi-code"></i> API Examples </a>
			</div>
		</div>
	</nav>
	<div class="container-fluid">
		<div class="row">
			<!-- Sidebar -->
			<div class="col-lg-2 sidebar p-3">
				<nav class="nav flex-column">
					<a class="nav-link active" href="#overview">
						<i class="bi bi-speedometer2"></i> Overview </a>
					<a class="nav-link" href="#security">
						<i class="bi bi-shield"></i> Security </a>
					<a class="nav-link" href="#rate-limits">
						<i class="bi bi-clock"></i> Rate Limits </a>
					<a class="nav-link" href="#spam">
						<i class="bi bi-funnel"></i> Spam Filter </a>
					<a class="nav-link" href="#tokens">
						<i class="bi bi-key"></i> Tokens </a>
					<a class="nav-link" href="#logs">
						<i class="bi bi-journal-text"></i> Activity </a>
				</nav>
			</div>
			<!-- Main Content -->
			<div class="col-lg-10 p-4">
				<!-- Alert Messages -->
				<?php if ($message): ?>
					<div class="alert <?= $alertClass ?> alert-dismissible fade show" role="alert">
						<?= htmlspecialchars($message) ?>
						<button type="button" class="btn-close" data-bs-dismiss="alert"></button>
					</div>
				<?php endif; ?>
				<!-- Overview Section -->
				<section id="overview">
					<div class="d-flex justify-content-between align-items-center mb-4">
						<h2>Security Overview</h2>
						<div>
							<button class="btn btn-outline-primary btn-sm me-2" onclick="refreshDashboard()">
								<i class="bi bi-arrow-clockwise"></i> Refresh </button>
							<span class="badge bg-success">System Active</span>
						</div>
					</div>
					<!-- Statistics Cards -->
					<div class="row">
						<div class="col-lg-3 col-md-6">
							<div class="stat-card">
								<div class="stat-number"><?= $securityStats['csrf']['active'] ?? 0 ?></div>
								<div class="stat-label">Active CSRF Tokens</div>
							</div>
						</div>
						<div class="col-lg-3 col-md-6">
							<div class="stat-card success">
								<div class="stat-number"><?= $ipStats['blacklist_count'] ?? 0 ?></div>
								<div class="stat-label">Blocked IPs</div>
							</div>
						</div>
						<div class="col-lg-3 col-md-6">
							<div class="stat-card warning">
								<div class="stat-number"><?= $securityStats['rate_limiting']['currently_blocked'] ?? 0 ?></div>
								<div class="stat-label">Rate Limited</div>
							</div>
						</div>
						<div class="col-lg-3 col-md-6">
							<div class="stat-card danger">
								<div class="stat-number"><?= $spamStats['recent_detections'] ?? 0 ?></div>
								<div class="stat-label">Recent Spam</div>
							</div>
						</div>
					</div>
					<!-- Charts Row -->
					<div class="row">
						<div class="col-lg-8">
							<div class="card dashboard-card">
								<div class="card-header">
									<h5 class="mb-0">Security Events (Last 24 Hours)</h5>
								</div>
								<div class="card-body">
									<div class="chart-container">
										<canvas id="securityChart"></canvas>
									</div>
								</div>
							</div>
						</div>
						<div class="col-lg-4">
							<div class="card dashboard-card">
								<div class="card-header">
									<h5 class="mb-0">Threat Distribution</h5>
								</div>
								<div class="card-body">
									<div class="chart-container">
										<canvas id="threatChart"></canvas>
									</div>
								</div>
							</div>
						</div>
					</div>
				</section>
				<!-- Quick Actions -->
				<section class="mb-5">
					<h3 class="mb-3">Quick Actions</h3>
					<div class="row">
						<div class="col-lg-3 col-md-6">
							<div class="quick-action-card" data-bs-toggle="modal" data-bs-target="#blacklistModal">
								<i class="bi bi-ban text-danger" style="font-size: 2rem;"></i>
								<h6 class="mt-2">Block IP Address</h6>
								<p class="text-muted small">Add IP to blacklist</p>
							</div>
						</div>
						<div class="col-lg-3 col-md-6">
							<div class="quick-action-card" data-bs-toggle="modal" data-bs-target="#spamKeywordModal">
								<i class="bi bi-funnel-fill text-warning" style="font-size: 2rem;"></i>
								<h6 class="mt-2">Add Spam Keyword</h6>
								<p class="text-muted small">Update spam filter</p>
							</div>
						</div>
						<div class="col-lg-3 col-md-6">
							<div class="quick-action-card" onclick="performCleanup()">
								<i class="bi bi-trash text-info" style="font-size: 2rem;"></i>
								<h6 class="mt-2">System Cleanup</h6>
								<p class="text-muted small">Clean expired data</p>
							</div>
						</div>
						<div class="col-lg-3 col-md-6">
							<div class="quick-action-card" onclick="exportLogs()">
								<i class="bi bi-download text-success" style="font-size: 2rem;"></i>
								<h6 class="mt-2">Export Logs</h6>
								<p class="text-muted small">Download security logs</p>
							</div>
						</div>
					</div>
				</section>
				<!-- Recent Activity -->
				<section>
					<div class="card dashboard-card">
						<div class="card-header d-flex justify-content-between align-items-center">
							<h5 class="mb-0">Recent Security Activity</h5>
							<a href="#" class="btn btn-sm btn-outline-primary">View All</a>
						</div>
						<div class="card-body p-0">
							<?php foreach ($recentActivity as $activity): ?>
								<div class="activity-item">
									<div class="activity-icon <?= $activity['severity'] ?>">
										<?php
										$icons = [
											'spam_detected'   => 'bi-funnel',
											'rate_limit'      => 'bi-clock',
											'ip_blocked'      => 'bi-ban',
											'token_generated' => 'bi-key'
										];
										$icon = $icons[$activity['type']] ?? 'bi-info-circle';
										?>
										<i class="bi <?= $icon ?>"></i>
									</div>
									<div class="flex-grow-1">
										<div class="fw-medium"><?= htmlspecialchars($activity['message']) ?></div>
										<div class="text-muted small"><?= date('Y-m-d H:i:s', $activity['time']) ?></div>
									</div>
									<div class="ms-2">
										<span
											class="badge bg-<?= $activity['severity'] === 'danger' ? 'danger' : ($activity['severity'] === 'warning' ? 'warning' : ($activity['severity'] === 'success' ? 'success' : 'info')) ?>">
											<?= ucfirst($activity['severity']) ?>
										</span>
									</div>
								</div>
							<?php endforeach; ?>
						</div>
					</div>
				</section>
				<!-- Detailed Statistics Tables -->
				<section class="mt-5">
					<div class="row">
						<div class="col-lg-6">
							<div class="card dashboard-card">
								<div class="card-header">
									<h5 class="mb-0">Token Statistics</h5>
								</div>
								<div class="card-body">
									<div class="table-responsive">
										<table class="table table-sm">
											<tbody>
												<tr>
													<td>Total Tokens</td>
													<td><strong><?= $tokenStats['total_tokens'] ?? 0 ?></strong></td>
												</tr>
												<tr>
													<td>Active Tokens</td>
													<td><strong><?= $tokenStats['active_tokens'] ?? 0 ?></strong></td>
												</tr>
												<tr>
													<td>Expired Tokens</td>
													<td><strong><?= $tokenStats['expired_tokens'] ?? 0 ?></strong></td>
												</tr>
												<tr>
													<td>Recent Events</td>
													<td><strong><?= $tokenStats['recent_events'] ?? 0 ?></strong></td>
												</tr>
											</tbody>
										</table>
									</div>
								</div>
							</div>
						</div>
						<div class="col-lg-6">
							<div class="card dashboard-card">
								<div class="card-header">
									<h5 class="mb-0">IP Security Status</h5>
								</div>
								<div class="card-body">
									<div class="table-responsive">
										<table class="table table-sm">
											<tbody>
												<tr>
													<td>Whitelisted IPs</td>
													<td><strong><?= $ipStats['whitelist_count'] ?? 0 ?></strong></td>
												</tr>
												<tr>
													<td>Blacklisted IPs</td>
													<td><strong><?= $ipStats['blacklist_count'] ?? 0 ?></strong></td>
												</tr>
												<tr>
													<td>Tracked IPs</td>
													<td><strong><?= $ipStats['tracked_ips'] ?? 0 ?></strong></td>
												</tr>
												<tr>
													<td>Avg Reputation</td>
													<td><strong><?= $ipStats['avg_reputation_score'] ?? 'N/A' ?></strong></td>
												</tr>
											</tbody>
										</table>
									</div>
								</div>
							</div>
						</div>
					</div>
				</section>
			</div>
		</div>
	</div>
	<!-- Blacklist Modal -->
	<div class="modal fade" id="blacklistModal" tabindex="-1">
		<div class="modal-dialog">
			<div class="modal-content">
				<form method="post">
					<div class="modal-header">
						<h5 class="modal-title">Add IP to Blacklist</h5>
						<button type="button" class="btn-close" data-bs-dismiss="modal"></button>
					</div>
					<div class="modal-body">
						<input type="hidden" name="csrf_token" value="<?= htmlspecialchars($adminCsrfToken) ?>">
						<input type="hidden" name="action" value="add_to_blacklist">
						<div class="mb-3">
							<label class="form-label">IP Address</label>
							<input type="text" class="form-control" name="ip" placeholder="192.168.1.100" required>
						</div>
						<div class="mb-3">
							<label class="form-label">Reason</label>
							<input type="text" class="form-control" name="reason" placeholder="Suspicious activity">
						</div>
					</div>
					<div class="modal-footer">
						<button type="button" class="btn btn-secondary" data-bs-dismiss="modal">Cancel</button>
						<button type="submit" class="btn btn-danger">Block IP</button>
					</div>
				</form>
			</div>
		</div>
	</div>
	<!-- Spam Keyword Modal -->
	<div class="modal fade" id="spamKeywordModal" tabindex="-1">
		<div class="modal-dialog">
			<div class="modal-content">
				<form method="post">
					<div class="modal-header">
						<h5 class="modal-title">Add Spam Keyword</h5>
						<button type="button" class="btn-close" data-bs-dismiss="modal"></button>
					</div>
					<div class="modal-body">
						<input type="hidden" name="csrf_token" value="<?= htmlspecialchars($adminCsrfToken) ?>">
						<input type="hidden" name="action" value="add_spam_keyword">
						<div class="mb-3">
							<label class="form-label">Keyword</label>
							<input type="text" class="form-control" name="keyword" placeholder="spam-word" required>
							<div class="form-text">This keyword will be added to the spam detection filter.</div>
						</div>
					</div>
					<div class="modal-footer">
						<button type="button" class="btn btn-secondary" data-bs-dismiss="modal">Cancel</button>
						<button type="submit" class="btn btn-warning">Add Keyword</button>
					</div>
				</form>
			</div>
		</div>
	</div>
	<!-- Bootstrap 5.3.7 JavaScript -->
	<script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.7/dist/js/bootstrap.bundle.min.js"></script>
	<script>
		// Security token for AJAX requests
		const csrfToken = '<?= htmlspecialchars($adminCsrfToken) ?>';

		// Initialize charts
		function initCharts() {
			// Security Events Chart
			const securityCtx = document.getElementById('securityChart').getContext('2d');
			new Chart(securityCtx, {
				type: 'line',
				data: {
					labels: ['00:00', '04:00', '08:00', '12:00', '16:00', '20:00', '24:00'],
					datasets: [{
						label: 'CSRF Attempts',
						data: [12, 19, 3, 5, 2, 3, 7],
						borderColor: 'rgb(75, 192, 192)',
						tension: 0.1
					}, {
						label: 'Spam Detected',
						data: [5, 8, 12, 7, 6, 9, 4],
						borderColor: 'rgb(255, 99, 132)',
						tension: 0.1
					}, {
						label: 'Rate Limits',
						data: [3, 2, 8, 4, 6, 2, 1],
						borderColor: 'rgb(255, 205, 86)',
						tension: 0.1
					}]
				},
				options: {
					responsive: true,
					maintainAspectRatio: false,
					scales: {
						y: {
							beginAtZero: true
						}
					}
				}
			});

			// Threat Distribution Chart
			const threatCtx = document.getElementById('threatChart').getContext('2d');
			new Chart(threatCtx, {
				type: 'doughnut',
				data: {
					labels: ['Spam', 'Rate Limit', 'IP Blocks', 'CSRF'],
					datasets: [{
						data: [<?= $spamStats['recent_detections'] ?? 0 ?>, <?= $securityStats['rate_limiting']['currently_blocked'] ?? 0 ?>, <?= $ipStats['blacklist_count'] ?? 0 ?>, <?= $securityStats['csrf']['active'] ?? 0 ?>],
						backgroundColor: [
							'rgb(255, 99, 132)',
							'rgb(255, 205, 86)',
							'rgb(54, 162, 235)',
							'rgb(75, 192, 192)'
						]
					}]
				},
				options: {
					responsive: true,
					maintainAspectRatio: false
				}
			});
		}

		// Dashboard functions
		function refreshDashboard() {
			location.reload();
		}

		function performCleanup() {
			if (confirm('Are you sure you want to perform system cleanup? This will remove expired tokens and old data.')) {
				const form = document.createElement('form');
				form.method = 'POST';

				// Create CSRF field
				const csrfField = document.createElement('input');
				csrfField.type = 'hidden';
				csrfField.name = 'csrf_token';
				csrfField.value = csrfToken;
				form.appendChild(csrfField);

				// Create action field
				const actionField = document.createElement('input');
				actionField.type = 'hidden';
				actionField.name = 'action';
				actionField.value = 'cleanup_expired';
				form.appendChild(actionField);

				document.body.appendChild(form);
				form.submit();
			}
		}

		function exportLogs() {
			// In a real implementation, this would trigger a download
			alert('Log export functionality would be implemented here.');
		}

		// Initialize when DOM is ready
		document.addEventListener('DOMContentLoaded', function () {
			initCharts();

			// Auto-refresh every 30 seconds
			setInterval(function () {
				const refreshBtn = document.querySelector('[onclick="refreshDashboard()"]');
				if (refreshBtn) {
					refreshBtn.innerHTML = '<i class="bi bi-arrow-clockwise"></i> Auto-refreshing...';
					setTimeout(refreshDashboard, 1000);
				}
			}, 30000);
		});

		// Smooth scrolling for sidebar navigation
		document.querySelectorAll('.sidebar .nav-link').forEach(link => {
			link.addEventListener('click', function (e) {
				if (this.getAttribute('href').startsWith('#')) {
					e.preventDefault();
					document.querySelectorAll('.sidebar .nav-link').forEach(l => l.classList.remove('active'));
					this.classList.add('active');

					const target = document.querySelector(this.getAttribute('href'));
					if (target) {
						target.scrollIntoView({ behavior: 'smooth' });
					}
				}
			});
		});
	</script>
</body>
</html>