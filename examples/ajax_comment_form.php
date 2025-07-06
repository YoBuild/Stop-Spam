<?php
/**
 * Advanced example implementation showing AJAX form submission with the security system
 */

// Include autoloader or require necessary files
// require_once 'path/to/autoloader.php';

use Yohns\Core\Config;
use Yohns\Security\SecurityConfig;
use Yohns\Security\CSRFToken;
use Yohns\Security\SpamDetector;
use Yohns\Security\TokenStorage;
use PDOChainer\PDOChainer;

// Initialize configuration
SecurityConfig::load();

// Create database connection
$dbOptions = [
	'host' => Config::get('db_host', 'database'),
	'dbname' => Config::get('db_name', 'database'),
	'user' => Config::get('db_user', 'database'),
	'pass' => Config::get('db_pass', 'database')
];

$pdo = new PDOChainer($dbOptions);

// Initialize security detector
$detector = new SpamDetector();

// Handle AJAX form submission
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_SERVER['HTTP_X_REQUESTED_WITH']) && $_SERVER['HTTP_X_REQUESTED_WITH'] === 'XMLHttpRequest') {
	// Set response headers
	header('Content-Type: application/json');

	$formId = 'comment_form';
	$response = ['success' => false, 'message' => '', 'data' => null];

	try {
		// Validate request
		if (!$detector->validateRequest($_POST, $formId)) {
			throw new \Exception('Your submission was flagged as potential spam. Please try again.');
		}

		// Process the comment submission
		$postId = $_POST['post_id'] ?? 0;
		$content = $_POST['comment'] ?? '';
		$name = $_POST['name'] ?? '';

		// Validate input
		if (empty($postId) || !is_numeric($postId)) {
			throw new \Exception('Invalid post ID.');
		}

		if (empty($content)) {
			throw new \Exception('Comment cannot be empty.');
		}

		if (empty($name)) {
			throw new \Exception('Name cannot be empty.');
		}

		// Insert comment into database
		$timestamp = date('Y-m-d H:i:s');
		$data = [
			['post_id', $postId, \PDO::PARAM_INT],
			['author_name', $name],
			['content', $content],
			['created_at', $timestamp]
		];

		$commentId = $pdo->DBAL->insert('comments', $data);

		if (!$commentId) {
			throw new \Exception('Failed to save your comment. Please try again.');
		}

		// Return success response with the new comment data
		$response['success'] = true;
		$response['message'] = 'Your comment has been posted successfully!';
		$response['data'] = [
			'id' => $commentId,
			'author' => $name,
			'content' => $content,
			'timestamp' => $timestamp
		];

		// Generate a new CSRF token for the next submission
		$newToken = CSRFToken::generate($formId);
		$response['csrf_token'] = $newToken;

	} catch (\Exception $e) {
		$response['message'] = $e->getMessage();
	}

	// Output JSON response
	echo json_encode($response);
	exit;
}

// Get post ID from query string
$postId = $_GET['id'] ?? 1;

// Get post details (placeholder for demonstration)
$post = [
	'id' => $postId,
	'title' => 'Sample Blog Post',
	'content' => 'This is a sample blog post content. It demonstrates how to implement AJAX comment forms with security measures.',
	'author' => 'John Doe',
	'date' => '2025-05-10'
];

// Get existing comments (placeholder for demonstration)
$comments = [
	[
		'id' => 1,
		'author' => 'Jane Smith',
		'content' => 'Great article! Thanks for sharing.',
		'timestamp' => '2025-05-11 10:30:45'
	],
	[
		'id' => 2,
		'author' => 'Bob Johnson',
		'content' => 'I have a question about the third paragraph...',
		'timestamp' => '2025-05-11 14:22:18'
	]
];

?>
<!DOCTYPE html>
<html lang="en">
<head>
	<meta charset="UTF-8">
	<meta name="viewport" content="width=device-width, initial-scale=1.0">
	<title><?= htmlspecialchars($post['title']) ?></title>
	<style>
		body { font-family: Arial, sans-serif; line-height: 1.6; max-width: 800px; margin: 0 auto; padding: 20px; }
		.blog-post { margin-bottom: 30px; }
		.post-meta { color: #666; font-size: 0.9em; margin-bottom: 20px; }
		.comments { margin-top: 40px; }
		.comment { padding: 15px; border-bottom: 1px solid #eee; }
		.comment-meta { font-size: 0.8em; color: #666; }
		.comment-form { margin-top: 30px; background: #f9f9f9; padding: 20px; border-radius: 5px; }
		.form-group { margin-bottom: 15px; }
		label { display: block; margin-bottom: 5px; }
		input, textarea { width: 100%; padding: 8px; box-sizing: border-box; }
		button { padding: 10px 15px; background: #4CAF50; color: white; border: none; cursor: pointer; }
		.error { color: red; }
		.success { color: green; }
		.hidden { display: none; }
	</style>
</head>
<body>
	<div class="blog-post">
		<h1><?= htmlspecialchars($post['title']) ?></h1>
		<div class="post-meta">
			Posted by <?= htmlspecialchars($post['author']) ?> on <?= htmlspecialchars($post['date']) ?>
		</div>
		<div class="post-content">
			<?= htmlspecialchars($post['content']) ?>
		</div>
	</div>

	<div class="comments">
		<h2>Comments</h2>

		<div id="comments-container">
			<?php foreach ($comments as $comment): ?>
				<div class="comment" id="comment-<?= $comment['id'] ?>">
					<div class="comment-content"><?= htmlspecialchars($comment['content']) ?></div>
					<div class="comment-meta">
						Posted by <?= htmlspecialchars($comment['author']) ?> on <?= htmlspecialchars($comment['timestamp']) ?>
					</div>
				</div>
			<?php endforeach; ?>
		</div>

		<div class="comment-form">
			<h3>Add a Comment</h3>
			<div id="form-messages"></div>

			<form id="comment-form" method="post">
				<input type="hidden" name="post_id" value="<?= htmlspecialchars($postId) ?>">

				<div class="form-group">
					<label for="name">Your Name:</label>
					<input type="text" id="name" name="name" required>
				</div>

				<div class="form-group">
					<label for="comment">Your Comment:</label>
					<textarea id="comment" name="comment" rows="5" required></textarea>
				</div>

				<?= $detector->protectForm('comment_form') ?>

				<button type="submit">Submit Comment</button>
			</form>
		</div>
	</div>

	<!-- Include the JavaScript validator -->
	<script src="/js/SecurityValidator.js"></script>
	<script>
		document.addEventListener('DOMContentLoaded', () => {
			// Initialize security validator
			const validator = new SecurityValidator('#comment-form', {
				minSubmitTime: 1000
			});

			// Handle form submission via AJAX
			const commentForm = document.getElementById('comment-form');
			const messagesContainer = document.getElementById('form-messages');
			const commentsContainer = document.getElementById('comments-container');

			commentForm.addEventListener('submit', function(e) {
				e.preventDefault();

				// Clear previous messages
				messagesContainer.innerHTML = '';

				// Collect form data
				const formData = new FormData(commentForm);

				// Send AJAX request
				fetch(window.location.href, {
					method: 'POST',
					body: formData,
					headers: {
						'X-Requested-With': 'XMLHttpRequest'
					}
				})
				.then(response => response.json())
				.then(response => {
					if (response.success) {
						// Show success message
						messagesContainer.innerHTML = `<div class="success">${response.message}</div>`;

						// Add new comment to the page
						const newComment = createCommentElement(response.data);
						commentsContainer.appendChild(newComment);

						// Reset form
						commentForm.reset();

						// Update CSRF token
						if (response.csrf_token) {
							const csrfInput = commentForm.querySelector('[name="csrf_token"]');
							if (csrfInput) {
								csrfInput.value = response.csrf_token;
							}
						}
					} else {
						// Show error message
						messagesContainer.innerHTML = `<div class="error">${response.message}</div>`;
					}
				})
				.catch(error => {
					console.error('Error:', error);
					messagesContainer.innerHTML = '<div class="error">An error occurred while submitting your comment. Please try again.</div>';
				});
			});

			// Helper function to create a comment element
			function createCommentElement(comment) {
				const commentDiv = document.createElement('div');
				commentDiv.className = 'comment';
				commentDiv.id = `comment-${comment.id}`;

				const contentDiv = document.createElement('div');
				contentDiv.className = 'comment-content';
				contentDiv.textContent = comment.content;

				const metaDiv = document.createElement('div');
				metaDiv.className = 'comment-meta';
				metaDiv.textContent = `Posted by ${comment.author} on ${comment.timestamp}`;

				commentDiv.appendChild(contentDiv);
				commentDiv.appendChild(metaDiv);

				return commentDiv;
			}
		});
	</script>
</body>
</html>