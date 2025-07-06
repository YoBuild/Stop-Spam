<?php

namespace Yohns\Security;

use Yohns\Core\Config;

/**
 * CSRFMiddleware class for automating CSRF protection on requests.
 *
 * This middleware can be used to automatically check for valid CSRF tokens
 * on POST, PUT, DELETE, and PATCH requests.
 *
 * Examples:
 * ```php
 * // Basic usage in a middleware-enabled framework
 * $middleware = new CSRFMiddleware();
 * $middleware->protect();
 *
 * // With custom configuration
 * $middleware = new CSRFMiddleware([
 *     'except' => ['api/webhook', 'api/callback'],
 *     'error_response' => function() {
 *         header('HTTP/1.1 403 Forbidden');
 *         echo json_encode(['error' => 'CSRF token validation failed']);
 *         exit;
 *     }
 * ]);
 * ```
 */
class CSRFMiddleware {
	/**
	 * @var array Request methods that require CSRF validation
	 */
	private array $protectedMethods = ['POST', 'PUT', 'DELETE', 'PATCH'];

	/**
	 * @var array Routes that are exempt from CSRF protection
	 */
	private array $except = [];

	/**
	 * @var callable Custom error response handler
	 */
	private $errorResponseHandler;

	/**
	 * Create a new CSRFMiddleware instance.
	 *
	 * @param array $options Configuration options
	 */
	public function __construct(array $options = []) {
		// Initialize CSRFToken if not already initialized
		CSRFToken::init();

		// Set protected methods if provided
		if (isset($options['methods']) && is_array($options['methods'])) {
			$this->protectedMethods = $options['methods'];
		}

		// Set exempt routes if provided
		if (isset($options['except']) && is_array($options['except'])) {
			$this->except = $options['except'];
		}

		// Set custom error response handler if provided
		if (isset($options['error_response']) && is_callable($options['error_response'])) {
			$this->errorResponseHandler = $options['error_response'];
		}
	}

	/**
	 * Protect the current request against CSRF attacks.
	 *
	 * @param string $context Optional context name, defaults to current URI
	 * @return bool True if the request is safe, false otherwise
	 */
	public function protect(string $context = ''): bool {
		// Only validate for protected methods
		$requestMethod = $_SERVER['REQUEST_METHOD'] ?? '';
		if (!in_array($requestMethod, $this->protectedMethods)) {
			return true;
		}

		// Get current request path
		$requestUri = $_SERVER['REQUEST_URI'] ?? '';
		$requestPath = parse_url($requestUri, PHP_URL_PATH);

		// Skip validation for exempt routes
		foreach ($this->except as $exemptRoute) {
			if ($this->matchesRoute($requestPath, $exemptRoute)) {
				return true;
			}
		}

		// Determine token context if not provided
		if (empty($context)) {
			$context = $requestPath;
		}

		// Get token from request
		$token = $_POST['csrf_token'] ?? $_SERVER['HTTP_X_CSRF_TOKEN'] ?? null;

		// Validate token
		if ($token && CSRFToken::validate($token, $context)) {
			return true;
		}

		// Handle invalid token
		$this->handleError();
		return false;
	}

	/**
	 * Check if a request path matches an exempt route pattern.
	 *
	 * @param string $requestPath The current request path
	 * @param string $exemptRoute The exempt route pattern
	 * @return bool True if the path matches the exempt route
	 */
	private function matchesRoute(string $requestPath, string $exemptRoute): bool {
		// Simple string comparison
		if ($exemptRoute === $requestPath) {
			return true;
		}

		// Wildcard matching (e.g., 'api/*')
		if (substr($exemptRoute, -1) === '*') {
			$prefix = rtrim(substr($exemptRoute, 0, -1), '/');
			return strpos($requestPath, $prefix) === 0;
		}

		// Regular expression matching (e.g., '~^/api/v\d+/~')
		if (substr($exemptRoute, 0, 1) === '~') {
			return preg_match($exemptRoute, $requestPath) === 1;
		}

		return false;
	}

	/**
	 * Handle CSRF validation error.
	 *
	 * @return void
	 */
	private function handleError(): void {
		// Use custom error handler if provided
		if (isset($this->errorResponseHandler) && is_callable($this->errorResponseHandler)) {
			call_user_func($this->errorResponseHandler);
			return;
		}

		// Default error response
		header('HTTP/1.1 403 Forbidden');
		header('Content-Type: text/html; charset=UTF-8');

		echo '<!DOCTYPE html>
<html>
<head>
	<title>403 Forbidden</title>
</head>
<body>
	<h1>403 Forbidden</h1>
	<p>Invalid or expired security token. Please try again.</p>
</body>
</html>';
		exit;
	}
}