<?php

return [

	// Debug and Development
	'app' => [
		'debug' => false, // Set to true for development debugging
	],

	// File Storage Settings
	'storage'            => [
		'type'                  => 'json', // json file storage
		'directory'             => __DIR__ . '/../database',
		'file_permissions'      => 0664,
		'directory_permissions' => 0755,
		'auto_cleanup'          => true,
		'cleanup_interval'      => 3600, // 1 hour in seconds
	],

	// CSRF Protection
	'csrf'               => [
		'enabled'        => true,
		'expiration'     => 1800, // 30 minutes in seconds
		'session_prefix' => 'csrf_token_',
		'header_name'    => 'X-CSRF-TOKEN',
		'cookie_name'    => 'XSRF-TOKEN',
		'same_site'      => 'Lax',
		'token_length'   => 32,
	],

	// Honeypot Detection
	'honeypot'           => [
		'enabled'        => true,
		'field_name'     => 'website',
		'min_time'       => 2, // seconds
		'max_time'       => 3600, // 1 hour in seconds
		'session_prefix' => 'honeypot_',
	],

	// Spam Detection
	'spam_detection'     => [
		'enabled'              => true,
		'log_enabled'          => true,
		'log_file'             => __DIR__ . '/../database/spam_log.json',
		'challenge_enabled'    => false,
		'js_token_secret'      => 'your-random-secret-key-change-this',
		'max_links'            => 3,
		'max_capitals_percent' => 70,
		'max_repeated_chars'   => 5,
	],

	// Rate Limiting
	'rate_limiting'      => [
		'enabled'          => true,
		'storage'          => 'json', // json file storage
		'global_max'       => 1000, // requests per hour
		'per_endpoint'     => 100, // requests per minute
		'per_ip'           => 300, // requests per minute
		'login_max'        => 5, // attempts per 15 minutes
		'block_duration'   => 900, // 15 minutes in seconds
		'block_multiplier' => 2.0, // multiplier for repeat offenders
	],

	// Content Validation
	'content_validation' => [
		'enabled'          => true,
		'max_length'       => 10000,
		'allow_html'       => false,
		'strip_tags'       => true,
		'profanity_filter' => true,
	],

	// IP Security
	'ip_security'        => [
		'enabled'         => true,
		'whitelist'       => [],
		'blacklist'       => [],
		'check_proxies'   => true,
		'max_proxy_depth' => 3,
	],

	// Logging
	'logging'            => [
		'enabled'       => true,
		'level'         => 'info', // debug, info, warning, error
		'directory'     => __DIR__ . '/../database',
		'max_file_size' => 10485760, // 10MB
		'max_files'     => 5,
	],

	// Domain and URLs
	'domain'             => [
		'base_url'        => 'http://stop-spam.jb',
		'allowed_origins' => [
			'https://stop-spam.jb',
			'http://stop-spam.jb'
		],
	],

	// Directories
	'directories'        => [
		'database'      => __DIR__ . '/../database',
		'config'        => __DIR__,
		'docs'          => __DIR__ . '/../docs',
		'examples'      => __DIR__ . '/../examples',
		'public_assets' => __DIR__ . '/../public/assets',
	],

	// Content Security Policy
	'csp_cdn_sources'    => [
		'https://cdn.jsdelivr.net',
		'https://cdnjs.cloudflare.com',
		'https://fonts.googleapis.com',
		'https://fonts.gstatic.com',
		'https://unpkg.com',
	],
];