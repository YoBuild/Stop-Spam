<?php

return [
	// Token security settings
	'token_secret' => '', // Will be generated automatically if empty

	// Trusted proxy IPs (for getting real client IP behind load balancers)
	'trusted_proxies' => [
		'127.0.0.1',
		'::1',
		// Add your load balancer/proxy IPs here
	],

	// Blacklisted IP addresses or CIDR ranges
	'blacklisted_ips' => [
		// Example: '192.168.1.100',
		// Example CIDR: '10.0.0.0/8',
	],

	// Whitelisted IP addresses or CIDR ranges (bypass rate limiting and blacklist)
	'whitelisted_ips' => [
		// Example: '192.168.1.1',
		// Example: '127.0.0.1',
	],

	// Spam keywords to detect in content
	'spam_keywords' => [
		'viagra',
		'cialis',
		'casino',
		'lottery',
		'winner',
		'congratulations',
		'urgent',
		'click here',
		'act now',
		'limited time',
		'free money',
		'make money fast',
		'work from home',
		'guaranteed',
		'no obligation',
		'risk free',
		'amazing deal',
		'special promotion',
		'exclusive offer',
		'once in lifetime',
	],

	// Regular expression patterns for spam detection
	'spam_patterns' => [
		// URLs with suspicious TLDs
		'/https?:\/\/.*\.(xyz|top|loan|work|click|gq|ml|ga|cf|tk)\b/i',
		// Too many URLs in content
		'/((https?:\/\/|www\.)[^\s<>"\']+){5,}/i',
		// Excessive use of keywords like "free", "discount", "offer"
		'/\b(free|discount|offer|buy|sell|promotion|deal|limited\s+time|special\s+offer)\b.*\1.*\1.*\1/i',
		// Hidden text using CSS tricks
		'/style\s*=\s*["\'].*display\s*:\s*none/i',
		// Excessive capitalization
		'/[A-Z\s]{50,}/',
		// Phone numbers with common spam patterns
		'/\b(?:\+?1[-.\s]?)?\(?[0-9]{3}\)?[-.\s]?[0-9]{3}[-.\s]?[0-9]{4}\b.*\b(?:\+?1[-.\s]?)?\(?[0-9]{3}\)?[-.\s]?[0-9]{3}[-.\s]?[0-9]{4}\b/i',
	],

	// Profanity filter words
	'profanity_list' => [
		// Add profanity words here as needed
		// This list is intentionally minimal for the example
		'badword1',
		'badword2',
	],

	// Whether to use the profanity filter
	'use_profanity_filter' => true,

	// Maximum file upload size (in bytes)
	'max_upload_size' => 10485760, // 10MB

	// Allowed file extensions for uploads
	'allowed_file_extensions' => [
		'jpg', 'jpeg', 'png', 'gif', 'webp', // Images
		'mp4', 'webm', 'ogg', // Videos
		'pdf', 'doc', 'docx', 'txt', // Documents
	],

	// Session security settings
	'session_timeout' => 3600, // 1 hour
	'session_regenerate_interval' => 1800, // 30 minutes

	// Password security settings
	'password_min_length' => 8,
	'password_require_uppercase' => true,
	'password_require_lowercase' => true,
	'password_require_numbers' => true,
	'password_require_symbols' => false,

	// Login attempt settings
	'max_login_attempts' => 5,
	'login_lockout_duration' => 900, // 15 minutes

	// Content moderation settings
	'auto_moderate_content' => true,
	'content_approval_required' => false,
	'spam_threshold' => 0.6, // 0.0 to 1.0, higher = more strict
];