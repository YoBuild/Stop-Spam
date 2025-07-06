<?php

return [
	// Login rate limiting
	'login' => [
		'max_requests' => 5,        // Maximum login attempts
		'time_window' => 300,       // Time window in seconds (5 minutes)
		'block_duration' => 900,    // Block duration in seconds (15 minutes)
		'block_multiplier' => 2.0,  // Multiplier for repeat offenders
	],

	// Post creation rate limiting
	'post' => [
		'max_requests' => 10,       // Maximum posts
		'time_window' => 600,       // Time window in seconds (10 minutes)
		'block_duration' => 1800,   // Block duration in seconds (30 minutes)
		'block_multiplier' => 2.0,  // Multiplier for repeat offenders
	],

	// Private messaging rate limiting
	'message' => [
		'max_requests' => 20,       // Maximum messages
		'time_window' => 600,       // Time window in seconds (10 minutes)
		'block_duration' => 900,    // Block duration in seconds (15 minutes)
		'block_multiplier' => 2.0,  // Multiplier for repeat offenders
	],

	// Profile viewing rate limiting
	'profile_view' => [
		'max_requests' => 50,       // Maximum profile views
		'time_window' => 300,       // Time window in seconds (5 minutes)
		'block_duration' => 600,    // Block duration in seconds (10 minutes)
		'block_multiplier' => 1.5,  // Multiplier for repeat offenders
	],

	// Search rate limiting
	'search' => [
		'max_requests' => 15,       // Maximum searches
		'time_window' => 60,        // Time window in seconds (1 minute)
		'block_duration' => 300,    // Block duration in seconds (5 minutes)
		'block_multiplier' => 1.5,  // Multiplier for repeat offenders
	],

	// Friend request rate limiting
	'friend_request' => [
		'max_requests' => 10,       // Maximum friend requests
		'time_window' => 3600,      // Time window in seconds (1 hour)
		'block_duration' => 7200,   // Block duration in seconds (2 hours)
		'block_multiplier' => 3.0,  // Multiplier for repeat offenders
	],

	// Comment rate limiting
	'comment' => [
		'max_requests' => 15,       // Maximum comments
		'time_window' => 600,       // Time window in seconds (10 minutes)
		'block_duration' => 1200,   // Block duration in seconds (20 minutes)
		'block_multiplier' => 2.0,  // Multiplier for repeat offenders
	],

	// Like/reaction rate limiting
	'like' => [
		'max_requests' => 100,      // Maximum likes
		'time_window' => 300,       // Time window in seconds (5 minutes)
		'block_duration' => 600,    // Block duration in seconds (10 minutes)
		'block_multiplier' => 1.5,  // Multiplier for repeat offenders
	],

	// Report/flag rate limiting
	'report' => [
		'max_requests' => 5,        // Maximum reports
		'time_window' => 3600,      // Time window in seconds (1 hour)
		'block_duration' => 3600,   // Block duration in seconds (1 hour)
		'block_multiplier' => 2.5,  // Multiplier for repeat offenders
	],

	// Registration rate limiting (by IP)
	'register' => [
		'max_requests' => 3,        // Maximum registrations per IP
		'time_window' => 3600,      // Time window in seconds (1 hour)
		'block_duration' => 7200,   // Block duration in seconds (2 hours)
		'block_multiplier' => 4.0,  // Multiplier for repeat offenders
	],

	// Password reset rate limiting
	'password_reset' => [
		'max_requests' => 3,        // Maximum password reset attempts
		'time_window' => 3600,      // Time window in seconds (1 hour)
		'block_duration' => 3600,   // Block duration in seconds (1 hour)
		'block_multiplier' => 2.0,  // Multiplier for repeat offenders
	],

	// File upload rate limiting
	'upload' => [
		'max_requests' => 10,       // Maximum uploads
		'time_window' => 600,       // Time window in seconds (10 minutes)
		'block_duration' => 1800,   // Block duration in seconds (30 minutes)
		'block_multiplier' => 2.5,  // Multiplier for repeat offenders
	],
];