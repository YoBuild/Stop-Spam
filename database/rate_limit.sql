-- Create table for rate limiting tracking
CREATE TABLE `rate_limits` (
	`id` INT UNSIGNED NOT NULL AUTO_INCREMENT,
	`identifier` VARCHAR(255) NOT NULL COMMENT 'IP address or user ID',
	`action_type` VARCHAR(50) NOT NULL COMMENT 'Type of action (post, message, login, etc.)',
	`request_count` INT UNSIGNED NOT NULL DEFAULT 1,
	`first_request_time` TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
	`last_request_time` TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
	`blocked_until` TIMESTAMP NULL DEFAULT NULL,
	`created_at` TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
	`updated_at` TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
	PRIMARY KEY (`id`),
	UNIQUE KEY `identifier_action_idx` (`identifier`, `action_type`),
	INDEX `blocked_until_idx` (`blocked_until`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Create table for rate limit configurations
CREATE TABLE `rate_limit_config` (
	`id` INT UNSIGNED NOT NULL AUTO_INCREMENT,
	`action_type` VARCHAR(50) NOT NULL COMMENT 'Type of action to limit',
	`max_requests` INT UNSIGNED NOT NULL,
	`time_window` INT UNSIGNED NOT NULL COMMENT 'Time window in seconds',
	`block_duration` INT UNSIGNED NOT NULL COMMENT 'Initial block time in seconds',
	`block_multiplier` FLOAT NOT NULL DEFAULT 2.0 COMMENT 'Multiplier for repeat offenders',
	`created_at` TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
	`updated_at` TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
	PRIMARY KEY (`id`),
	UNIQUE KEY `action_type_idx` (`action_type`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Insert default rate limit configurations
INSERT INTO `rate_limit_config`
	(`action_type`, `max_requests`, `time_window`, `block_duration`, `block_multiplier`)
VALUES
	('login', 5, 300, 900, 2.0),
	('post', 10, 600, 1800, 2.0),
	('message', 20, 600, 900, 2.0),
	('profile_view', 50, 300, 600, 1.5),
	('search', 15, 60, 300, 1.5);