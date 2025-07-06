-- Database schema for spam prevention and security
-- This schema is designed for MySQL 8.0+ or MariaDB 10.3+

-- Table for storing CSRF tokens (alternative to session storage for stateless applications)
CREATE TABLE `security_csrf_tokens` (
	`id` BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
	`token` CHAR(64) NOT NULL,
	`context` VARCHAR(255) NOT NULL,
	`user_id` BIGINT UNSIGNED NULL,
	`ip_address` VARCHAR(45) NOT NULL,
	`user_agent` VARCHAR(255) NULL,
	`expires_at` TIMESTAMP NOT NULL,
	`created_at` TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
	PRIMARY KEY (`id`),
	UNIQUE INDEX `token_UNIQUE` (`token`),
	INDEX `context_user_idx` (`context`, `user_id`),
	INDEX `expires_at_idx` (`expires_at`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Table for tracking rate limits (IP-based, user-based, and endpoint-based)
CREATE TABLE `security_rate_limits` (
	`id` BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
	`identifier` VARCHAR(255) NOT NULL COMMENT 'IP address, user ID, or endpoint',
	`type` ENUM('ip', 'user', 'endpoint') NOT NULL,
	`counter` INT UNSIGNED NOT NULL DEFAULT 1,
	`first_request` TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
	`last_request` TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
	`blocked_until` TIMESTAMP NULL,
	PRIMARY KEY (`id`),
	UNIQUE INDEX `identifier_type_UNIQUE` (`identifier`, `type`),
	INDEX `blocked_until_idx` (`blocked_until`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Table for logging spam detection events
CREATE TABLE `security_spam_log` (
	`id` BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
	`ip_address` VARCHAR(45) NOT NULL,
	`user_agent` VARCHAR(255) NULL,
	`user_id` BIGINT UNSIGNED NULL,
	`detection_type` VARCHAR(50) NOT NULL COMMENT 'honeypot, timing, csrf, challenge, etc.',
	`form_id` VARCHAR(100) NULL,
	`request_data` JSON NULL,
	`created_at` TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
	PRIMARY KEY (`id`),
	INDEX `ip_address_idx` (`ip_address`),
	INDEX `user_id_idx` (`user_id`),
	INDEX `created_at_idx` (`created_at`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Table for tracking IP reputation
CREATE TABLE `security_ip_reputation` (
	`ip_address` VARCHAR(45) NOT NULL,
	`score` SMALLINT NOT NULL DEFAULT 0 COMMENT 'Negative values indicate suspicious behavior',
	`last_evaluated` TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
	`blocked` BOOLEAN NOT NULL DEFAULT 0,
	`blocked_reason` VARCHAR(255) NULL,
	`blocked_until` TIMESTAMP NULL,
	`country_code` CHAR(2) NULL,
	`created_at` TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
	PRIMARY KEY (`ip_address`),
	INDEX `score_idx` (`score`),
	INDEX `blocked_idx` (`blocked`),
	INDEX `country_code_idx` (`country_code`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Stored procedure to clean up expired tokens
DELIMITER //
CREATE PROCEDURE `sp_cleanup_expired_tokens`()
BEGIN
	DELETE FROM `security_csrf_tokens` WHERE `expires_at` < NOW();
END //
DELIMITER ;

-- Event to periodically clean up expired tokens
CREATE EVENT `evt_cleanup_expired_tokens`
ON SCHEDULE EVERY 1 HOUR
DO
	CALL sp_cleanup_expired_tokens();