<?php

namespace Yohns\Security;

use Yohns\Core\Config;
use InvalidArgumentException;
use RuntimeException;

/**
 * FileStorage class for managing JSON file-based data storage
 *
 * This class provides a simple JSON file storage system to replace MySQL
 * for security tokens, rate limits, and spam detection logs. Features
 * automatic cleanup, file locking, and configurable permissions.
 *
 * @package Yohns\Security
 * @version 1.0.0
 * @author  Yohns Framework
 *
 * Usage example:
 * ```php
 * $storage = new FileStorage();
 * // Insert a record
 * $id = $storage->insert('users', ['name' => 'John', 'email' => 'john@example.com']);
 * // Find records
 * $users = $storage->find('users', ['name' => 'John']);
 * // Update a record
 * $storage->update('users', $id, ['email' => 'newemail@example.com']);
 * ```
 */
class FileStorage {
	private string $storageDirectory;
	private int    $filePermissions;
	private int    $directoryPermissions;
	private bool   $autoCleanup;
	private int    $cleanupInterval;

	/**
	 * Constructor - Initialize file storage with configuration
	 *
	 * Sets up the file storage system with configuration from Config class.
	 * Creates storage directory if it doesn't exist and validates permissions.
	 *
	 * @throws RuntimeException If storage directory cannot be created or is not writable
	 *
	 * Usage example:
	 * ```php
	 * $storage = new FileStorage();
	 * // Storage is now ready to use
	 * ```
	 */
	public function __construct() {
		$this->storageDirectory = Config::get('storage.directory', 'security') ?: __DIR__ . '/../../database';
		$this->filePermissions = Config::get('storage.file_permissions', 'security') ?: 0664;
		$this->directoryPermissions = Config::get('storage.directory_permissions', 'security') ?: 0755;
		$this->autoCleanup = Config::get('storage.auto_cleanup', 'security') ?? true;
		$this->cleanupInterval = Config::get('storage.cleanup_interval', 'security') ?: 3600;

		$this->ensureDirectoryExists();
	}

	/**
	 * Ensure the storage directory exists with proper permissions
	 *
	 * Creates the storage directory if it doesn't exist and verifies
	 * that it has proper write permissions for the application.
	 *
	 * @return void
	 * @throws RuntimeException If directory creation fails or directory is not writable
	 *
	 * Usage example:
	 * ```php
	 * $this->ensureDirectoryExists();
	 * // Storage directory is now ready for use
	 * ```
	 */
	private function ensureDirectoryExists(): void {
		if (!is_dir($this->storageDirectory)) {
			if (!mkdir($this->storageDirectory, $this->directoryPermissions, true)) {
				throw new RuntimeException("Failed to create storage directory: {$this->storageDirectory}");
			}
		}

		if (!is_writable($this->storageDirectory)) {
			throw new RuntimeException("Storage directory is not writable: {$this->storageDirectory}");
		}
	}

	/**
	 * Get the full path for a storage file
	 *
	 * Constructs the complete file path for a given table name
	 * by combining storage directory with table name and .json extension.
	 *
	 * @param string $table Table name to get file path for
	 * @return string Complete file path for the table
	 *
	 * Usage example:
	 * ```php
	 * $path = $this->getFilePath('users');
	 * // Returns: /path/to/storage/users.json
	 * ```
	 */
	private function getFilePath(string $table): string {
		return $this->storageDirectory . '/' . $table . '.json';
	}

	/**
	 * Read data from a JSON file
	 *
	 * Loads and parses JSON data from the specified table file.
	 * Performs automatic cleanup if enabled and validates JSON format.
	 *
	 * @param string $table Table name to read data from
	 * @return array Array of records from the table
	 * @throws RuntimeException If file cannot be read or contains invalid JSON
	 *
	 * Usage example:
	 * ```php
	 * $storage = new FileStorage();
	 * $users = $storage->read('users');
	 * foreach ($users as $id => $user) {
	 *     echo "User: " . $user['name'] . "\n";
	 * }
	 * ```
	 */
	public function read(string $table): array {
		$filePath = $this->getFilePath($table);

		if (!file_exists($filePath)) {
			return [];
		}

		$content = file_get_contents($filePath);
		if ($content === false) {
			throw new RuntimeException("Failed to read file: {$filePath}");
		}

		$data = json_decode($content, true);
		if (json_last_error() !== JSON_ERROR_NONE) {
			throw new RuntimeException("Invalid JSON in file {$filePath}: " . json_last_error_msg());
		}

		// Auto cleanup if enabled
		if ($this->autoCleanup) {
			$data = $this->performCleanup($table, $data);
		}

		return $data ?: [];
	}

	/**
	 * Write data to a JSON file
	 *
	 * Saves data array to the specified table file as formatted JSON.
	 * Uses file locking to prevent corruption and sets proper permissions.
	 *
	 * @param string $table Table name to write data to
	 * @param array  $data  Data array to save
	 * @return bool True on success
	 * @throws RuntimeException If JSON encoding fails or file cannot be written
	 *
	 * Usage example:
	 * ```php
	 * $storage = new FileStorage();
	 * $data = ['user1' => ['name' => 'John'], 'user2' => ['name' => 'Jane']];
	 * $storage->write('users', $data);
	 * echo "Data saved successfully";
	 * ```
	 */
	public function write(string $table, array $data): bool {
		$filePath = $this->getFilePath($table);

		$json = json_encode($data, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES);
		if ($json === false) {
			throw new RuntimeException("Failed to encode JSON for table: {$table}");
		}

		$result = file_put_contents($filePath, $json, LOCK_EX);
		if ($result === false) {
			throw new RuntimeException("Failed to write file: {$filePath}");
		}

		// Set file permissions
		chmod($filePath, $this->filePermissions);

		return true;
	}

	/**
	 * Insert a record into a table
	 *
	 * Adds a new record to the specified table with auto-generated ID
	 * and timestamps. Returns the generated ID for future reference.
	 *
	 * @param string $table  Table name to insert into
	 * @param array  $record Record data to insert
	 * @return string Generated unique ID for the inserted record
	 * @throws RuntimeException If write operation fails
	 *
	 * Usage example:
	 * ```php
	 * $storage = new FileStorage();
	 * $id = $storage->insert('users', [
	 *     'name' => 'John Doe',
	 *     'email' => 'john@example.com',
	 *     'role' => 'admin'
	 * ]);
	 * echo "User created with ID: " . $id;
	 * ```
	 */
	public function insert(string $table, array $record): string {
		$data = $this->read($table);

		// Generate unique ID
		$id = $this->generateId();
		$record['id'] = $id;
		$record['created_at'] = time();
		$record['updated_at'] = time();

		$data[$id] = $record;
		$this->write($table, $data);

		return $id;
	}

	/**
	 * Update a record in a table
	 *
	 * Updates an existing record by merging new data with existing record.
	 * Automatically updates the 'updated_at' timestamp.
	 *
	 * @param string $table   Table name containing the record
	 * @param string $id      ID of record to update
	 * @param array  $updates Array of fields to update
	 * @return bool True if record was updated, false if record not found
	 * @throws RuntimeException If write operation fails
	 *
	 * Usage example:
	 * ```php
	 * $storage = new FileStorage();
	 * $success = $storage->update('users', $userId, [
	 *     'email' => 'newemail@example.com',
	 *     'last_login' => time()
	 * ]);
	 * if ($success) {
	 *     echo "User updated successfully";
	 * }
	 * ```
	 */
	public function update(string $table, string $id, array $updates): bool {
		$data = $this->read($table);

		if (!isset($data[$id])) {
			return false;
		}

		$data[$id] = array_merge($data[$id], $updates);
		$data[$id]['updated_at'] = time();

		$this->write($table, $data);
		return true;
	}

	/**
	 * Delete a record from a table
	 *
	 * Removes the specified record from the table permanently.
	 * This operation cannot be undone.
	 *
	 * @param string $table Table name containing the record
	 * @param string $id    ID of record to delete
	 * @return bool True if record was deleted, false if record not found
	 * @throws RuntimeException If write operation fails
	 *
	 * Usage example:
	 * ```php
	 * $storage = new FileStorage();
	 * if ($storage->delete('users', $userId)) {
	 *     echo "User deleted successfully";
	 * } else {
	 *     echo "User not found";
	 * }
	 * ```
	 */
	public function delete(string $table, string $id): bool {
		$data = $this->read($table);

		if (!isset($data[$id])) {
			return false;
		}

		unset($data[$id]);
		$this->write($table, $data);
		return true;
	}

	/**
	 * Find records in a table by criteria
	 *
	 * Searches for records matching the specified criteria using exact matching.
	 * Returns all records if no criteria provided.
	 *
	 * @param string $table    Table name to search in
	 * @param array  $criteria Key-value pairs for filtering records
	 * @return array Array of matching records (re-indexed)
	 *
	 * Usage example:
	 * ```php
	 * $storage = new FileStorage();
	 * // Find all active users
	 * $activeUsers = $storage->find('users', ['status' => 'active']);
	 * // Find all records
	 * $allUsers = $storage->find('users');
	 * foreach ($activeUsers as $user) {
	 *     echo "Active user: " . $user['name'] . "\n";
	 * }
	 * ```
	 */
	public function find(string $table, array $criteria = []): array {
		$data = $this->read($table);

		if (empty($criteria)) {
			return array_values($data);
		}

		$results = [];
		foreach ($data as $record) {
			$match = true;
			foreach ($criteria as $field => $value) {
				if (!isset($record[$field]) || $record[$field] !== $value) {
					$match = false;
					break;
				}
			}
			if ($match) {
				$results[] = $record;
			}
		}

		return $results;
	}

	/**
	 * Find a single record in a table by criteria
	 *
	 * Returns the first record matching the specified criteria,
	 * or null if no matching record is found.
	 *
	 * @param string $table    Table name to search in
	 * @param array  $criteria Key-value pairs for filtering records
	 * @return array|null First matching record or null if not found
	 *
	 * Usage example:
	 * ```php
	 * $storage = new FileStorage();
	 * $user = $storage->findOne('users', ['email' => 'john@example.com']);
	 * if ($user) {
	 *     echo "Found user: " . $user['name'];
	 * } else {
	 *     echo "User not found";
	 * }
	 * ```
	 */
	public function findOne(string $table, array $criteria): ?array {
		$results = $this->find($table, $criteria);
		return $results[0] ?? null;
	}

	/**
	 * Count records in a table
	 *
	 * Returns the number of records matching the specified criteria.
	 * Counts all records if no criteria provided.
	 *
	 * @param string $table    Table name to count records in
	 * @param array  $criteria Key-value pairs for filtering records
	 * @return int Number of matching records
	 *
	 * Usage example:
	 * ```php
	 * $storage = new FileStorage();
	 * $totalUsers = $storage->count('users');
	 * $activeUsers = $storage->count('users', ['status' => 'active']);
	 * echo "Total users: {$totalUsers}, Active: {$activeUsers}";
	 * ```
	 */
	public function count(string $table, array $criteria = []): int {
		return count($this->find($table, $criteria));
	}

	/**
	 * Clear all records from a table
	 *
	 * Removes all records from the specified table, effectively
	 * resetting it to an empty state. This operation cannot be undone.
	 *
	 * @param string $table Table name to clear
	 * @return bool True on success
	 * @throws RuntimeException If write operation fails
	 *
	 * Usage example:
	 * ```php
	 * $storage = new FileStorage();
	 * if ($storage->clear('temp_data')) {
	 *     echo "Temporary data cleared successfully";
	 * }
	 * // Warning: This will delete ALL records in the table
	 * ```
	 */
	public function clear(string $table): bool {
		return $this->write($table, []);
	}

	/**
	 * Generate a unique ID
	 *
	 * Creates a unique identifier using PHP's uniqid function with
	 * additional entropy for enhanced uniqueness.
	 *
	 * @return string Unique identifier string
	 *
	 * Usage example:
	 * ```php
	 * $id = $this->generateId();
	 * // Returns something like: "507f1f77bcf86cd799439011.23456789"
	 * ```
	 */
	private function generateId(): string {
		return uniqid(more_entropy: true);
	}

	/**
	 * Perform cleanup based on table type
	 *
	 * Removes expired or outdated records based on table-specific rules.
	 * Different tables have different retention policies.
	 *
	 * @param string $table Table name to clean up
	 * @param array  $data  Current table data
	 * @return array Cleaned data with expired records removed
	 *
	 * Usage example:
	 * ```php
	 * $cleanedData = $this->performCleanup('csrf_tokens', $currentData);
	 * // Expired CSRF tokens are automatically removed
	 * ```
	 */
	private function performCleanup(string $table, array $data): array {
		$now = time();
		$cleaned = [];

		foreach ($data as $id => $record) {
			$shouldKeep = true;

			// Cleanup logic based on table type
			switch ($table) {
				case 'csrf_tokens':
					$expiration = $record['expires_at'] ?? 0;
					$shouldKeep = $expiration > $now;
					break;

				case 'rate_limits':
					$lastRequest = $record['last_request'] ?? 0;
					$maxAge = $this->cleanupInterval * 2; // Keep rate limit data for 2 cleanup intervals
					$shouldKeep = ($now - $lastRequest) < $maxAge;
					break;

				case 'spam_log':
					$createdAt = $record['created_at'] ?? 0;
					$maxAge = 86400 * 30; // Keep spam logs for 30 days
					$shouldKeep = ($now - $createdAt) < $maxAge;
					break;

				case 'security_tokens':
					$expiresAt = $record['expires_at'] ?? 0;
					$shouldKeep = $expiresAt > $now;
					break;

				default:
					// For unknown tables, keep everything
					$shouldKeep = true;
			}

			if ($shouldKeep) {
				$cleaned[$id] = $record;
			}
		}

		// If data was cleaned, write it back
		if (count($cleaned) !== count($data)) {
			$this->write($table, $cleaned);
		}

		return $cleaned;
	}

	/**
	 * Manually trigger cleanup for all tables
	 *
	 * Performs cleanup operations on all known table types to remove
	 * expired records and free up storage space.
	 *
	 * @return void
	 *
	 * Usage example:
	 * ```php
	 * $storage = new FileStorage();
	 * $storage->cleanup();
	 * echo "All tables cleaned up successfully";
	 * // Run this periodically via cron job
	 * ```
	 */
	public function cleanup(): void {
		$tables = ['csrf_tokens', 'rate_limits', 'spam_log', 'security_tokens'];

		foreach ($tables as $table) {
			$filePath = $this->getFilePath($table);
			if (file_exists($filePath)) {
				$data = $this->read($table);
				$this->performCleanup($table, $data);
			}
		}
	}

	/**
	 * Get storage statistics
	 *
	 * Returns comprehensive statistics about the storage system including
	 * table information, record counts, and file sizes.
	 *
	 * @return array Statistics array with storage directory, tables info, totals
	 *
	 * Usage example:
	 * ```php
	 * $storage = new FileStorage();
	 * $stats = $storage->getStats();
	 * echo "Storage directory: " . $stats['storage_directory'];
	 * echo "Total records: " . $stats['total_records'];
	 * echo "Total size: " . $stats['total_size'] . " bytes";
	 * foreach ($stats['tables'] as $table => $info) {
	 *     echo "Table {$table}: {$info['records']} records, {$info['size']} bytes";
	 * }
	 * ```
	 */
	public function getStats(): array {
		$stats = [
			'storage_directory' => $this->storageDirectory,
			'tables'            => [],
			'total_records'     => 0,
			'total_size'        => 0,
		];

		$files = glob($this->storageDirectory . '/*.json');
		foreach ($files as $file) {
			$table = basename($file, '.json');
			$size = filesize($file);
			$data = $this->read($table);
			$recordCount = count($data);

			$stats['tables'][$table] = [
				'records' => $recordCount,
				'size'    => $size,
				'file'    => $file,
			];

			$stats['total_records'] += $recordCount;
			$stats['total_size'] += $size;
		}

		return $stats;
	}
}