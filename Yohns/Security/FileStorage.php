<?php

namespace Yohns\Security;

use Yohns\Core\Config;
use InvalidArgumentException;
use RuntimeException;

/**
 * FileStorage class for managing JSON file-based data storage
 *
 * This class provides a simple JSON file storage system to replace MySQL
 * for security tokens, rate limits, and spam detection logs.
 */
class FileStorage {
	private string $storageDirectory;
	private int    $filePermissions;
	private int    $directoryPermissions;
	private bool   $autoCleanup;
	private int    $cleanupInterval;

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
	 */
	private function getFilePath(string $table): string {
		return $this->storageDirectory . '/' . $table . '.json';
	}

	/**
	 * Read data from a JSON file
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
	 */
	public function findOne(string $table, array $criteria): ?array {
		$results = $this->find($table, $criteria);
		return $results[0] ?? null;
	}

	/**
	 * Count records in a table
	 */
	public function count(string $table, array $criteria = []): int {
		return count($this->find($table, $criteria));
	}

	/**
	 * Clear all records from a table
	 */
	public function clear(string $table): bool {
		return $this->write($table, []);
	}

	/**
	 * Generate a unique ID
	 */
	private function generateId(): string {
		return uniqid(more_entropy: true);
	}

	/**
	 * Perform cleanup based on table type
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