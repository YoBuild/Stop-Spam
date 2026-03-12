# FileStorage

**Class:** `Yohns\Security\FileStorage`
**File:** `Yohns/Security/FileStorage.php`

JSON file-based persistence layer used by every component in the library. Each "table" is a single `.json` file in the storage directory. No database required.

## Config

All values come from the `storage` section of `config/security.php`:

| Key                     | Default                      | Description                                                 |
|-------------------------|------------------------------|-------------------------------------------------------------|
| `type`                  | `'json'`                     | Storage type identifier (currently only `json` supported).  |
| `directory`             | `__DIR__ . '/../database'`   | Absolute path to the storage directory.                     |
| `file_permissions`      | `0664`                       | Permissions set on JSON files after write (`chmod`).        |
| `directory_permissions` | `0755`                       | Permissions used when creating the storage directory.       |
| `auto_cleanup`          | `true`                       | Whether to auto-clean expired records during `read()`.      |
| `cleanup_interval`      | `3600`                       | Minimum seconds between automatic cleanups per table.       |

```php
// config/security.php
'storage' => [
	'type'                  => 'json',
	'directory'             => __DIR__ . '/../database',
	'file_permissions'      => 0664,
	'directory_permissions' => 0755,
	'auto_cleanup'          => true,
	'cleanup_interval'      => 3600,
],
```

## Basic CRUD

### Insert

```php
<?php
use Yohns\Security\FileStorage;

$storage = new FileStorage();

$id = $storage->insert('audit_log', [
	'action'  => 'login',
	'user_id' => 42,
	'ip'      => '203.0.113.50',
]);
// $id = '3f8a1b2c4d5e6f7a8b9c0d1e2f3a4b5c' (32-char hex string)
```

The stored record includes auto-generated fields:

```json
{
	"id": "3f8a1b2c4d5e6f7a8b9c0d1e2f3a4b5c",
	"action": "login",
	"user_id": 42,
	"ip": "203.0.113.50",
	"created_at": 1710100000,
	"updated_at": 1710100000
}
```

### Read All Records

```php
$records = $storage->read('audit_log');
// Returns associative array keyed by ID:
// [
//     '3f8a1b2c...' => ['id' => '3f8a1b2c...', 'action' => 'login', ...],
//     'b7c8d9e0...' => ['id' => 'b7c8d9e0...', 'action' => 'logout', ...],
// ]
```

### Update

```php
$success = $storage->update('audit_log', $id, [
	'resolved' => true,
	'notes'    => 'Reviewed by admin',
]);
// true if the record exists, false if not found
// 'updated_at' is automatically set to current time
```

### Delete

```php
$deleted = $storage->delete('audit_log', $id);
// true if deleted, false if the ID was not found
```

## Finding Records

### `find(string $table, array $criteria = []): array`

Returns all matching records as a re-indexed array. Uses exact matching on all criteria fields.

```php
// All login events from a specific IP
$logins = $storage->find('audit_log', [
	'action' => 'login',
	'ip'     => '203.0.113.50',
]);
// [
//     ['id' => '3f8a1b2c...', 'action' => 'login', 'ip' => '203.0.113.50', ...],
//     ['id' => 'e4f5a6b7...', 'action' => 'login', 'ip' => '203.0.113.50', ...],
// ]

// All records (no criteria)
$all = $storage->find('audit_log');
```

### `findOne(string $table, array $criteria): ?array`

Returns the first matching record, or `null`.

```php
$record = $storage->findOne('audit_log', ['user_id' => 42]);
// ['id' => '3f8a1b2c...', 'action' => 'login', 'user_id' => 42, ...] or null
```

### `count(string $table, array $criteria = []): int`

Returns the count of matching records.

```php
$totalLogins = $storage->count('audit_log', ['action' => 'login']);
// 15
$totalRecords = $storage->count('audit_log');
// 42
```

## Bulk Operations

### `write(string $table, array $data): bool`

Overwrites the entire table with the given data. Used internally by `insert()`, `update()`, and `delete()`. You can use it directly to replace all records at once.

```php
$storage->write('cache', [
	'key1' => ['value' => 'hello', 'expires_at' => time() + 300],
	'key2' => ['value' => 'world', 'expires_at' => time() + 300],
]);
```

### `clear(string $table): bool`

Removes all records from a table (writes an empty array).

```php
$storage->clear('temp_data');
// The file still exists but contains: {}
```

## Cleanup

### Automatic Cleanup

When `auto_cleanup` is `true`, `read()` checks whether enough time has passed since the last cleanup for that table (controlled by `cleanup_interval`). If so, it removes expired records based on table-specific rules:

| Table              | Retention Rule                                    |
|--------------------|---------------------------------------------------|
| `csrf_tokens`      | Removed when `expires_at` is in the past          |
| `rate_limits`      | Removed when `last_request` is older than 2x `cleanup_interval` |
| `spam_log`         | Removed when `created_at` is older than 30 days   |
| `security_tokens`  | Removed when `expires_at` is in the past          |
| Any other table    | Never auto-cleaned                                |

The cleanup interval is tracked per table in a static property. This means cleanup runs at most once per `cleanup_interval` seconds per table, not on every `read()`.

### Manual Cleanup

```php
$storage->cleanup();
// Runs cleanup on: csrf_tokens, rate_limits, spam_log, security_tokens
// Skips tables whose JSON files don't exist
```

## Storage Statistics

```php
$stats = $storage->getStats();
// [
//     'storage_directory' => '/var/www/app/database',
//     'tables' => [
//         'csrf_tokens' => [
//             'records' => 38,
//             'size'    => 12480,
//             'file'    => '/var/www/app/database/csrf_tokens.json',
//         ],
//         'rate_limits' => [
//             'records' => 156,
//             'size'    => 45200,
//             'file'    => '/var/www/app/database/rate_limits.json',
//         ],
//     ],
//     'total_records' => 194,
//     'total_size'    => 57680,
// ]
```

## Security Features

### Table Name Validation

Table names are validated against the regex `^[a-zA-Z0-9_-]+$`. This prevents path traversal attacks:

```php
// These work
$storage->read('csrf_tokens');
$storage->read('rate-limits');
$storage->read('my_table_2');

// These throw InvalidArgumentException
$storage->read('../etc/passwd');    // InvalidArgumentException
$storage->read('../../secrets');    // InvalidArgumentException
$storage->read('table name');      // InvalidArgumentException (spaces)
$storage->read('table.name');      // InvalidArgumentException (dots)
```

### Cryptographically Secure IDs

Record IDs are generated with `bin2hex(random_bytes(16))`, producing 32-character hex strings. This is cryptographically secure and unpredictable, unlike `uniqid()` which is based on the current timestamp and can be guessed.

### Atomic Writes

`write()` uses `file_put_contents()` with the `LOCK_EX` flag, which acquires an exclusive lock before writing. This prevents corruption when multiple PHP processes write to the same file simultaneously.

### File Permissions

After every write, `chmod()` is called with the configured `file_permissions` (default `0664`). This ensures new files don't inherit overly permissive umask settings.

## File Format

Each table is stored as `{table_name}.json` in the storage directory. The file contains a JSON object keyed by record ID:

```json
{
	"3f8a1b2c4d5e6f7a8b9c0d1e2f3a4b5c": {
		"id": "3f8a1b2c4d5e6f7a8b9c0d1e2f3a4b5c",
		"token": "abc123...",
		"context": "login_form",
		"expires_at": 1710101800,
		"created_at": 1710100000,
		"updated_at": 1710100000
	},
	"b7c8d9e0f1a2b3c4d5e6f7a8b9c0d1e2": {
		"id": "b7c8d9e0f1a2b3c4d5e6f7a8b9c0d1e2",
		"token": "def456...",
		"context": "settings_form",
		"expires_at": 1710101900,
		"created_at": 1710100100,
		"updated_at": 1710100100
	}
}
```

JSON is formatted with `JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES` for readability and to avoid double-escaping URLs.

## Gotchas

- **`read()` returns ID-keyed associative array, `find()` returns re-indexed numeric array.** Use `read()` when you need to look up by ID. Use `find()` when you need to search by field values.
- **`find()` uses exact matching only.** There is no support for greater-than, less-than, LIKE, or regex matching. For complex queries, use `read()` and filter the results yourself.
- **Constructor throws on bad directory.** If the storage directory cannot be created or is not writable, the constructor throws `RuntimeException`. This will crash any class that creates a `FileStorage` instance (which is all of them).
- **Cleanup interval is per-process.** The `$lastCleanup` tracker is a static property. In long-running processes (e.g., Swoole, ReactPHP), cleanup runs once per interval as expected. In traditional PHP-FPM, each request is a new process, so the static is reset -- but cleanup still won't run more than once per request per table.
- **No schema enforcement.** You can insert any array of data into any table. There is no validation that fields match a schema. If you insert a record missing `expires_at`, the cleanup logic will treat `$record['expires_at'] ?? 0` as epoch zero and immediately clean it up.
- **JSON file size.** All records in a table are loaded into memory on every `read()`. For tables with thousands of records, this can consume significant memory. The cleanup mechanism helps keep table sizes manageable.