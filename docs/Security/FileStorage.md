# Yohns\Security\FileStorage

FileStorage class for managing JSON file-based data storage

This class provides a simple JSON file storage system to replace MySQL
for security tokens, rate limits, and spam detection logs. Features
automatic cleanup, file locking, and configurable permissions.

Usage example:
```php
$storage = new FileStorage();
// Insert a record
$id = $storage->insert('users', ['name' => 'John', 'email' => 'john@example.com']);
// Find records

$users = $storage->find('users', ['name' => 'John']);
// Update a record
$storage->update('users', $id, ['email' => 'newemail@example.com']);
```



## Methods

| Name | Description |
|------|-------------|
|[__construct](#filestorage__construct)|Constructor - Initialize file storage with configuration|
|[cleanup](#filestoragecleanup)|Manually trigger cleanup for all tables|
|[clear](#filestorageclear)|Clear all records from a table|
|[count](#filestoragecount)|Count records in a table|
|[delete](#filestoragedelete)|Delete a record from a table|
|[find](#filestoragefind)|Find records in a table by criteria|
|[findOne](#filestoragefindone)|Find a single record in a table by criteria|
|[getStats](#filestoragegetstats)|Get storage statistics|
|[insert](#filestorageinsert)|Insert a record into a table|
|[read](#filestorageread)|Read data from a JSON file|
|[update](#filestorageupdate)|Update a record in a table|
|[write](#filestoragewrite)|Write data to a JSON file|




### FileStorage::__construct

**Description**

```php
public __construct (void)
```

Constructor - Initialize file storage with configuration

Sets up the file storage system with configuration from Config class.
Creates storage directory if it doesn't exist and validates permissions.

**Parameters**

`This function has no parameters.`

**Return Values**

`void`


**Throws Exceptions**


`\RuntimeException`
> If storage directory cannot be created or is not writable

Usage example:
```php
$storage = new FileStorage();
// Storage is now ready to use
```

<hr />


### FileStorage::cleanup

**Description**

```php
public cleanup (void)
```

Manually trigger cleanup for all tables

Performs cleanup operations on all known table types to remove
expired records and free up storage space.

**Parameters**

`This function has no parameters.`

**Return Values**

`void`

>

Usage example:
```php
$storage = new FileStorage();
$storage->cleanup();
echo "All tables cleaned up successfully";
// Run this periodically via cron job
```


<hr />


### FileStorage::clear

**Description**

```php
public clear (string $table)
```

Clear all records from a table

Removes all records from the specified table, effectively
resetting it to an empty state. This operation cannot be undone.

**Parameters**

* `(string) $table`
: Table name to clear

**Return Values**

`bool`

> True on success


**Throws Exceptions**


`\RuntimeException`
> If write operation fails

Usage example:
```php
$storage = new FileStorage();
if ($storage->clear('temp_data')) {
    echo "Temporary data cleared successfully";
}
// Warning: This will delete ALL records in the table
```

<hr />


### FileStorage::count

**Description**

```php
public count (string $table, array $criteria)
```

Count records in a table

Returns the number of records matching the specified criteria.
Counts all records if no criteria provided.

**Parameters**

* `(string) $table`
: Table name to count records in
* `(array) $criteria`
: Key-value pairs for filtering records

**Return Values**

`int`

> Number of matching records

Usage example:
```php
$storage = new FileStorage();
$totalUsers = $storage->count('users');
$activeUsers = $storage->count('users', ['status' => 'active']);
echo "Total users: {$totalUsers}, Active: {$activeUsers}";
```


<hr />


### FileStorage::delete

**Description**

```php
public delete (string $table, string $id)
```

Delete a record from a table

Removes the specified record from the table permanently.
This operation cannot be undone.

**Parameters**

* `(string) $table`
: Table name containing the record
* `(string) $id`
: ID of record to delete

**Return Values**

`bool`

> True if record was deleted, false if record not found


**Throws Exceptions**


`\RuntimeException`
> If write operation fails

Usage example:
```php
$storage = new FileStorage();
if ($storage->delete('users', $userId)) {
    echo "User deleted successfully";
} else {
    echo "User not found";
}
```

<hr />


### FileStorage::find

**Description**

```php
public find (string $table, array $criteria)
```

Find records in a table by criteria

Searches for records matching the specified criteria using exact matching.
Returns all records if no criteria provided.

**Parameters**

* `(string) $table`
: Table name to search in
* `(array) $criteria`
: Key-value pairs for filtering records

**Return Values**

`array`

> Array of matching records (re-indexed)

Usage example:
```php
$storage = new FileStorage();
// Find all active users
$activeUsers = $storage->find('users', ['status' => 'active']);
// Find all records
$allUsers = $storage->find('users');
foreach ($activeUsers as $user) {
    echo "Active user: " . $user['name'] . "\n";
}
```


<hr />


### FileStorage::findOne

**Description**

```php
public findOne (string $table, array $criteria)
```

Find a single record in a table by criteria

Returns the first record matching the specified criteria,
or null if no matching record is found.

**Parameters**

* `(string) $table`
: Table name to search in
* `(array) $criteria`
: Key-value pairs for filtering records

**Return Values**

`array|null`

> First matching record or null if not found

Usage example:
```php
$storage = new FileStorage();
$user = $storage->findOne('users', ['email' => 'john@example.com']);
if ($user) {
    echo "Found user: " . $user['name'];
} else {
    echo "User not found";
}
```


<hr />


### FileStorage::getStats

**Description**

```php
public getStats (void)
```

Get storage statistics

Returns comprehensive statistics about the storage system including
table information, record counts, and file sizes.

**Parameters**

`This function has no parameters.`

**Return Values**

`array`

> Statistics array with storage directory, tables info, totals

Usage example:
```php
$storage = new FileStorage();
$stats = $storage->getStats();
echo "Storage directory: " . $stats['storage_directory'];
echo "Total records: " . $stats['total_records'];
echo "Total size: " . $stats['total_size'] . " bytes";
foreach ($stats['tables'] as $table => $info) {
    echo "Table {$table}: {$info['records']} records, {$info['size']} bytes";
}
```


<hr />


### FileStorage::insert

**Description**

```php
public insert (string $table, array $record)
```

Insert a record into a table

Adds a new record to the specified table with auto-generated ID
and timestamps. Returns the generated ID for future reference.

**Parameters**

* `(string) $table`
: Table name to insert into
* `(array) $record`
: Record data to insert

**Return Values**

`string`

> Generated unique ID for the inserted record


**Throws Exceptions**


`\RuntimeException`
> If write operation fails

Usage example:
```php
$storage = new FileStorage();
$id = $storage->insert('users', [
    'name' => 'John Doe',
    'email' => 'john@example.com',
    'role' => 'admin'
]);
echo "User created with ID: " . $id;
```

<hr />


### FileStorage::read

**Description**

```php
public read (string $table)
```

Read data from a JSON file

Loads and parses JSON data from the specified table file.
Performs automatic cleanup if enabled and validates JSON format.

**Parameters**

* `(string) $table`
: Table name to read data from

**Return Values**

`array`

> Array of records from the table


**Throws Exceptions**


`\RuntimeException`
> If file cannot be read or contains invalid JSON

Usage example:
```php
$storage = new FileStorage();
$users = $storage->read('users');
foreach ($users as $id => $user) {
    echo "User: " . $user['name'] . "\n";
}
```

<hr />


### FileStorage::update

**Description**

```php
public update (string $table, string $id, array $updates)
```

Update a record in a table

Updates an existing record by merging new data with existing record.
Automatically updates the 'updated_at' timestamp.

**Parameters**

* `(string) $table`
: Table name containing the record
* `(string) $id`
: ID of record to update
* `(array) $updates`
: Array of fields to update

**Return Values**

`bool`

> True if record was updated, false if record not found


**Throws Exceptions**


`\RuntimeException`
> If write operation fails

Usage example:
```php
$storage = new FileStorage();
$success = $storage->update('users', $userId, [
    'email' => 'newemail@example.com',
    'last_login' => time()
]);
if ($success) {
    echo "User updated successfully";
}
```

<hr />


### FileStorage::write

**Description**

```php
public write (string $table, array $data)
```

Write data to a JSON file

Saves data array to the specified table file as formatted JSON.
Uses file locking to prevent corruption and sets proper permissions.

**Parameters**

* `(string) $table`
: Table name to write data to
* `(array) $data`
: Data array to save

**Return Values**

`bool`

> True on success


**Throws Exceptions**


`\RuntimeException`
> If JSON encoding fails or file cannot be written

Usage example:
```php
$storage = new FileStorage();
$data = ['user1' => ['name' => 'John'], 'user2' => ['name' => 'Jane']];
$storage->write('users', $data);
echo "Data saved successfully";
```

<hr />
