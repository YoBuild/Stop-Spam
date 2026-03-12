# Yohns\Core\Config  

Config class for managing application configurations.

Examples:
```php
// Initialize Config with a specific directory
$config = new Yohns\Core\Config(__DIR__.'/../config');
// Get a configuration value
$dbHost = Yohns\Core\Config::get('db_host', 'database');
// Set a custom configuration value
Yohns\Core\Config::set('api_key', '12345');
// Retrieve a custom configuration value
$apiKey = Yohns\Core\Config::getCustom('api_key');
// Reload configurations from a different directory
Yohns\Core\Config::reload('/new/path/to/config');
```  





## Methods

| Name | Description |
|------|-------------|
|[__construct](#config__construct)|Config constructor.|
|[get](#configget)|Retrieves a configuration value.|
|[getAll](#configgetall)|Retrieve all configuration values for file.|
|[getCustom](#configgetcustom)|Retrieves a custom configuration value.|
|[reload](#configreload)|Reloads configurations from a specified directory.|
|[set](#configset)|Sets a configuration value.|




### Config::__construct  

**Description**

```php
public __construct (string $directory, string $default)
```

Config constructor. 

 

**Parameters**

* `(string) $directory`
: Path to the directory containing configuration files.  
* `(string) $default`
: the default configuration file name (without extension).  

**Return Values**

`void`


**Throws Exceptions**


`\InvalidArgumentException`
> if the directory does not exist or is not readable.

<hr />


### Config::get  

**Description**

```php
public static get (string $key, string $configFile)
```

Retrieves a configuration value. 

 

**Parameters**

* `(string) $key`
: The key of the configuration to retrieve.  
* `(string) $configFile`
: The configuration file identifier.  

**Return Values**

`mixed`

> The value of the configuration, or null if not found.


<hr />


### Config::getAll  

**Description**

```php
public static getAll (string $configFile)
```

Retrieve all configuration values for file. 

 

**Parameters**

* `(string) $configFile`
: The configuration file identifier.  

**Return Values**

`mixed`

> The value of the configuration, or null if not found.


<hr />


### Config::getCustom  

**Description**

```php
public static getCustom (string $key)
```

Retrieves a custom configuration value. 

 

**Parameters**

* `(string) $key`
: The key of the custom configuration to retrieve.  

**Return Values**

`mixed`

> The value of the custom configuration, or null if not found.


<hr />


### Config::reload  

**Description**

```php
public static reload (string $directory)
```

Reloads configurations from a specified directory. 

 

**Parameters**

* `(string) $directory`
: Directory path to reload configuration files from.  

**Return Values**

`void`


<hr />


### Config::set  

**Description**

```php
public static set (string $key, mixed $value, string $configFile)
```

Sets a configuration value. 

 

**Parameters**

* `(string) $key`
: The key of the configuration to set.  
* `(mixed) $value`
: The value to assign to the configuration.  
* `(string) $configFile`
: The configuration file identifier.  

**Return Values**

`void`


<hr />

