# Yohns\Security\RateLimiter

RateLimiter class for preventing abuse through rate limiting

Implements progressive timeouts and tracks requests by IP and action type.

Usage example:
```php
$limiter = new RateLimiter();
$ip = $_SERVER['REMOTE_ADDR'];
if ($limiter->isLimited($ip, 'login')) {
    die('Too many login attempts. Please try again later.');
}
// ...process login...
$limiter->recordAttempt($ip, 'login', $loginSuccess);
```





## Methods

| Name | Description |
|------|-------------|
|[__construct](#ratelimiter__construct)||
|[blockIdentifier](#ratelimiterblockidentifier)|Manually block a user/IP for a given duration.|
|[cleanup](#ratelimitercleanup)|Clean up old rate limit records.|
|[getBlockTimeRemaining](#ratelimitergetblocktimeremaining)|Get block time remaining for identifier.|
|[getRemainingRequests](#ratelimitergetremainingrequests)|Get remaining requests for identifier in the current window.|
|[getStats](#ratelimitergetstats)|Get rate limiting statistics.|
|[isBlocked](#ratelimiterisblocked)|Check if user/IP is currently blocked.|
|[isEnabled](#ratelimiterisenabled)|Check if rate limiting is enabled.|
|[isLimited](#ratelimiterislimited)|Check if a request should be rate limited.|
|[recordAttempt](#ratelimiterrecordattempt)|Record an authentication attempt (success or failure).|
|[resetIdentifier](#ratelimiterresetidentifier)|Reset all rate limits for an identifier.|
|[unblockIdentifier](#ratelimiterunblockidentifier)|Unblock a user/IP.|




### RateLimiter::__construct

**Description**

```php
 __construct (void)
```





**Parameters**

`This function has no parameters.`

**Return Values**

`void`


<hr />


### RateLimiter::blockIdentifier

**Description**

```php
public blockIdentifier (string $identifier, string $actionType, int|null $duration)
```

Manually block a user/IP for a given duration.



**Parameters**

* `(string) $identifier`
: The identifier (user or IP).
* `(string) $actionType`
: The action type.
* `(int|null) $duration`
: Duration in seconds (optional).

Example:
```php
$limiter->blockIdentifier('ip_1.2.3.4', 'login', 3600);
```

**Return Values**

`void`


<hr />


### RateLimiter::cleanup

**Description**

```php
public cleanup (void)
```

Clean up old rate limit records.



**Parameters**

`This function has no parameters.`

**Return Values**

`int`

> Number of records deleted.

Example:
```php
$deleted = $limiter->cleanup();
```


<hr />


### RateLimiter::getBlockTimeRemaining

**Description**

```php
public getBlockTimeRemaining (string $identifier, string $actionType)
```

Get block time remaining for identifier.



**Parameters**

* `(string) $identifier`
: The identifier (user or IP).
* `(string) $actionType`
: The action type.

**Return Values**

`int`

> Seconds remaining in block, or 0 if not blocked.

Example:
```php
$seconds = $limiter->getBlockTimeRemaining('ip_1.2.3.4', 'login');
```


<hr />


### RateLimiter::getRemainingRequests

**Description**

```php
public getRemainingRequests (string $identifier, string $actionType)
```

Get remaining requests for identifier in the current window.



**Parameters**

* `(string) $identifier`
: The identifier (user or IP).
* `(string) $actionType`
: The action type.

**Return Values**

`int`

> Number of remaining requests.

Example:
```php
$remaining = $limiter->getRemainingRequests('ip_1.2.3.4', 'post');
```


<hr />


### RateLimiter::getStats

**Description**

```php
public getStats (void)
```

Get rate limiting statistics.



**Parameters**

`This function has no parameters.`

**Return Values**

`array`

> Statistics including total records, violations, etc.

Example:
```php
$stats = $limiter->getStats();
```


<hr />


### RateLimiter::isBlocked

**Description**

```php
public isBlocked (string $identifier, string $actionType)
```

Check if user/IP is currently blocked.



**Parameters**

* `(string) $identifier`
: The identifier (user or IP).
* `(string) $actionType`
: The action type.

**Return Values**

`bool`

> True if blocked, false otherwise.


<hr />


### RateLimiter::isEnabled

**Description**

```php
public isEnabled (void)
```

Check if rate limiting is enabled.



**Parameters**

`This function has no parameters.`

**Return Values**

`bool`

> True if enabled, false otherwise.

Example:
```php
if ($limiter->isEnabled()) { ... }
```


<hr />


### RateLimiter::isLimited

**Description**

```php
public isLimited (string $ipAddress, string $actionType, int|null $userId)
```

Check if a request should be rate limited.



**Parameters**

* `(string) $ipAddress`
: The IP address of the requester.
* `(string) $actionType`
: The action type (e.g., 'login', 'post').
* `(int|null) $userId`
: Optional user ID for user-based limiting.

**Return Values**

`bool`

> True if the request is rate limited, false otherwise.

Example:
```php
if ($limiter->isLimited($ip, 'post')) {
    // Block the request
}
```


<hr />


### RateLimiter::recordAttempt

**Description**

```php
public recordAttempt (string $ipAddress, string $actionType, bool $success, int|null $userId)
```

Record an authentication attempt (success or failure).



**Parameters**

* `(string) $ipAddress`
: The IP address of the requester.
* `(string) $actionType`
: The action type (e.g., 'login').
* `(bool) $success`
: Whether the attempt was successful.
* `(int|null) $userId`
: Optional user ID.

Example:
```php
$limiter->recordAttempt($ip, 'login', false, $userId);
```

**Return Values**

`void`


<hr />


### RateLimiter::resetIdentifier

**Description**

```php
public resetIdentifier (string $identifier)
```

Reset all rate limits for an identifier.



**Parameters**

* `(string) $identifier`
: The identifier (user or IP).

**Return Values**

`int`

> Number of records deleted.

Example:
```php
$limiter->resetIdentifier('user_123');
```


<hr />


### RateLimiter::unblockIdentifier

**Description**

```php
public unblockIdentifier (string $identifier, string $actionType)
```

Unblock a user/IP.



**Parameters**

* `(string) $identifier`
: The identifier (user or IP).
* `(string) $actionType`
: The action type.

**Return Values**

`bool`

> True if unblocked, false if not found.

Example:
```php
$limiter->unblockIdentifier('user_123', 'login');
```


<hr />
