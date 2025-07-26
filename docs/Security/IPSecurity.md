# Yohns\Security\IPSecurity

IPSecurity class for IP-based security management

Handles IP whitelisting, blacklisting, geolocation, and reputation tracking.
Provides comprehensive IP analysis including proxy detection, threat assessment,
and automated security responses.

Usage example:
```php
$ipSec = new IPSecurity();
$analysis = $ipSec->analyzeIP('192.168.1.100');
if ($analysis['is_blocked']) {
    die('Access denied from your IP address');
}

// Add suspicious IP to blacklist
$ipSec->addToBlacklist('192.168.1.100', 'Suspicious activity', 3600);
```



## Methods

| Name | Description |
|------|-------------|
|[__construct](#ipsecurity__construct)|Constructor - Initialize IP security system with configuration|
|[addToBlacklist](#ipsecurityaddtoblacklist)|Add IP to blacklist|
|[addToWhitelist](#ipsecurityaddtowhitelist)|Add IP to whitelist|
|[analyzeIP](#ipsecurityanalyzeip)|Analyze IP address for security threats|
|[bulkBlacklist](#ipsecuritybulkblacklist)|Bulk import IPs to blacklist|
|[exportIPLists](#ipsecurityexportiplists)|Export IP lists for backup|
|[getClientIP](#ipsecuritygetclientip)|Get the real client IP address|
|[getSecurityStats](#ipsecuritygetsecuritystats)|Get IP security statistics|
|[importIPLists](#ipsecurityimportiplists)|Import IP lists from backup|
|[isBlacklisted](#ipsecurityisblacklisted)|Check if IP is blacklisted|
|[isEnabled](#ipsecurityisenabled)|Check if IP security is enabled|
|[isWhitelisted](#ipsecurityiswhitelisted)|Check if IP is whitelisted|
|[performMaintenance](#ipsecurityperformmaintenance)|Perform maintenance on IP security data|
|[removeFromBlacklist](#ipsecurityremovefromblacklist)|Remove IP from blacklist|
|[removeFromWhitelist](#ipsecurityremovefromwhitelist)|Remove IP from whitelist|
|[updateReputation](#ipsecurityupdatereputation)|Update IP reputation based on behavior|




### IPSecurity::__construct

**Description**

```php
public __construct (void)
```

Constructor - Initialize IP security system with configuration

Sets up IP security with configuration from Config class and loads
whitelist, blacklist, and trusted proxy data from storage.

**Parameters**

`This function has no parameters.`

**Return Values**

`void`


**Throws Exceptions**


`\Exception`
> If FileStorage initialization fails

Usage example:
```php
$ipSec = new IPSecurity();
// IP security system is now ready for analysis
```

<hr />


### IPSecurity::addToBlacklist

**Description**

```php
public addToBlacklist (string $ip, string $reason, int $duration)
```

Add IP to blacklist

Adds an IP address or CIDR range to the blacklist with optional
expiration time and logs the security event.

**Parameters**

* `(string) $ip`
: IP address or CIDR range to blacklist
* `(string) $reason`
: Reason for blacklisting (optional)
* `(int) $duration`
: Duration in seconds (0 = permanent)

**Return Values**

`bool`

> True on success

Usage example:
```php
$ipSec = new IPSecurity();
// Temporary block for 1 hour
$ipSec->addToBlacklist('203.0.113.50', 'Brute force attempt', 3600);
// Permanent block
$ipSec->addToBlacklist('198.51.100.25', 'Known malicious IP', 0);
```


<hr />


### IPSecurity::addToWhitelist

**Description**

```php
public addToWhitelist (string $ip, string $reason, int $duration)
```

Add IP to whitelist

Adds an IP address or CIDR range to the whitelist with optional
expiration time and reason for tracking purposes.

**Parameters**

* `(string) $ip`
: IP address or CIDR range to whitelist
* `(string) $reason`
: Reason for whitelisting (optional)
* `(int) $duration`
: Duration in seconds (0 = permanent)

**Return Values**

`bool`

> True on success

Usage example:
```php
$ipSec = new IPSecurity();
$ipSec->addToWhitelist('192.168.1.0/24', 'Office network', 0);
$ipSec->addToWhitelist('203.0.113.10', 'Trusted partner', 86400);
echo "IPs added to whitelist";
```


<hr />


### IPSecurity::analyzeIP

**Description**

```php
public analyzeIP (string|null $ipAddress)
```

Analyze IP address for security threats

Performs comprehensive security analysis including whitelist/blacklist checks,
proxy detection, reputation analysis, and geolocation assessment.
Returns detailed threat analysis with trust score and recommendations.

**Parameters**

* `(string|null) $ipAddress`
: IP address to analyze (null uses client IP)

**Return Values**

`array`

> Complete security analysis with trust score, threats, and recommendations

Usage example:
```php
$ipSec = new IPSecurity();
$analysis = $ipSec->analyzeIP('203.0.113.10');

echo "Trust Score: " . $analysis['trust_score'];
if ($analysis['is_blocked']) {
    echo "IP is blocked!";
}
foreach ($analysis['threats'] as $threat) {
    echo "Threat: " . $threat['description'] . " (Severity: " . $threat['severity'] . ")";
}
```


<hr />


### IPSecurity::bulkBlacklist

**Description**

```php
public bulkBlacklist (array $ips, string $reason)
```

Bulk import IPs to blacklist

Adds multiple IP addresses to the blacklist in a single operation
with validation and error handling.

**Parameters**

* `(array) $ips`
: Array of IP addresses to blacklist
* `(string) $reason`
: Reason for bulk blacklisting

**Return Values**

`int`

> Number of IPs successfully added to blacklist

Usage example:
```php
$ipSec = new IPSecurity();
$maliciousIPs = ['203.0.113.10', '198.51.100.25', '192.0.2.50'];
$added = $ipSec->bulkBlacklist($maliciousIPs, 'Threat intelligence feed');
echo "Added {$added} IPs to blacklist";
```


<hr />


### IPSecurity::exportIPLists

**Description**

```php
public exportIPLists (void)
```

Export IP lists for backup

Creates a comprehensive backup of all IP security data
including whitelist, blacklist, and reputation information.

**Parameters**

`This function has no parameters.`

**Return Values**

`array`

> Complete export of IP security data

Usage example:
```php
$ipSec = new IPSecurity();
$backup = $ipSec->exportIPLists();
file_put_contents('ip_security_backup.json', json_encode($backup));
echo "IP security data exported successfully";
```


<hr />


### IPSecurity::getClientIP

**Description**

```php
public getClientIP (void)
```

Get the real client IP address

Determines the actual client IP address by checking various headers
in order of priority, handling proxy scenarios and validating IPs.

**Parameters**

`This function has no parameters.`

**Return Values**

`string`

> Client IP address or '0.0.0.0' if unable to determine

Usage example:
```php
$ipSec = new IPSecurity();
$clientIP = $ipSec->getClientIP();
echo "Client IP: " . $clientIP;
// Handles Cloudflare, proxies, load balancers automatically
```


<hr />


### IPSecurity::getSecurityStats

**Description**

```php
public getSecurityStats (void)
```

Get IP security statistics

Returns comprehensive statistics about the IP security system
including counts, averages, and top violators.

**Parameters**

`This function has no parameters.`

**Return Values**

`array`

> Security statistics with counts, reputation data, and violators

Usage example:
```php
$ipSec = new IPSecurity();
$stats = $ipSec->getSecurityStats();
echo "Blacklisted IPs: " . $stats['blacklist_count'];
echo "Average reputation: " . $stats['avg_reputation_score'];
echo "Recent events: " . $stats['recent_events'];
foreach ($stats['top_violators'] as $violator) {
    echo "IP: " . $violator['ip'] . " (Violations: " . $violator['violations'] . ")";
}
```


<hr />


### IPSecurity::importIPLists

**Description**

```php
public importIPLists (array $data)
```

Import IP lists from backup

Restores IP security data from a backup file including
whitelist, blacklist, and reputation information.

**Parameters**

* `(array) $data`
: Backup data to import

**Return Values**

`array`

> Summary of import operations performed

Usage example:
```php
$ipSec = new IPSecurity();
$backupData = json_decode(file_get_contents('backup.json'), true);
$results = $ipSec->importIPLists($backupData);
echo "Whitelist entries imported: " . $results['whitelist_imported'];
echo "Blacklist entries imported: " . $results['blacklist_imported'];
```


<hr />


### IPSecurity::isBlacklisted

**Description**

```php
public isBlacklisted (string $ip)
```

Check if IP is blacklisted

Verifies if the given IP address matches any entry in the blacklist
and checks for expiration of temporary blacklist entries.

**Parameters**

* `(string) $ip`
: IP address to check

**Return Values**

`bool`

> True if IP is blacklisted, false otherwise

Usage example:
```php
$ipSec = new IPSecurity();
if ($ipSec->isBlacklisted('203.0.113.50')) {
    http_response_code(403);
    die('Access denied');
}
```


<hr />


### IPSecurity::isEnabled

**Description**

```php
public isEnabled (void)
```

Check if IP security is enabled

Returns the current enabled status of the IP security system
based on configuration settings.

**Parameters**

`This function has no parameters.`

**Return Values**

`bool`

> True if IP security is enabled, false otherwise

Usage example:
```php
$ipSec = new IPSecurity();
if ($ipSec->isEnabled()) {
    $analysis = $ipSec->analyzeIP();
    // Process security analysis
} else {
    echo "IP security is disabled";
}
```


<hr />


### IPSecurity::isWhitelisted

**Description**

```php
public isWhitelisted (string $ip)
```

Check if IP is whitelisted

Verifies if the given IP address matches any entry in the whitelist,
including CIDR ranges and individual IPs.

**Parameters**

* `(string) $ip`
: IP address to check

**Return Values**

`bool`

> True if IP is whitelisted, false otherwise

Usage example:
```php
$ipSec = new IPSecurity();
if ($ipSec->isWhitelisted('192.168.1.100')) {
    echo "IP is trusted - bypassing security checks";
}
```


<hr />


### IPSecurity::performMaintenance

**Description**

```php
public performMaintenance (void)
```

Perform maintenance on IP security data

Cleans up expired entries, old data, and refreshes caches
to maintain optimal performance and data accuracy.

**Parameters**

`This function has no parameters.`

**Return Values**

`array`

> Summary of maintenance operations performed

Usage example:
```php
$ipSec = new IPSecurity();
$results = $ipSec->performMaintenance();
echo "Expired blacklist entries removed: " . $results['expired_blacklist'];
echo "Old reputation records cleaned: " . $results['old_reputation'];
// Run this periodically via cron job
```


<hr />


### IPSecurity::removeFromBlacklist

**Description**

```php
public removeFromBlacklist (string $ip)
```

Remove IP from blacklist

Removes all blacklist entries matching the specified IP address
and refreshes the internal blacklist cache.

**Parameters**

* `(string) $ip`
: IP address to remove from blacklist

**Return Values**

`bool`

> True if entries were removed, false if not found

Usage example:
```php
$ipSec = new IPSecurity();
if ($ipSec->removeFromBlacklist('203.0.113.50')) {
    echo "IP removed from blacklist - access restored";
}
```


<hr />


### IPSecurity::removeFromWhitelist

**Description**

```php
public removeFromWhitelist (string $ip)
```

Remove IP from whitelist

Removes all whitelist entries matching the specified IP address
and refreshes the internal whitelist cache.

**Parameters**

* `(string) $ip`
: IP address to remove from whitelist

**Return Values**

`bool`

> True if entries were removed, false if not found

Usage example:
```php
$ipSec = new IPSecurity();
if ($ipSec->removeFromWhitelist('192.168.1.100')) {
    echo "IP removed from whitelist";
} else {
    echo "IP not found in whitelist";
}
```


<hr />


### IPSecurity::updateReputation

**Description**

```php
public updateReputation (string $ip, string $action, float $scoreChange)
```

Update IP reputation based on behavior

Modifies an IP's reputation score based on observed behavior.
Positive actions increase score, negative actions decrease it.

**Parameters**

* `(string) $ip`
: IP address to update reputation for
* `(string) $action`
: Action type that triggered the update
* `(float) $scoreChange`
: Change in reputation score (-1.0 to 1.0)

**Return Values**

`void`

>

Usage example:
```php
$ipSec = new IPSecurity();
// Decrease reputation for failed login
$ipSec->updateReputation('203.0.113.10', 'failed_login', -0.1);
// Increase reputation for successful verification
$ipSec->updateReputation('192.168.1.100', 'successful_auth', 0.05);
```


<hr />
