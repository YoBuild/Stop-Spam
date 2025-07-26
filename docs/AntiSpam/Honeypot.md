# Yohns\AntiSpam\Honeypot

Honeypot class for detecting automated bot submissions

Uses hidden form fields and timing analysis to catch spam bots.

Usage example:
```php
$honeypot = new Honeypot();
// In your form:
echo $honeypot->getCSS();
echo $honeypot->initialize('contact_form');
// In your form handler:
$result = $honeypot->validate($_POST, 'contact_form');
if (!$result['passed']) {
    die('Spam detected: ' . $result['reason']);
}
```





## Methods

| Name | Description |
|------|-------------|
|[__construct](#honeypot__construct)|Constructor - Initialize honeypot with configuration|
|[cleanup](#honeypotcleanup)|Clean up old honeypot sessions|
|[getCSS](#honeypotgetcss)|Get CSS to hide honeypot field|
|[getHiddenField](#honeypotgethiddenfield)|Get hidden field HTML|
|[getStats](#honeypotgetstats)|Get honeypot statistics|
|[initialize](#honeypotinitialize)|Initialize honeypot for a form|
|[isEnabled](#honeypotisenabled)|Check if honeypot is enabled|
|[validate](#honeypotvalidate)|Validate honeypot submission|




### Honeypot::__construct

**Description**

```php
public __construct (void)
```

Constructor - Initialize honeypot with configuration

Sets up the honeypot system with configuration from Config class.
Starts session if not already active.

**Parameters**

`This function has no parameters.`

**Return Values**

`void`


**Throws Exceptions**


`\Exception`
> If FileStorage initialization fails

Usage example:
```php
$honeypot = new Honeypot();
```

<hr />


### Honeypot::cleanup

**Description**

```php
public cleanup (void)
```

Clean up old honeypot sessions

Removes expired honeypot sessions from storage to prevent
database bloat and maintain performance.

**Parameters**

`This function has no parameters.`

**Return Values**

`int`

> Number of sessions cleaned up

Usage example:
```php
$honeypot = new Honeypot();
$cleaned = $honeypot->cleanup();
echo "Cleaned up {$cleaned} expired sessions";
```


<hr />


### Honeypot::getCSS

**Description**

```php
public getCSS (void)
```

Get CSS to hide honeypot field

Returns CSS styles to ensure honeypot field remains hidden
from legitimate users while remaining accessible to bots.

**Parameters**

`This function has no parameters.`

**Return Values**

`string`

> CSS style block for hiding honeypot field

Usage example:
```php
$honeypot = new Honeypot();
echo $honeypot->getCSS();
// Place this in your HTML <head> section
```


<hr />


### Honeypot::getHiddenField

**Description**

```php
public getHiddenField (void)
```

Get hidden field HTML

Returns the HTML input element for the honeypot field.
This field should be hidden from users but visible to bots.

**Parameters**

`This function has no parameters.`

**Return Values**

`string`

> HTML input element for honeypot field

Usage example:
```php
$honeypot = new Honeypot();
echo $honeypot->getHiddenField();
// Outputs: <input type="text" name="website" value="" style="display:none !important;...">
```


<hr />


### Honeypot::getStats

**Description**

```php
public getStats (void)
```

Get honeypot statistics

Returns comprehensive statistics about honeypot performance
including total attempts, detection types, and recent activity.

**Parameters**

`This function has no parameters.`

**Return Values**

`array`

> Statistics array with 'total_attempts', 'detection_types', 'recent_attempts'

Usage example:
```php
$honeypot = new Honeypot();
$stats = $honeypot->getStats();
echo "Total spam attempts: " . $stats['total_attempts'];
echo "Recent attempts (24h): " . $stats['recent_attempts'];
print_r($stats['detection_types']);
```


<hr />


### Honeypot::initialize

**Description**

```php
public initialize (string $formId)
```

Initialize honeypot for a form

Creates a honeypot session for the specified form and returns
the hidden field HTML to include in your form.

**Parameters**

* `(string) $formId`
: Unique identifier for the form (default: 'default')

**Return Values**

`string`

> HTML for hidden honeypot field

Usage example:
```php
$honeypot = new Honeypot();
echo $honeypot->initialize('contact_form');
// Outputs: <input type="text" name="website" value="" style="display:none !important;...">
```


<hr />


### Honeypot::isEnabled

**Description**

```php
public isEnabled (void)
```

Check if honeypot is enabled

Returns the current enabled status of the honeypot system
based on configuration settings.

**Parameters**

`This function has no parameters.`

**Return Values**

`bool`

> True if honeypot is enabled, false otherwise

Usage example:
```php
$honeypot = new Honeypot();
if ($honeypot->isEnabled()) {
    echo $honeypot->initialize('my_form');
} else {
    echo "Honeypot protection is disabled";
}
```


<hr />


### Honeypot::validate

**Description**

```php
public validate (array $postData, string $formId)
```

Validate honeypot submission

Performs comprehensive validation including honeypot field check,
timing analysis, and bot behavior detection.

**Parameters**

* `(array) $postData`
: Form submission data ($_POST)
* `(string) $formId`
: Form identifier used during initialization

**Return Values**

`array`

> Validation result with 'passed', 'reason', and 'details' keys

Usage example:
```php
$result = $honeypot->validate($_POST, 'contact_form');
if (!$result['passed']) {
    error_log('Spam detected: ' . $result['reason']);
    die('Form submission rejected');
}
echo "Form validated successfully!";
```


<hr />
