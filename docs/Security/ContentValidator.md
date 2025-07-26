# Yohns\Security\ContentValidator

ContentValidator class for sanitizing and validating user input

Provides XSS protection, input sanitization, and content validation.
Supports HTML filtering, email validation, URL validation, and comprehensive
security threat detection with configurable rules and patterns.

Usage example:
```php
$validator = new ContentValidator();
$result = $validator->validate($userInput, ['allow_html' => false]);
if ($result['is_valid']) {
    echo "Safe content: " . $result['sanitized_content'];
} else {
    echo "Validation errors: " . implode(', ', $result['errors']);
}
```



## Methods

| Name | Description |
|------|-------------|
|[__construct](#contentvalidator__construct)|Constructor - Initialize content validator with configuration|
|[addValidationRule](#contentvalidatoraddvalidationrule)|Add custom validation rule|
|[detectXSS](#contentvalidatordetectxss)|Detect XSS attempts in content|
|[getValidationStats](#contentvalidatorgetvalidationstats)|Get validation statistics|
|[isEnabled](#contentvalidatorisenabled)|Check if content validator is enabled|
|[sanitizeHTML](#contentvalidatorsanitizehtml)|Sanitize HTML content|
|[validate](#contentvalidatorvalidate)|Validate and sanitize content|
|[validateEmail](#contentvalidatorvalidateemail)|Validate specific input types|
|[validateFilename](#contentvalidatorvalidatefilename)|Validate and sanitize filename|
|[validatePhone](#contentvalidatorvalidatephone)|Validate phone number|
|[validateURL](#contentvalidatorvalidateurl)|Validate URL|




### ContentValidator::__construct

**Description**

```php
public __construct (void)
```

Constructor - Initialize content validator with configuration

Sets up content validation system with configuration from Config class
and loads allowed tags, attributes, and XSS patterns from storage.

**Parameters**

`This function has no parameters.`

**Return Values**

`void`


**Throws Exceptions**


`\Exception`
> If FileStorage initialization fails

Usage example:
```php
$validator = new ContentValidator();
// Content validator is now ready for use
```

<hr />


### ContentValidator::addValidationRule

**Description**

```php
public addValidationRule (string $name, callable $validator)
```

Add custom validation rule

Registers a custom validation rule with a callable validator function
for application-specific validation requirements.

**Parameters**

* `(string) $name`
: Name of the validation rule
* `(callable) $validator`
: Validation function to execute

**Return Values**

`void`

>

Usage example:
```php
$validator = new ContentValidator();
$validator->addValidationRule('custom_format', function($content) {
    return preg_match('/^[A-Z]{3}-\d{4}$/', $content);
});
// Custom validation rule is now registered
```


<hr />


### ContentValidator::detectXSS

**Description**

```php
public detectXSS (string $content)
```

Detect XSS attempts in content

Analyzes content for known XSS attack patterns and malicious code.
Returns threat analysis and sanitized content with dangerous elements removed.

**Parameters**

* `(string) $content`
: Content to analyze for XSS threats

**Return Values**

`array`

> XSS analysis with safety status, threats found, and sanitized content

Usage example:
```php
$validator = new ContentValidator();
$xssCheck = $validator->detectXSS('<script>alert("XSS")</script>Hello World');

if (!$xssCheck['is_safe']) {
    echo "XSS threats detected:\n";
    foreach ($xssCheck['threats'] as $threat) {
        echo "- " . $threat['description'] . " (Severity: " . $threat['severity'] . ")\n";
    }
    echo "Sanitized: " . $xssCheck['sanitized_content'];
}
```


<hr />


### ContentValidator::getValidationStats

**Description**

```php
public getValidationStats (void)
```

Get validation statistics

Returns comprehensive statistics about content validation including
security issues found, severity breakdown, and common attack patterns.

**Parameters**

`This function has no parameters.`

**Return Values**

`array`

> Validation statistics with counts, breakdowns, and trends

Usage example:
```php
$validator = new ContentValidator();
$stats = $validator->getValidationStats();

echo "Total validations: " . $stats['total_validations'];
echo "Security issues found: " . $stats['security_issues_found'];
echo "Recent validations (24h): " . $stats['recent_validations'];

foreach ($stats['severity_breakdown'] as $severity => $count) {
    echo "Severity {$severity}: {$count} issues\n";
}

foreach ($stats['common_issues'] as $issue => $count) {
    echo "Issue {$issue}: {$count} occurrences\n";
}
```


<hr />


### ContentValidator::isEnabled

**Description**

```php
public isEnabled (void)
```

Check if content validator is enabled

Returns the current enabled status of the content validation system
based on configuration settings.

**Parameters**

`This function has no parameters.`

**Return Values**

`bool`

> True if content validator is enabled, false otherwise

Usage example:
```php
$validator = new ContentValidator();
if ($validator->isEnabled()) {
    $result = $validator->validate($userInput);
    // Process validation results
} else {
    echo "Content validation is disabled";
}
```


<hr />


### ContentValidator::sanitizeHTML

**Description**

```php
public sanitizeHTML (string $content)
```

Sanitize HTML content

Performs comprehensive HTML sanitization by removing disallowed tags
and attributes while preserving safe content structure.

**Parameters**

* `(string) $content`
: HTML content to sanitize

**Return Values**

`array`

> Sanitization result with cleaned content, changes, and warnings

Usage example:
```php
$validator = new ContentValidator();
$htmlResult = $validator->sanitizeHTML('<p>Safe content</p><script>alert("xss")</script>');

echo "Sanitized HTML: " . $htmlResult['content']; // <p>Safe content</p>

foreach ($htmlResult['changes'] as $change) {
    echo "Change made: " . $change . "\n";
}

foreach ($htmlResult['warnings'] as $warning) {
    echo "Warning: " . $warning . "\n";
}
```


<hr />


### ContentValidator::validate

**Description**

```php
public validate (string $content, array $options)
```

Validate and sanitize content

Performs comprehensive content validation including XSS detection,
HTML sanitization, length checking, and whitespace normalization.
Returns detailed results with sanitized content and security analysis.

**Parameters**

* `(string) $content`
: Content to validate and sanitize
* `(array) $options`
: Validation options to override defaults

**Return Values**

`array`

> Validation result with sanitized content, errors, warnings, and security issues

Usage example:
```php
$validator = new ContentValidator();
$result = $validator->validate($userInput, [
    'allow_html' => true,
    'max_length' => 5000,
    'check_xss' => true
]);

if ($result['is_valid']) {
    $safeContent = $result['sanitized_content'];
    if (!empty($result['security_issues'])) {
        error_log('Security threats detected: ' . json_encode($result['security_issues']));
    }
} else {
    foreach ($result['errors'] as $error) {
        echo "Error: " . $error . "\n";
    }
}
```


<hr />


### ContentValidator::validateEmail

**Description**

```php
public validateEmail (string $email)
```

Validate specific input types

Validates and sanitizes email addresses using comprehensive checks
including format validation, length limits, and normalization.

**Parameters**

* `(string) $email`
: Email address to validate

**Return Values**

`array`

> Validation result with sanitized email and error messages

Usage example:
```php
$validator = new ContentValidator();
$emailResult = $validator->validateEmail('  USER@EXAMPLE.COM  ');

if ($emailResult['is_valid']) {
    echo "Valid email: " . $emailResult['sanitized_email']; // user@example.com
} else {
    foreach ($emailResult['errors'] as $error) {
        echo "Email error: " . $error . "\n";
    }
}
```


<hr />


### ContentValidator::validateFilename

**Description**

```php
public validateFilename (string $filename)
```

Validate and sanitize filename

Sanitizes filenames by removing dangerous characters, preventing
directory traversal, and checking for malicious file extensions.

**Parameters**

* `(string) $filename`
: Filename to validate and sanitize

**Return Values**

`array`

> Validation result with sanitized filename, errors, and warnings

Usage example:
```php
$validator = new ContentValidator();
$fileResult = $validator->validateFilename('../../../etc/passwd.txt');

if ($fileResult['is_valid']) {
    echo "Safe filename: " . $fileResult['sanitized_filename']; // passwd.txt
} else {
    foreach ($fileResult['errors'] as $error) {
        echo "Filename error: " . $error . "\n";
    }
}
```


<hr />


### ContentValidator::validatePhone

**Description**

```php
public validatePhone (string $phone)
```

Validate phone number

Validates and formats phone numbers with digit extraction,
length validation, and intelligent formatting for different regions.

**Parameters**

* `(string) $phone`
: Phone number to validate

**Return Values**

`array`

> Validation result with sanitized and formatted phone numbers

Usage example:
```php
$validator = new ContentValidator();
$phoneResult = $validator->validatePhone('(555) 123-4567');

if ($phoneResult['is_valid']) {
    echo "Digits only: " . $phoneResult['sanitized_phone']; // 5551234567
    echo "Formatted: " . $phoneResult['formatted_phone'];   // (555) 123-4567
}
```


<hr />


### ContentValidator::validateURL

**Description**

```php
public validateURL (string $url)
```

Validate URL

Validates and sanitizes URLs with protocol checking, scheme validation,
and security analysis for suspicious patterns.

**Parameters**

* `(string) $url`
: URL to validate

**Return Values**

`array`

> Validation result with sanitized URL, errors, and warnings

Usage example:
```php
$validator = new ContentValidator();
$urlResult = $validator->validateURL('example.com/path');

if ($urlResult['is_valid']) {
    echo "Valid URL: " . $urlResult['sanitized_url']; // http://example.com/path
    foreach ($urlResult['warnings'] as $warning) {
        echo "Warning: " . $warning . "\n";
    }
}
```


<hr />
