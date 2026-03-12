# ContentValidator

`Yohns\Security\ContentValidator` -- Input sanitization and XSS protection.

Validates, sanitizes, and secures user-submitted content. Detects XSS attack patterns, strips or sanitizes HTML via DOMDocument, validates emails/URLs/phones/filenames, and supports custom validation rules.

---

## Configuration

Values from the `content_validation` section of `config/security.php`:

| Key               | Default | Description                                  |
|-------------------|---------|----------------------------------------------|
| `enabled`         | `true`  | Master switch for all validation              |
| `max_length`      | `10000` | Maximum content length in characters          |
| `allow_html`      | `false` | Allow HTML tags (sanitized) in content        |
| `strip_tags`      | `true`  | Strip all HTML tags when `allow_html` is off  |
| `profanity_filter` | `true` | Enable profanity/spam word filtering          |

```php
// config/security.php (excerpt)
'content_validation' => [
	'enabled'          => true,
	'max_length'       => 10000,
	'allow_html'       => false,
	'strip_tags'       => true,
	'profanity_filter' => true,
],
```

---

## Core Methods

### validate(string $content, array $options = []): array

Comprehensive content validation. Checks length, removes control characters, detects XSS, handles HTML, normalizes whitespace, and applies final encoding.

**Options** (all override config defaults):

| Option                | Type   | Default          |
|-----------------------|--------|------------------|
| `allow_html`          | `bool` | from config      |
| `max_length`          | `int`  | from config      |
| `strip_tags`          | `bool` | from config      |
| `check_xss`           | `bool` | `true`           |
| `normalize_whitespace` | `bool` | `true`          |
| `remove_control_chars` | `bool` | `true`          |

**Returns** an array with these keys:

| Key                  | Type     | Description                                |
|----------------------|----------|--------------------------------------------|
| `is_valid`           | `bool`   | `false` if content exceeds max length       |
| `original_content`   | `string` | Untouched input                             |
| `sanitized_content`  | `string` | Cleaned output safe for storage/display     |
| `errors`             | `array`  | Validation error messages                   |
| `warnings`           | `array`  | Non-fatal warnings                          |
| `changes_made`       | `array`  | List of modifications applied               |
| `security_issues`    | `array`  | XSS threats found (type, description, severity) |

```php
$validator = new \Yohns\Security\ContentValidator();

// Plain text input (default mode -- no HTML allowed)
$result = $validator->validate(
	'<b>Hello</b> world <script>alert("xss")</script>',
	['max_length' => 5000]
);

// $result['is_valid']          => true
// $result['sanitized_content'] => 'Hello world' (tags stripped, then HTML-encoded)
// $result['security_issues']   => [
//     ['type' => 'script_tags', 'description' => 'Script tag injection', 'severity' => 'high']
// ]
// $result['changes_made']      => ['Removed XSS threats', 'Removed HTML tags', 'Normalized whitespace']
```

```php
// Allow HTML -- sanitizes rather than strips
$result = $validator->validate(
	'<p>Safe paragraph</p><script>alert("xss")</script><div onmouseover="hack()">hover</div>',
	['allow_html' => true]
);

// $result['sanitized_content'] => '<p>Safe paragraph</p>hover'
// Script tag removed by XSS detector, <div> removed as disallowed tag (content preserved),
// onmouseover removed as event handler
```

```php
// Content too long
$result = $validator->validate(str_repeat('a', 15000), ['max_length' => 10000]);

// $result['is_valid'] => false
// $result['errors']   => ['Content exceeds maximum length of 10000 characters']
// Content is truncated to 10000 chars in sanitized_content
```

---

### detectXSS(string $content): array

Scans content for XSS attack patterns without modifying or logging anything else.

**Detected patterns:**

| Pattern               | Severity | Example                                |
|-----------------------|----------|----------------------------------------|
| `script_tags`         | high     | `<script>alert('xss')</script>`        |
| `javascript_protocol` | high    | `javascript:void(0)`                   |
| `event_handlers`      | high     | `onmouseover="hack()"`                 |
| `data_urls`           | medium   | `data:text/html,<script>...`           |
| `vbscript`            | high     | `vbscript:MsgBox("hi")`               |

```php
$validator = new \Yohns\Security\ContentValidator();

$xss = $validator->detectXSS('Click <a href="javascript:steal()">here</a>');

// $xss['is_safe']           => false
// $xss['threats']           => [
//     [
//         'type'        => 'javascript_protocol',
//         'description' => 'JavaScript protocol in URLs',
//         'severity'    => 'high',
//     ]
// ]
// $xss['sanitized_content'] => 'Click <a href="blocked:steal()">here</a>'
```

```php
$safe = $validator->detectXSS('Just a normal comment with no threats.');

// $safe['is_safe']           => true
// $safe['threats']           => []
// $safe['sanitized_content'] => 'Just a normal comment with no threats.'
```

---

### sanitizeHTML(string $content): array

Parses HTML with DOMDocument, removes disallowed tags (preserving their text content), strips disallowed attributes, and blocks dangerous attribute values.

**Default allowed tags:** `p`, `br`, `strong`, `b`, `em`, `i`, `u`, `span`, `h1`-`h6`, `ul`, `ol`, `li`, `blockquote`, `a`, `img`

**Default allowed attributes:**

| Scope        | Attributes                          |
|--------------|-------------------------------------|
| `*` (global) | `class`, `id`                       |
| `a`          | `href`, `title`, `target`           |
| `img`        | `src`, `alt`, `title`, `width`, `height` |
| `blockquote` | `cite`                              |

Allowed tags and attributes are loaded from FileStorage on first use. If none exist, the defaults above are persisted automatically.

```php
$validator = new \Yohns\Security\ContentValidator();

$html = $validator->sanitizeHTML(
	'<p class="intro">Hello</p><div>world</div><script>bad()</script>'
);

// $html['content']  => '<p class="intro">Hello</p>world'
//   - <div> removed (not in allowed list), text "world" preserved
//   - <script> removed as disallowed tag, content discarded
// $html['changes']  => ['Removed 2 disallowed HTML tags']
// $html['warnings'] => []
```

```php
// Dangerous attribute values are caught even on allowed tags
$html = $validator->sanitizeHTML('<a href="javascript:steal()">click</a>');

// $html['warnings'] => ['Removed dangerous attribute: href']
```

---

## Validation Helpers

### validateEmail(string $email): array

Trims, checks length (max 254 chars), validates with `FILTER_VALIDATE_EMAIL`, lowercases.

```php
$validator = new \Yohns\Security\ContentValidator();

$result = $validator->validateEmail('  User@Example.COM  ');
// $result['is_valid']        => true
// $result['sanitized_email'] => 'user@example.com'

$result = $validator->validateEmail('not-an-email');
// $result['is_valid'] => false
// $result['errors']   => ['Invalid email address format']

$result = $validator->validateEmail('');
// $result['errors'] => ['Email address is required']
```

### validateURL(string $url): array

Adds `http://` if no protocol, validates with `FILTER_VALIDATE_URL`, checks scheme against `http`, `https`, `ftp`. Warns on IP-based URLs.

```php
$validator = new \Yohns\Security\ContentValidator();

$result = $validator->validateURL('example.com/page');
// $result['is_valid']      => true
// $result['sanitized_url'] => 'http://example.com/page'
// $result['warnings']      => ['Added http:// protocol']

$result = $validator->validateURL('https://192.168.1.1/admin');
// $result['is_valid']  => true
// $result['warnings']  => ['URL contains IP address instead of domain name']

$result = $validator->validateURL('ftp://files.example.com/doc.pdf');
// $result['is_valid']      => true
// $result['sanitized_url'] => 'ftp://files.example.com/doc.pdf'
```

### validatePhone(string $phone): array

Strips non-digit characters, validates length (7-15 digits), formats US numbers.

```php
$validator = new \Yohns\Security\ContentValidator();

$result = $validator->validatePhone('(555) 123-4567');
// $result['is_valid']        => true
// $result['sanitized_phone'] => '5551234567'
// $result['formatted_phone'] => '(555) 123-4567'

$result = $validator->validatePhone('+1 (555) 123-4567');
// $result['sanitized_phone'] => '15551234567'
// $result['formatted_phone'] => '+1 (555) 123-4567'

$result = $validator->validatePhone('+44 20 7946 0958');
// $result['sanitized_phone'] => '442079460958'
// $result['formatted_phone'] => '+442079460958'
```

### validateFilename(string $filename): array

Strips directory traversal (`basename()`), replaces dangerous characters with `_`, blocks executable extensions, limits to 255 chars.

**Blocked extensions:** `php`, `phtml`, `php3`, `php4`, `php5`, `phar`, `exe`, `bat`, `cmd`, `com`, `scr`, `vbs`, `js`

```php
$validator = new \Yohns\Security\ContentValidator();

$result = $validator->validateFilename('../../../etc/passwd');
// $result['is_valid']            => true
// $result['sanitized_filename']  => 'passwd'
// $result['warnings']            => ['Filename was sanitized']

$result = $validator->validateFilename('malware.php');
// $result['is_valid'] => false
// $result['errors']   => ['File extension not allowed for security reasons']

$result = $validator->validateFilename('my document (1).pdf');
// $result['is_valid']           => true
// $result['sanitized_filename'] => 'my_document__1_.pdf'
```

---

## Custom Validation Rules

### addValidationRule(string $name, callable $validator): void

Registers a custom validation callable stored in `$this->customRules`.

```php
$validator = new \Yohns\Security\ContentValidator();

// Add a rule that checks for a product code format
$validator->addValidationRule('product_code', function (string $content): bool {
	return (bool) preg_match('/^[A-Z]{3}-\d{4}$/', $content);
});

// Add a rule that rejects content with too many URLs
$validator->addValidationRule('max_urls', function (string $content): bool {
	$urlCount = preg_match_all('/https?:\/\//', $content);
	return $urlCount <= 2;
});
```

Note: Custom rules are stored in memory on the instance. They persist for the lifetime of the `ContentValidator` object.

---

## Statistics

### getValidationStats(): array

Returns aggregate data from the `content_security_log` FileStorage table.

```php
$validator = new \Yohns\Security\ContentValidator();
$stats = $validator->getValidationStats();

// $stats = [
//     'total_validations'     => 142,       // all-time logged validations with security issues
//     'recent_validations'    => 8,          // last 24 hours
//     'security_issues_found' => 23,
//     'severity_breakdown'    => [
//         'low'    => 3,
//         'medium' => 5,
//         'high'   => 15,
//     ],
//     'common_issues' => [
//         'script_tags'         => 10,       // top 10 issue types, sorted desc
//         'event_handlers'      => 7,
//         'javascript_protocol' => 6,
//     ],
// ]
```

---

## Gotchas

1. **`allow_html` skips `finalEncode()`.**
   When `allow_html=true` in `validate()`, the output is NOT run through `htmlspecialchars()`. This avoids double-encoding already-sanitized HTML but means the DOMDocument-based `sanitizeHTML()` is the only defense layer. If you set `allow_html=true`, trust the sanitizer -- do not double-encode afterward.

2. **`addValidationRule()` stores callables properly.**
   Earlier versions discarded the callable argument. The current implementation correctly stores it in `$this->customRules[$name]`.

3. **IP logging uses `ClientIP::get()`.**
   The `logSecurityIssue()` method uses `ClientIP::get()` rather than reading `$_SERVER['REMOTE_ADDR']` directly. This respects the trusted proxy gate so forwarded headers are only used when `REMOTE_ADDR` is a recognized proxy.

4. **XSS patterns are persisted to FileStorage.**
   On first instantiation, default XSS patterns, allowed tags, and allowed attributes are written to FileStorage JSON files. Subsequent instances load from storage, so changes made directly to the JSON files will take effect.

5. **`validate()` truncates but still flags.**
   If content exceeds `max_length`, it is truncated AND `is_valid` is set to `false` with an error. The `sanitized_content` will contain the truncated (and otherwise cleaned) version.

6. **Disabled validator passes everything.**
   When `enabled` is `false`, `validate()` returns immediately with `is_valid=true` and the original content unchanged.