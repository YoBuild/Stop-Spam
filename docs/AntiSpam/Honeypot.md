# Yohns\AntiSpam\Honeypot

Bot detection via hidden form fields and timing analysis. Bots that auto-fill hidden fields or submit forms inhumanly fast get caught. Legitimate users never see the honeypot field.

Uses `\Yohns\Security\ClientIP::get()` for IP detection (never reads `$_SERVER` headers directly).
Stores honeypot sessions in both `$_SESSION` and `FileStorage` (backup for stateless apps).
Logs all spam attempts to the `spam_log` storage table.

## Configuration

All values come from the `honeypot` section in `config/security.php`:

| Key              | Default       | Description                                      |
|------------------|---------------|--------------------------------------------------|
| `enabled`        | `true`        | Master switch for honeypot protection             |
| `field_name`     | `'website'`   | Name attribute of the hidden input field          |
| `min_time`       | `2`           | Minimum seconds before a submission is valid      |
| `max_time`       | `3600`        | Maximum seconds (1 hour) before form goes stale   |
| `session_prefix` | `'honeypot_'` | Prefix for session keys storing form timestamps   |

## Methods

### `initialize(string $formId = 'default'): string`

Starts a honeypot session for the given form. Records the current timestamp in `$_SESSION` and `FileStorage`, then returns the hidden field HTML.

```php
<?php
use Yohns\AntiSpam\Honeypot;

$honeypot = new Honeypot();
?>
<html>
<head>
	<?= $honeypot->getCSS() ?>
</head>
<body>
	<form method="post" action="/submit-contact">
		<?= $honeypot->initialize('contact_form') ?>
		<!-- Outputs: <input type="text" name="website" value="" style="display:none !important; position:absolute; left:-9999px;" tabindex="-1" autocomplete="off"> -->

		<label>Name</label>
		<input type="text" name="name" required>

		<label>Email</label>
		<input type="email" name="email" required>

		<label>Message</label>
		<textarea name="message" required></textarea>

		<button type="submit">Send</button>
	</form>
</body>
</html>
```

### `validate(array $postData, string $formId = 'default'): array`

Runs three checks in sequence. Returns on the first failure.

**Validation checks (in order):**

1. **`checkHoneypotField()`** -- If the hidden `website` field contains any value, it is a bot. Bots auto-fill all fields; real users never see this one.
2. **`checkTiming()`** -- Submission faster than `min_time` (2s) = bot. Slower than `max_time` (3600s) = stale/expired form. Looks up the timestamp from `$_SESSION` first, falls back to `FileStorage`.
3. **`checkBotBehavior()`** -- Checks four suspicious patterns and fails if 2 or more are found:
   - No common fields present (`email`, `name`, `message`, `content`, `subject`)
   - Total POST content shorter than 3 characters
   - More than 5 URLs in the combined POST data
   - More than 10 spam log entries from the same IP in the last 5 minutes

**Return value:**

```php
[
	'passed'  => true,   // bool: did all checks pass?
	'reason'  => '',     // string: failure reason (empty on success)
	'details' => [],     // array: detailed explanation strings
]
```

**Form handler example:**

```php
<?php
use Yohns\AntiSpam\Honeypot;

$honeypot = new Honeypot();

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
	$result = $honeypot->validate($_POST, 'contact_form');

	if (!$result['passed']) {
		// $result['reason'] is one of:
		//   'Honeypot field filled'
		//   'Submission too fast'
		//   'Submission too slow'
		//   'No honeypot session found'
		//   'Suspicious bot behavior'
		error_log('Spam blocked: ' . $result['reason']);
		http_response_code(403);
		exit('Form submission rejected.');
	}

	// Submission is legitimate -- process the form
	$name    = $_POST['name'];
	$email   = $_POST['email'];
	$message = $_POST['message'];
	// ... save to database, send email, etc.
}
```

### `getHiddenField(): string`

Returns the raw hidden input HTML without starting a session. Useful if you call `initialize()` separately and just need the field markup again.

```php
$html = $honeypot->getHiddenField();
// '<input type="text" name="website" value="" style="display:none !important; position:absolute; left:-9999px;" tabindex="-1" autocomplete="off">'
```

Returns an empty string when honeypot is disabled.

### `getCSS(): string`

Returns a `<style>` block that hides the honeypot field via multiple CSS properties (`display:none`, `position:absolute`, `visibility:hidden`). Place this in your `<head>`.

```php
echo $honeypot->getCSS();
// Output:
// <style>
// .honeypot, input[name='website'] {
//     display: none !important;
//     position: absolute !important;
//     left: -9999px !important;
//     top: -9999px !important;
//     visibility: hidden !important;
// }
// </style>
```

### `cleanup(): int`

Removes expired honeypot sessions from `FileStorage` (sessions past their `expires_at` timestamp). Returns the count of deleted records. Call this from a cron job or periodic maintenance script.

```php
$honeypot = new Honeypot();
$deleted = $honeypot->cleanup();
// $deleted = 14  (14 expired sessions removed)
```

### `getStats(): array`

Returns spam detection statistics from the `spam_log` table, filtered to honeypot-related entries only.

```php
$honeypot = new Honeypot();
$stats = $honeypot->getStats();

// $stats = [
//     'total_attempts'  => 47,
//     'detection_types' => [
//         'honeypot_honeypot_field' => 12,
//         'honeypot_timing_too_fast' => 28,
//         'honeypot_timing_too_slow' => 3,
//         'honeypot_bot_behavior'   => 4,
//     ],
//     'recent_attempts' => 5,   // last 24 hours
// ]
```

### `isEnabled(): bool`

Returns `true` if `honeypot.enabled` is `true` in config. When disabled, `initialize()` returns an empty string and `validate()` always passes.

```php
if ($honeypot->isEnabled()) {
	echo $honeypot->initialize('signup_form');
}
```

## Complete Form Example

```php
<?php
// form.php
use Yohns\AntiSpam\Honeypot;

$honeypot = new Honeypot();
?>
<!DOCTYPE html>
<html>
<head>
	<title>Contact Us</title>
	<?= $honeypot->getCSS() ?>
</head>
<body>
	<form method="post" action="process.php">
		<?= $honeypot->initialize('contact_form') ?>

		<label for="name">Name</label>
		<input type="text" id="name" name="name" required>

		<label for="email">Email</label>
		<input type="email" id="email" name="email" required>

		<label for="subject">Subject</label>
		<input type="text" id="subject" name="subject">

		<label for="message">Message</label>
		<textarea id="message" name="message" required></textarea>

		<button type="submit">Send Message</button>
	</form>
</body>
</html>
```

```php
<?php
// process.php
use Yohns\AntiSpam\Honeypot;

$honeypot = new Honeypot();

$result = $honeypot->validate($_POST, 'contact_form');

if (!$result['passed']) {
	http_response_code(403);
	exit('Submission rejected.');
}

// Safe to process
$name    = htmlspecialchars($_POST['name']);
$email   = filter_var($_POST['email'], FILTER_VALIDATE_EMAIL);
$message = htmlspecialchars($_POST['message']);

mail($email, 'Contact Form', $message);
echo 'Thank you for your message!';
```

## Gotchas

- **Session must be available.** The constructor calls `session_start()` if no session is active. If your framework manages sessions differently, make sure a session is started before constructing `Honeypot`.
- **FileStorage fallback.** If `$_SESSION` data is lost between requests (e.g., stateless API), the class falls back to `FileStorage` using the client IP + form ID to find the session. This means two users behind the same IP submitting the same form could theoretically collide.
- **Field name collisions.** The default field name is `website`. If your form has a legitimate field called `website`, change `honeypot.field_name` in config or that field will trigger false positives.
- **Bot behavior check needs common fields.** The `checkBotBehavior()` check looks for fields named `email`, `name`, `message`, `content`, or `subject`. If your form uses none of these names, that counts as one suspicious pattern toward the threshold of 2.