# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

PHP 8.2+ security library (`yohns/stop-spam`) providing spam prevention and security features without a database dependency. Uses JSON file-based storage via `FileStorage`.

## Commands

```bash
# Install PHP dependencies
composer install

# Install frontend dependencies
npm install

# Build production CSS + JS
npm run build

# Watch for changes during development
npm run dev        # or: npm run watch

# Generate API docs from PHPDoc
composer exec phpdoc-md

# Syntax check a PHP file
php -l Yohns/Security/CSRFToken.php
```

## Architecture

**Orchestrator pattern:** `SecurityManager` composes and coordinates all security components:

```
SecurityManager (Yohns\Security)
├── CSRFToken          - Token-based CSRF protection (session + file + cookie storage)
├── RateLimiter        - IP/user rate limiting with progressive timeouts
├── Honeypot           - Bot detection via hidden fields and timing analysis (Yohns\AntiSpam)
├── SpamDetector       - Content spam scoring via keywords/patterns (Yohns\AntiSpam)
├── ContentValidator   - Input sanitization and XSS protection
├── TokenManager       - API/verification/reset token lifecycle
├── IPSecurity         - IP whitelist/blacklist and reputation tracking
├── FileStorage        - JSON file persistence layer (used by all components)
└── ClientIP           - Shared IP detection with trusted proxy gate (used by all components)
```

`ContentAnalyzer` (`Yohns\AntiSpam`) provides advanced content analysis (sentiment, readability, language detection) as a standalone class.

**Namespaces:** `Yohns\Security\*` and `Yohns\AntiSpam\*`, PSR-4 autoloaded from `Yohns/` directory.

**Configuration:** Centralized in `config/security.php` (PHP array), accessed via `yohns/config` library. All security features enabled by default.

**Storage:** JSON files in `database/` directory with file locking (`flock`). No database required.

**Frontend:** `public/assets/js/security-validator.js` provides client-side bot detection, timing analysis, and CSRF validation. SCSS uses Bootstrap 5.3.7.

## Gotchas

- **ClientIP trusted proxy gate:** Forwarded headers (X-Forwarded-For, etc.) are only trusted when REMOTE_ADDR is a known proxy. All classes delegate IP detection to `ClientIP::get()` — never read `$_SERVER` headers directly.
- **FileStorage table names:** Must match `^[a-zA-Z0-9_-]+$` — path traversal attempts throw `InvalidArgumentException`.
- **TokenManager signing secret:** `signToken()`/`verifyTokenSignature()` throw `RuntimeException` if `token_management.signing_secret` config key is missing. No default fallback.
- **ContentValidator allow_html:** When `allow_html=true`, `finalEncode()` is skipped to avoid double-encoding already-sanitized HTML.
- **IPSecurity analyzeIP vs enforcePolicy:** `analyzeIP()` is a pure read (no side effects). Use `enforcePolicy()` when you want auto-blocking of low-trust IPs.
- **RateLimiter isLimited vs recordAttempt:** `isLimited()` is a pure check. Call `recordAttempt()` separately to increment counters.

## Code Style

- Tab indentation (2-space width), LF line endings, UTF-8
- PHP 8.2+ features expected
- No trailing newline at end of files
