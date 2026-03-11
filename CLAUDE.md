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
└── FileStorage        - JSON file persistence layer (used by all components)
```

`ContentAnalyzer` (`Yohns\AntiSpam`) provides advanced content analysis (sentiment, readability, language detection) as a standalone class.

**Namespaces:** `Yohns\Security\*` and `Yohns\AntiSpam\*`, PSR-4 autoloaded from `Yohns/` directory.

**Configuration:** Centralized in `config/security.php` (PHP array), accessed via `yohns/config` library. All security features enabled by default.

**Storage:** JSON files in `database/` directory with file locking (`flock`). No database required.

**Frontend:** `public/assets/js/security-validator.js` provides client-side bot detection, timing analysis, and CSRF validation. SCSS uses Bootstrap 5.3.7.

## Code Style

- Tab indentation (2-space width), LF line endings, UTF-8
- PHP 8.2+ features expected
- No trailing newline at end of files
