# Yohns Stop-Spam Documentation

### JavaScript Front End
[README JavaScript Guide](../README-JavaScript-GUIDE.md) | Code: [security-validator.js](../public/assets/js/security-validator.js)

### More Reading
- [Brief README](../README-BRIEF.md)
- [In Depth README](../README-IN-DEPT.md)

## Security Classes

* [Security\ClientIP](Security/ClientIP.md) — Shared IP detection with trusted proxy gate
* [Security\SecurityManager](Security/SecurityManager.md) — Orchestrator for all components
* [Security\CSRFToken](Security/CSRFToken.md) — CSRF protection (session + file + cookie)
* [Security\RateLimiter](Security/RateLimiter.md) — Rate limiting with progressive timeouts
* [Security\IPSecurity](Security/IPSecurity.md) — IP whitelist/blacklist and reputation
* [Security\ContentValidator](Security/ContentValidator.md) — Input sanitization and XSS protection
* [Security\TokenManager](Security/TokenManager.md) — API/verification/reset token lifecycle
* [Security\FileStorage](Security/FileStorage.md) — JSON file persistence layer

## AntiSpam Classes

* [AntiSpam\Honeypot](AntiSpam/Honeypot.md) — Bot detection via hidden fields and timing
* [AntiSpam\SpamDetector](AntiSpam/SpamDetector.md) — Content spam scoring via keywords/patterns
* [AntiSpam\ContentAnalyzer](AntiSpam/ContentAnalyzer.md) — Sentiment, readability, language detection
