/**
 * SecurityValidator.js - Client-side security validation for forms
 *
 * This script provides client-side validation for CSRF tokens,
 * honeypot fields, and implements bot detection techniques.
 */

class SecurityValidator {
	/**
	 * Initialize security validation on a form
	 * @param {string} formSelector - CSS selector for the form(s) to protect
	 * @param {Object} options - Configuration options
	 */
	constructor(formSelector = 'form', options = {}) {
		// Default options
		this.options = {
			csrfTokenName: 'csrf_token',
			csrfHeaderName: 'X-CSRF-TOKEN',
			honeypotFieldName: 'website',
			minSubmitTime: 2000, // Minimum time in milliseconds before form submission is allowed
			detectBotBehavior: true,
			validateBeforeSubmit: true,
			...options
		};

		// State variables
		this.formLoadTime = Date.now();
		this.hasInteracted = false;
		this.botBehaviorDetected = false;
		this.forms = [];

		// Initialize
		this.init(formSelector);
	}

	/**
	 * Initialize the security validator
	 * @param {string} formSelector - CSS selector for the form(s) to protect
	 */
	init(formSelector) {
		// Document loaded check
		if (document.readyState === 'loading') {
			document.addEventListener('DOMContentLoaded', () => this.setupForms(formSelector));
		} else {
			this.setupForms(formSelector);
		}

		// Track user interactions
		this.trackUserInteraction();

		// Run bot detection if enabled
		if (this.options.detectBotBehavior) {
			this.detectBotBehavior();
		}
	}

	/**
	 * Set up security validation on the selected forms
	 * @param {string} formSelector - CSS selector for the form(s) to protect
	 */
	setupForms(formSelector) {
		// Find all matching forms
		this.forms = document.querySelectorAll(formSelector);

		if (this.forms.length === 0) {
			console.warn('SecurityValidator: No forms found matching selector', formSelector);
			return;
		}

		// Set up each form
		this.forms.forEach(form => {
			// Only set up forms that have a CSRF token field
			const csrfField = form.querySelector(`[name="${this.options.csrfTokenName}"]`);
			if (!csrfField) {
				return;
			}

			// Add submit event listener for validation
			if (this.options.validateBeforeSubmit) {
				form.addEventListener('submit', event => this.validateOnSubmit(event, form));
			}

			// Add AJAX request interceptor for forms that may submit via AJAX
			this.setupAjaxInterceptor();
		});
	}

	/**
	 * Track user interaction with the page
	 */
	trackUserInteraction() {
		const interactionEvents = ['mousemove', 'click', 'scroll', 'keydown', 'touchstart'];

		interactionEvents.forEach(eventType => {
			document.addEventListener(eventType, () => {
				this.hasInteracted = true;
			}, { once: true });
		});
	}

	/**
	 * Set up AJAX request interceptor to add CSRF tokens to AJAX requests
	 */
	setupAjaxInterceptor() {
		const originalXhrOpen = XMLHttpRequest.prototype.open;
		const originalXhrSend = XMLHttpRequest.prototype.send;
		const csrfHeaderName = this.options.csrfHeaderName;

		// Get all CSRF tokens on the page
		const csrfTokens = {};
		document.querySelectorAll(`[name="${this.options.csrfTokenName}"]`).forEach(input => {
			// Use the closest form's action or ID as the context
			const form = input.closest('form');
			let context = '';

			if (form) {
				context = form.getAttribute('action') || form.getAttribute('id') || 'default';
			}

			csrfTokens[context] = input.value;
		});

		// Intercept XHR.open
		XMLHttpRequest.prototype.open = function() {
			this._securityContext = arguments[1] || 'default';
			return originalXhrOpen.apply(this, arguments);
		};

		// Intercept XHR.send
		XMLHttpRequest.prototype.send = function() {
			// Find the most appropriate CSRF token
			let token = null;

			// Try to find an exact match first
			if (csrfTokens[this._securityContext]) {
				token = csrfTokens[this._securityContext];
			} else {
				// Otherwise use the default token if available
				token = csrfTokens['default'];
			}

			// Add CSRF token header if a token was found
			if (token) {
				this.setRequestHeader(csrfHeaderName, token);
			}

			return originalXhrSend.apply(this, arguments);
		};
	}

	/**
	 * Detect potential bot behavior
	 */
	detectBotBehavior() {
		// Check for automation frameworks
		if (window.navigator.webdriver ||
			window.callPhantom ||
			window._phantom ||
			window.__nightmare ||
			window.Buffer ||
			window.emit ||
			window.spawn) {
			this.botBehaviorDetected = true;
		}

		// Check for headless browser
		if (/HeadlessChrome/.test(window.navigator.userAgent)) {
			this.botBehaviorDetected = true;
		}

		// Check for missing plugins (most bots have 0)
		// Note: This could also flag privacy-focused browsers, so we don't use it alone
		const noPlugins = navigator.plugins.length === 0 && !navigator.mimeTypes.length;

		// Check for suspicious user agent patterns
		const userAgent = navigator.userAgent.toLowerCase();
		const suspiciousUaPatterns = ['bot', 'crawler', 'spider', 'slurp', 'baidu', 'yandex'];

		const hasSuspiciousUa = suspiciousUaPatterns.some(pattern => userAgent.includes(pattern));

		// Combine multiple factors for more reliable detection
		if (noPlugins && hasSuspiciousUa) {
			this.botBehaviorDetected = true;
		}

		// Monitor for suspicious form filling behavior
		if (this.forms.length > 0) {
			// Track rapid field filling
			const inputFields = document.querySelectorAll('input, textarea, select');
			const changeTimestamps = [];

			inputFields.forEach(field => {
				field.addEventListener('change', () => {
					changeTimestamps.push(Date.now());

					// Check for too rapid changes (less than 10ms apart)
					if (changeTimestamps.length > 1) {
						const lastIndex = changeTimestamps.length - 1;
						const timeDiff = changeTimestamps[lastIndex] - changeTimestamps[lastIndex - 1];

						if (timeDiff < 10) {
							this.botBehaviorDetected = true;
						}
					}
				});
			});

			// Track too-perfect tab navigation
			let lastTabTime = 0;
			let tabTimeDiffs = [];

			document.addEventListener('keydown', (event) => {
				if (event.key === 'Tab') {
					const now = Date.now();

					if (lastTabTime > 0) {
						const diff = now - lastTabTime;
						tabTimeDiffs.push(diff);

						// If we have enough samples, check for too-consistent timing
						if (tabTimeDiffs.length >= 5) {
							// Calculate standard deviation
							const avg = tabTimeDiffs.reduce((sum, val) => sum + val, 0) / tabTimeDiffs.length;
							const variance = tabTimeDiffs.reduce((sum, val) => sum + Math.pow(val - avg, 2), 0) / tabTimeDiffs.length;
							const stdDev = Math.sqrt(variance);

							// If standard deviation is very low (too consistent), it might be a bot
							if (stdDev < 5 && avg < 200) {
								this.botBehaviorDetected = true;
							}

							// Reset for the next batch
							tabTimeDiffs = [];
						}
					}

					lastTabTime = now;
				}
			});
		}
	}

	/**
	 * Validate form before submission
	 * @param {Event} event - The submit event
	 * @param {HTMLFormElement} form - The form being submitted
	 */
	validateOnSubmit(event, form) {
		// Check for bot behavior
		if (this.botBehaviorDetected) {
			console.warn('Form submission blocked: Bot behavior detected');
			event.preventDefault();
			return false;
		}

		// Check for minimum submission time
		const timeOnPage = Date.now() - this.formLoadTime;
		if (timeOnPage < this.options.minSubmitTime) {
			console.warn('Form submission blocked: Submitted too quickly');
			event.preventDefault();
			return false;
		}

		// Check for user interaction
		if (!this.hasInteracted) {
			console.warn('Form submission blocked: No user interaction detected');
			event.preventDefault();
			return false;
		}

		// Check honeypot field
		const honeypotField = form.querySelector(`[name="${this.options.honeypotFieldName}"]`);
		if (honeypotField && honeypotField.value !== '') {
			console.warn('Form submission blocked: Honeypot field filled');
			event.preventDefault();
			return false;
		}

		// Verify CSRF token exists
		const csrfField = form.querySelector(`[name="${this.options.csrfTokenName}"]`);
		if (!csrfField || !csrfField.value) {
			console.warn('Form submission blocked: Missing CSRF token');
			event.preventDefault();
			return false;
		}

		// All validations passed
		return true;
	}

	/**
	 * Get the CSRF token for a specific form
	 * @param {HTMLFormElement|string} form - Form element or selector
	 * @returns {string|null} - The CSRF token or null if not found
	 */
	getCSRFToken(form) {
		if (typeof form === 'string') {
			form = document.querySelector(form);
		}

		if (!form) {
			return null;
		}

		const csrfField = form.querySelector(`[name="${this.options.csrfTokenName}"]`);
		return csrfField ? csrfField.value : null;
	}

	/**
	 * Check if bot behavior has been detected
	 * @returns {boolean} - True if bot behavior was detected
	 */
	isBotDetected() {
		return this.botBehaviorDetected;
	}

	/**
	 * Add a custom bot detection check
	 * @param {Function} checkFunction - Function that returns true if bot is detected
	 */
	addBotDetectionCheck(checkFunction) {
		if (typeof checkFunction === 'function') {
			const result = checkFunction();
			if (result === true) {
				this.botBehaviorDetected = true;
			}
		}
	}
}

// Initialize on page load with default settings
document.addEventListener('DOMContentLoaded', () => {
	// Only auto-initialize if the script is loaded directly (not as a module)
	if (typeof module === 'undefined') {
		window.securityValidator = new SecurityValidator();
	}
});

// Support for module imports
if (typeof module !== 'undefined' && typeof module.exports !== 'undefined') {
	module.exports = SecurityValidator;
}