/**
 * Security Validator JavaScript Library
 *
 * Provides client-side security validation and bot detection.
 * Works with the Yohns Stop Spam PHP library.
 */

// Helper function for HTML escaping
function htmlspecialchars(str) {
	const map = {
		'&': '&amp;',
		'<': '&lt;',
		'>': '&gt;',
		'"': '&quot;',
		"'": '&#039;'
	};
	return str.replace(/[&<>"']/g, function (m) { return map[m]; });
}

class SecurityValidator {
	constructor(options = {}) {
		this.options = {
			enableBotDetection: true,
			enableTimingAnalysis: true,
			enableCSRFValidation: true,
			minFormTime: 2000, // 2 seconds minimum
			maxFormTime: 3600000, // 1 hour maximum
			debugMode: false,
			...options
		};

		this.formTimers = new Map();
		this.mouseMovements = 0;
		this.keystrokes = 0;
		this.focusEvents = 0;
		this.isBot = false;

		this.init();
	}

	/**
	 * Initialize the security validator
	 */
	init() {
		if (document.readyState === 'loading') {
			document.addEventListener('DOMContentLoaded', () => {
				this.setupEventListeners();
				this.initializeForms();
			});
		} else {
			this.setupEventListeners();
			this.initializeForms();
		}

		this.log('SecurityValidator initialized');
	}

	/**
	 * Setup event listeners for bot detection
	 */
	setupEventListeners() {
		if (this.options.enableBotDetection) {
			// Mouse movement tracking
			document.addEventListener('mousemove', () => {
				this.mouseMovements++;
			}, { passive: true });

			// Keystroke tracking
			document.addEventListener('keydown', () => {
				this.keystrokes++;
			}, { passive: true });

			// Focus event tracking
			document.addEventListener('focusin', () => {
				this.focusEvents++;
			}, { passive: true });

			// Page visibility changes
			document.addEventListener('visibilitychange', () => {
				if (document.hidden) {
					this.log('Page became hidden - potential bot behavior');
				}
			});
		}

		// Form submission handling
		document.addEventListener('submit', (e) => {
			this.handleFormSubmission(e);
		});

		this.log('Event listeners setup complete');
	}

	/**
	 * Initialize forms with security features
	 */
	initializeForms() {
		const forms = document.querySelectorAll('form[data-validate="true"]');

		forms.forEach(form => {
			this.initializeForm(form);
		});

		this.log(`Initialized ${forms.length} forms with security validation`);
	}

	/**
	 * Initialize individual form
	 */
	initializeForm(form) {
		const formId = form.id || 'default';
		const startTime = Date.now();

		// Store form initialization time
		this.formTimers.set(formId, startTime);

		// Add hidden timestamp field
		this.addTimestampField(form, startTime);

		// Add bot detection fields
		if (this.options.enableBotDetection) {
			this.addBotDetectionFields(form);
		}

		// Setup form-specific event listeners
		this.setupFormListeners(form);

		this.log(`Form ${formId} initialized at ${startTime}`);
	}

	/**
	 * Add timestamp field to form
	 */
	addTimestampField(form, timestamp) {
		const timestampField = document.createElement('input');
		timestampField.type = 'hidden';
		timestampField.name = 'form_timestamp';
		timestampField.value = timestamp.toString();
		form.appendChild(timestampField);
	}

	/**
	 * Add bot detection fields
	 */
	addBotDetectionFields(form) {
		// Mouse movement counter
		const mouseField = document.createElement('input');
		mouseField.type = 'hidden';
		mouseField.name = 'mouse_movements';
		mouseField.className = 'security-field';
		form.appendChild(mouseField);

		// Keystroke counter
		const keyField = document.createElement('input');
		keyField.type = 'hidden';
		keyField.name = 'keystrokes';
		keyField.className = 'security-field';
		form.appendChild(keyField);

		// Focus events counter
		const focusField = document.createElement('input');
		focusField.type = 'hidden';
		focusField.name = 'focus_events';
		focusField.className = 'security-field';
		form.appendChild(focusField);

		// Screen resolution
		const screenField = document.createElement('input');
		screenField.type = 'hidden';
		screenField.name = 'screen_resolution';
		screenField.value = `${screen.width}x${screen.height}`;
		screenField.className = 'security-field';
		form.appendChild(screenField);

		// Timezone
		const timezoneField = document.createElement('input');
		timezoneField.type = 'hidden';
		timezoneField.name = 'timezone';
		timezoneField.value = Intl.DateTimeFormat().resolvedOptions().timeZone;
		timezoneField.className = 'security-field';
		form.appendChild(timezoneField);
	}

	/**
	 * Setup form-specific event listeners
	 */
	setupFormListeners(form) {
		// Track form interaction time
		let firstInteraction = null;

		const trackInteraction = () => {
			if (!firstInteraction) {
				firstInteraction = Date.now();
				this.log(`First interaction with form ${form.id || 'default'} at ${firstInteraction}`);
			}
		};

		// Listen for various interaction events
		form.addEventListener('focus', trackInteraction, true);
		form.addEventListener('input', trackInteraction, true);
		form.addEventListener('change', trackInteraction, true);
		form.addEventListener('click', trackInteraction, true);
	}

	/**
	 * Handle form submission
	 */
	handleFormSubmission(event) {
		const form = event.target;
		const formId = form.id || 'default';

		this.log(`Form submission attempted for ${formId}`);

		// Update bot detection counters
		this.updateBotDetectionFields(form);

		// Perform validation checks
		const validationResult = this.validateForm(form);

		if (!validationResult.valid) {
			event.preventDefault();
			this.showValidationError(form, validationResult.message);
			this.log(`Form submission blocked: ${validationResult.message}`);
			return false;
		}

		// Add CSRF token if needed
		if (this.options.enableCSRFValidation) {
			this.addCSRFToken(form);
		}

		this.log(`Form ${formId} passed validation`);
		return true;
	}

	/**
	 * Update bot detection fields before submission
	 */
	updateBotDetectionFields(form) {
		const mouseField = form.querySelector('input[name="mouse_movements"]');
		const keyField = form.querySelector('input[name="keystrokes"]');
		const focusField = form.querySelector('input[name="focus_events"]');

		if (mouseField) mouseField.value = this.mouseMovements.toString();
		if (keyField) keyField.value = this.keystrokes.toString();
		if (focusField) focusField.value = this.focusEvents.toString();
	}

	/**
	 * Validate form before submission
	 */
	validateForm(form) {
		const formId = form.id || 'default';
		const startTime = this.formTimers.get(formId);
		const currentTime = Date.now();

		if (!startTime) {
			return {
				valid: false,
				message: 'Form not properly initialized'
			};
		}

		const formTime = currentTime - startTime;

		// Check timing constraints
		if (this.options.enableTimingAnalysis) {
			if (formTime < this.options.minFormTime) {
				return {
					valid: false,
					message: 'Form submitted too quickly'
				};
			}

			if (formTime > this.options.maxFormTime) {
				return {
					valid: false,
					message: 'Form session expired'
				};
			}
		}

		// Check bot behavior
		if (this.options.enableBotDetection) {
			const botCheck = this.detectBotBehavior(formTime);
			if (botCheck.isBot) {
				return {
					valid: false,
					message: botCheck.reason
				};
			}
		}

		// Check honeypot fields
		const honeypotCheck = this.checkHoneypotFields(form);
		if (!honeypotCheck.valid) {
			return honeypotCheck;
		}

		return { valid: true, message: 'Form validated successfully' };
	}

	/**
	 * Detect bot behavior patterns
	 */
	detectBotBehavior(formTime) {
		const result = {
			isBot: false,
			reason: '',
			score: 0
		};

		let suspicionScore = 0;

		// No mouse movements
		if (this.mouseMovements === 0) {
			suspicionScore += 30;
		} else if (this.mouseMovements < 5) {
			suspicionScore += 15;
		}

		// No keystrokes
		if (this.keystrokes === 0) {
			suspicionScore += 20;
		} else if (this.keystrokes < 3) {
			suspicionScore += 10;
		}

		// No focus events
		if (this.focusEvents === 0) {
			suspicionScore += 25;
		}

		// Perfect timing (suspicious)
		if (formTime % 1000 === 0) {
			suspicionScore += 20;
		}

		// Too fast overall interaction
		if (formTime < 1000) {
			suspicionScore += 40;
		}

		// Check screen resolution (common bot values)
		const commonBotResolutions = ['1024x768', '800x600', '1920x1080'];
		const screenRes = `${screen.width}x${screen.height}`;
		if (commonBotResolutions.includes(screenRes) && suspicionScore > 20) {
			suspicionScore += 15;
		}

		result.score = suspicionScore;

		if (suspicionScore >= 60) {
			result.isBot = true;
			result.reason = 'Suspicious bot-like behavior detected';
		}

		this.log(`Bot detection score: ${suspicionScore}/100`);
		return result;
	}

	/**
	 * Check honeypot fields
	 */
	checkHoneypotFields(form) {
		// Common honeypot field names
		const honeypotNames = ['website', 'url', 'homepage', 'email_confirm'];

		for (const name of honeypotNames) {
			const field = form.querySelector(`input[name="${name}"]`);
			if (field && field.value.trim() !== '') {
				return {
					valid: false,
					message: 'Honeypot field filled'
				};
			}
		}

		return { valid: true };
	}

	/**
	 * Add CSRF token to form
	 */
	addCSRFToken(form) {
		// Get CSRF token from meta tag
		const metaToken = document.querySelector('meta[name="csrf-token"]');

		if (metaToken && !form.querySelector('input[name="csrf_token"]')) {
			const csrfField = document.createElement('input');
			csrfField.type = 'hidden';
			csrfField.name = 'csrf_token';
			csrfField.value = metaToken.getAttribute('content');
			form.appendChild(csrfField);
		}
	}

	/**
	 * Show validation error to user
	 */
	showValidationError(form, message) {
		// Remove existing error messages
		const existingErrors = form.querySelectorAll('.security-error');
		existingErrors.forEach(error => error.remove());

		// Create error message element
		const errorDiv = document.createElement('div');
		errorDiv.className = 'alert alert-danger security-error';
		errorDiv.textContent = message;

		// Insert at beginning of form
		form.insertBefore(errorDiv, form.firstChild);

		// Auto-remove after 5 seconds
		setTimeout(() => {
			if (errorDiv.parentNode) {
				errorDiv.remove();
			}
		}, 5000);
	}

	/**
	 * Get security information for debugging
	 */
	getSecurityInfo() {
		return {
			mouseMovements: this.mouseMovements,
			keystrokes: this.keystrokes,
			focusEvents: this.focusEvents,
			formTimers: Object.fromEntries(this.formTimers),
			userAgent: navigator.userAgent,
			screenResolution: `${screen.width}x${screen.height}`,
			timezone: Intl.DateTimeFormat().resolvedOptions().timeZone,
			language: navigator.language,
			platform: navigator.platform
		};
	}

	/**
	 * Reset security counters
	 */
	reset() {
		this.mouseMovements = 0;
		this.keystrokes = 0;
		this.focusEvents = 0;
		this.formTimers.clear();
		this.log('Security validator reset');
	}

	/**
	 * Log messages (only in debug mode)
	 */
	log(message) {
		if (this.options.debugMode) {
			console.log(`[SecurityValidator] ${message}`);
		}
	}

	/**
	 * Static method to initialize with default options
	 */
	static init(options = {}) {
		window.securityValidator = new SecurityValidator(options);
		return window.securityValidator;
	}
}

// Auto-initialize if not in module environment
if (typeof module === 'undefined') {
	// Initialize when DOM is ready
	if (document.readyState === 'loading') {
		document.addEventListener('DOMContentLoaded', () => {
			SecurityValidator.init();
		});
	} else {
		SecurityValidator.init();
	}
}

// Export for module environments
if (typeof module !== 'undefined' && module.exports) {
	module.exports = SecurityValidator;
}