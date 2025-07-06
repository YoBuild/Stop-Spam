/**
 * SecurityClient.js
 * Client-side security and validation functionality for the social network
 *
 * This script provides client-side validation, rate limiting, and security
 * features to complement the server-side security measures.
 */

class SecurityClient {
	/**
	 * Constructor for SecurityClient
	 *
	 * @param {Object} options Configuration options
	 * @param {Object} options.rateLimits Client-side rate limit settings
	 * @param {boolean} options.validateForms Whether to automatically validate forms
	 * @param {boolean} options.trackUserActions Whether to track user actions for rate limiting
	 */
	constructor(options = {}) {
		// Default options
		this.options = {
			rateLimits: {
				'post': { maxAttempts: 5, timeWindow: 60000 }, // 5 posts per minute
				'message': { maxAttempts: 10, timeWindow: 60000 }, // 10 messages per minute
				'search': { maxAttempts: 10, timeWindow: 30000 } // 10 searches per 30 seconds
			},
			validateForms: true,
			trackUserActions: true,
			...options
		};

		// Initialize rate limit tracking
		this.actionTracking = {};

		// Initialize form validation
		if (this.options.validateForms) {
			this.initFormValidation();
		}

		// Initialize action tracking
		if (this.options.trackUserActions) {
			this.initActionTracking();
		}
	}

	/**
	 * Initialize form validation for all forms with data-validate attribute
	 */
	initFormValidation() {
		// Find all forms that need validation
		const forms = document.querySelectorAll('form[data-validate="true"]');

		// Add validation to each form
		forms.forEach(form => {
			form.addEventListener('submit', (event) => {
				// Prevent form submission if validation fails
				if (!this.validateForm(form)) {
					event.preventDefault();
				}
			});
		});
	}

	/**
	 * Initialize action tracking for rate limiting
	 */
	initActionTracking() {
		// Track form submissions for rate limiting
		document.addEventListener('submit', (event) => {
			const form = event.target;

			// Get the action type from the form
			const actionType = form.getAttribute('data-action-type');

			// If the form has an action type, track it
			if (actionType && this.options.rateLimits[actionType]) {
				// Check if the action is rate limited
				if (this.isRateLimited(actionType)) {
					// Prevent form submission if rate limited
					event.preventDefault();

					// Show rate limit message
					this.showRateLimitMessage(form, actionType);
				} else {
					// Track the action
					this.trackAction(actionType);
				}
			}
		});

		// Track button clicks for rate limiting
		document.addEventListener('click', (event) => {
			// Check if the clicked element is a button or link with data-action-type
			const element = event.target.closest('[data-action-type]');

			if (element) {
				const actionType = element.getAttribute('data-action-type');

				// If the element has an action type, track it
				if (actionType && this.options.rateLimits[actionType]) {
					// Check if the action is rate limited
					if (this.isRateLimited(actionType)) {
						// Prevent default action if rate limited
						event.preventDefault();

						// Show rate limit message
						this.showRateLimitMessage(element, actionType);
					} else {
						// Track the action
						this.trackAction(actionType);
					}
				}
			}
		});
	}

	/**
	 * Track an action for rate limiting
	 *
	 * @param {string} actionType The type of action
	 */
	trackAction(actionType) {
		// Initialize tracking for this action type if it doesn't exist
		if (!this.actionTracking[actionType]) {
			this.actionTracking[actionType] = [];
		}

		// Add the current timestamp to the action tracking
		this.actionTracking[actionType].push(Date.now());

		// Store in session storage for persistence across page loads
		this.saveActionTracking();
	}

	/**
	 * Save action tracking to session storage
	 */
	saveActionTracking() {
		sessionStorage.setItem('actionTracking', JSON.stringify(this.actionTracking));
	}

	/**
	 * Load action tracking from session storage
	 */
	loadActionTracking() {
		const tracking = sessionStorage.getItem('actionTracking');

		if (tracking) {
			this.actionTracking = JSON.parse(tracking);
		}
	}

	/**
	 * Check if an action is rate limited
	 *
	 * @param {string} actionType The type of action
	 * @return {boolean} True if the action is rate limited, false otherwise
	 */
	isRateLimited(actionType) {
		// Load the latest action tracking from session storage
		this.loadActionTracking();

		// Get the rate limit settings for this action type
		const rateLimit = this.options.rateLimits[actionType];

		if (!rateLimit) {
			return false;
		}

		// Get the action history for this action type
		const actionHistory = this.actionTracking[actionType] || [];

		// Get the current time
		const now = Date.now();

		// Filter out actions outside the time window
		const recentActions = actionHistory.filter(timestamp => {
			return now - timestamp < rateLimit.timeWindow;
		});

		// Update the action history
		this.actionTracking[actionType] = recentActions;
		this.saveActionTracking();

		// Check if the number of recent actions exceeds the maximum
		return recentActions.length >= rateLimit.maxAttempts;
	}

	/**
	 * Show a rate limit message on an element
	 *
	 * @param {HTMLElement} element The element to show the message on
	 * @param {string} actionType The type of action
	 */
	showRateLimitMessage(element, actionType) {
		// Create a message element if it doesn't exist
		let messageElement = element.nextElementSibling;

		if (!messageElement || !messageElement.classList.contains('rate-limit-message')) {
			messageElement = document.createElement('div');
			messageElement.classList.add('rate-limit-message', 'error-message');
			element.parentNode.insertBefore(messageElement, element.nextSibling);
		}

		// Get the rate limit settings for this action type
		const rateLimit = this.options.rateLimits[actionType];

		// Calculate the time remaining until the rate limit resets
		const actionHistory = this.actionTracking[actionType] || [];
		const now = Date.now();
		const oldestAction = Math.min(...actionHistory);
		const timeRemaining = Math.ceil((oldestAction + rateLimit.timeWindow - now) / 1000);

		// Set the message text
		messageElement.textContent = `You're doing that too frequently. Please wait ${timeRemaining} seconds before trying again.`;
	}

	/**
	 * Validate a form
	 *
	 * @param {HTMLFormElement} form The form to validate
	 * @return {boolean} True if the form is valid, false otherwise
	 */
	validateForm(form) {
		// Get all form elements that need validation
		const elements = form.querySelectorAll('[data-validate]');

		// Track whether the form is valid
		let isValid = true;

		// Validate each element
		elements.forEach(element => {
			// Clear previous error messages
			this.clearValidationError(element);

			// Get the validation type
			const validationType = element.getAttribute('data-validate');

			// Validate the element
			if (!this.validateElement(element, validationType)) {
				isValid = false;
			}
		});

		return isValid;
	}

	/**
	 * Validate a single form element
	 *
	 * @param {HTMLElement} element The element to validate
	 * @param {string} validationType The type of validation to perform
	 * @return {boolean} True if the element is valid, false otherwise
	 */
	validateElement(element, validationType) {
		const value = element.value.trim();

		// Required field validation
		if (validationType.includes('required') && value === '') {
			this.showValidationError(element, 'This field is required');
			return false;
		}

		// Email validation
		if (validationType.includes('email') && value !== '') {
			const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

			if (!emailRegex.test(value)) {
				this.showValidationError(element, 'Please enter a valid email address');
				return false;
			}
		}

		// URL validation
		if (validationType.includes('url') && value !== '') {
			try {
				new URL(value);
			} catch (e) {
				this.showValidationError(element, 'Please enter a valid URL');
				return false;
			}
		}

		// Minimum length validation
		if (validationType.includes('minlength') && value !== '') {
			const minLength = parseInt(element.getAttribute('data-minlength') || '0');

			if (value.length < minLength) {
				this.showValidationError(element, `Please enter at least ${minLength} characters`);
				return false;
			}
		}

		// Maximum length validation
		if (validationType.includes('maxlength') && value !== '') {
			const maxLength = parseInt(element.getAttribute('data-maxlength') || '0');

			if (value.length > maxLength) {
				this.showValidationError(element, `Please enter no more than ${maxLength} characters`);
				return false;
			}
		}

		// Custom pattern validation
		if (validationType.includes('pattern') && value !== '') {
			const pattern = new RegExp(element.getAttribute('data-pattern') || '');

			if (!pattern.test(value)) {
				this.showValidationError(element, element.getAttribute('data-pattern-message') || 'Please enter a valid value');
				return false;
			}
		}

		// Spam keyword validation
		if (validationType.includes('spam-check') && value !== '') {
			const spamKeywords = element.getAttribute('data-spam-keywords');

			if (spamKeywords) {
				const keywords = spamKeywords.split(',');

				for (const keyword of keywords) {
					if (value.toLowerCase().includes(keyword.toLowerCase().trim())) {
						this.showValidationError(element, 'Your content contains inappropriate terms');
						return false;
					}
				}
			}
		}

		return true;
	}

	/**
	 * Show a validation error message for an element
	 *
	 * @param {HTMLElement} element The element with the error
	 * @param {string} message The error message
	 */
	showValidationError(element, message) {
		// Add error class to the element
		element.classList.add('validation-error');

		// Create error message element
		const errorElement = document.createElement('div');
		errorElement.classList.add('error-message');
		errorElement.textContent = message;

		// Add the error message after the element
		element.parentNode.insertBefore(errorElement, element.nextSibling);
	}

	/**
	 * Clear validation error for an element
	 *
	 * @param {HTMLElement} element The element to clear errors for
	 */
	clearValidationError(element) {
		// Remove error class from the element
		element.classList.remove('validation-error');

		// Find and remove any error message
		const nextElement = element.nextElementSibling;

		if (nextElement && nextElement.classList.contains('error-message')) {
			nextElement.remove();
		}
	}

	/**
	 * Sanitize text input to prevent XSS attacks
	 *
	 * @param {string} text The text to sanitize
	 * @param {boolean} allowHtml Whether to allow some HTML tags
	 * @return {string} The sanitized text
	 */
	sanitizeText(text, allowHtml = false) {
		// Create a temporary div element
		const tempDiv = document.createElement('div');

		// Set the text as the div content
		tempDiv.textContent = text;

		// Return the sanitized text
		if (allowHtml) {
			// Use DOMPurify or similar library for more robust HTML sanitization
			// For now, we'll use a simple approach
			return tempDiv.innerHTML;
		} else {
			return tempDiv.textContent;
		}
	}

	/**
	 * Check if a string contains potential spam based on patterns
	 *
	 * @param {string} text The text to check
	 * @return {boolean} True if the text might be spam, false otherwise
	 */
	containsSpam(text) {
		// Convert to lowercase for case-insensitive matching
		const lowerText = text.toLowerCase();

		// Common spam patterns
		const spamPatterns = [
			// Too many URLs
			/((https?:\/\/|www\.)[^\s]+){5,}/i,
			// Suspicious TLDs
			/https?:\/\/.*\.(xyz|top|loan|work|click|gq|ml|ga|cf|tk)\b/i,
			// Excessive use of certain keywords
			/\b(free|discount|offer|buy|sell|promotion|deal|limited\s+time)\b.*\1.*\1/i,
			// Excessive capitalization
			/[A-Z]{10,}/
		];

		// Check for matches
		for (const pattern of spamPatterns) {
			if (pattern.test(text)) {
				return true;
			}
		}

		// Keyword density check
		const spamKeywords = ['free', 'discount', 'limited time', 'offer', 'click here', 'buy now', 'act now'];
		let keywordCount = 0;

		for (const keyword of spamKeywords) {
			// Count occurrences of keyword
			const regex = new RegExp('\\b' + keyword + '\\b', 'gi');
			const matches = text.match(regex);

			if (matches) {
				keywordCount += matches.length;
			}
		}

		// If there are too many spam keywords relative to text length
		const wordCount = text.split(/\s+/).length;
		if (wordCount > 0 && keywordCount / wordCount > 0.2) {
			return true;
		}

		return false;
	}

	/**
	 * Throttle a function to limit how often it can be called
	 *
	 * @param {Function} callback The function to throttle
	 * @param {number} delay The minimum time between calls in milliseconds
	 * @return {Function} The throttled function
	 */
	throttle(callback, delay) {
		let lastCall = 0;

		return function(...args) {
			const now = Date.now();

			if (now - lastCall >= delay) {
				lastCall = now;
				return callback.apply(this, args);
			}
		};
	}

	/**
	 * Add security headers to a fetch request
	 *
	 * @param {Object} options The fetch options
	 * @return {Object} The updated fetch options with security headers
	 */
	addSecurityHeaders(options = {}) {
		// Default options
		options.headers = options.headers || {};

		// Add CSRF token if available
		const csrfToken = document.querySelector('meta[name="csrf-token"]')?.getAttribute('content');

		if (csrfToken) {
			options.headers['X-CSRF-Token'] = csrfToken;
		}

		// Add other security headers
		options.headers['X-Requested-With'] = 'XMLHttpRequest';

		return options;
	}

	/**
	 * Secure fetch wrapper that adds security headers
	 *
	 * @param {string} url The URL to fetch
	 * @param {Object} options The fetch options
	 * @return {Promise} The fetch promise
	 */
	secureFetch(url, options = {}) {
		// Add security headers
		const secureOptions = this.addSecurityHeaders(options);

		// Make the fetch request
		return fetch(url, secureOptions);
	}
}

// Initialize the security client
document.addEventListener('DOMContentLoaded', () => {
	// Create a global security client instance
	window.securityClient = new SecurityClient();

	// Initialize validation for dynamic forms
	document.addEventListener('form-initialized', (event) => {
		if (event.detail && event.detail.form) {
			window.securityClient.validateForm(event.detail.form);
		}
	});
});

// CSS styles for validation messages
const style = document.createElement('style');
style.textContent = `
	.validation-error {
		border: 1px solid #ff3860 !important;
		background-color: #fff5f7;
	}

	.error-message {
		color: #ff3860;
		font-size: 0.8rem;
		margin-top: 0.25rem;
	}

	.rate-limit-message {
		background-color: #fff5f7;
		padding: 0.5rem;
		border-radius: 4px;
		margin-top: 0.5rem;
	}
`;
document.head.appendChild(style);