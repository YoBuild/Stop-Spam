# JavaScript Security Validator - Standalone Guide

## Overview

A lightweight, framework-agnostic JavaScript library for client-side form security and bot detection. Works independently or as part of the Yohns Security Framework.

## Features

- 🤖 **Bot Detection** - Behavioral analysis and pattern recognition
- ⏱️ **Timing Analysis** - Form interaction and submission timing validation
- 🔒 **CSRF Protection** - Automatic token management
- 🍯 **Honeypot Integration** - Hidden field validation
- 🛡️ **XSS Prevention** - Real-time content sanitization
- 📊 **Analytics** - Detailed security metrics and reporting
- 🎯 **Performance Optimized** - Efficient event handling and memory management

## Installation

### Option 1: Direct Include

```html
<script src="path/to/security-validator.js"></script>
```

### Option 2: Module Import

```javascript
// ES6 Modules
import SecurityValidator from './security-validator.js';

// CommonJS
const SecurityValidator = require('./security-validator.js');

// AMD
define(['security-validator'], function(SecurityValidator) {
    // Use SecurityValidator
});
```

### Option 3: CDN (Future)

```html
<script src="https://cdn.jsdelivr.net/npm/yohns-security-validator@1.0.0/dist/security-validator.min.js"></script>
```

## Quick Start

### Basic Usage

```html
<!DOCTYPE html>
<html>
<head>
    <meta name="csrf-token" content="your-csrf-token-here">
</head>
<body>
    <!-- Add data-validate="true" to enable automatic security -->
    <form id="my-form" data-validate="true" method="post">
        <input type="text" name="name" placeholder="Your Name" required>
        <textarea name="message" placeholder="Message" required></textarea>
        <button type="submit">Submit</button>
    </form>

    <script src="security-validator.js"></script>
    <!-- Library auto-initializes -->
</body>
</html>
```

### Manual Initialization

```javascript
// Custom configuration
const validator = new SecurityValidator({
    enableBotDetection: true,
    enableTimingAnalysis: true,
    debugMode: true
});

// Initialize specific form
const form = document.getElementById('my-form');
validator.initializeForm(form);
```

## Configuration Options

### Complete Options Reference

```javascript
const options = {
    // === Core Features ===
    enableBotDetection: true,           // Enable behavioral bot detection
    enableTimingAnalysis: true,         // Enable form timing validation
    enableCSRFValidation: true,         // Enable CSRF token management

    // === Timing Thresholds ===
    minFormTime: 2000,                  // Minimum form interaction time (ms)
    maxFormTime: 3600000,              // Maximum form session time (1 hour in ms)
    perfectTimingPenalty: 20,          // Penalty score for "perfect" timing patterns

    // === Bot Detection Thresholds ===
    botDetectionThreshold: 60,          // Bot probability threshold (0-100)
    thresholds: {
        minMouseMovements: 5,           // Minimum expected mouse movements
        minKeystrokes: 3,               // Minimum expected keystrokes
        minFocusEvents: 1,              // Minimum expected focus events
        maxSubmissionSpeed: 1000        // Maximum form submission speed (ms)
    },

    // === Field Configuration ===
    honeypotFields: [                   // Honeypot field names to check
        'website', 'url', 'homepage',
        'email_confirm', 'phone_confirm'
    ],
    csrfTokenName: 'csrf_token',        // CSRF hidden field name
    csrfMetaName: 'csrf-token',         // CSRF meta tag name

    // === Error Handling ===
    showUserErrors: true,               // Show validation errors to users
    errorDisplayTime: 5000,             // Error message display duration (ms)
    errorClassName: 'security-error',   // CSS class for error messages

    // === Performance Options ===
    eventSampling: 1.0,                 // Event sampling rate (0.1 = 10% of events)
    batchSize: 50,                      // Event batch processing size
    maxDataPoints: 1000,                // Maximum stored data points
    cleanupInterval: 60000,             // Memory cleanup interval (ms)

    // === Debug and Analytics ===
    debugMode: false,                   // Enable console logging
    collectMetrics: true,               // Collect usage metrics
    reportingEndpoint: null,            // URL for security event reporting

    // === Advanced Options ===
    enableWebWorker: false,             // Use Web Worker for analysis (if available)
    enableMachineLearning: false,       // Enable ML-based detection (requires model)
    modelPath: '/models/bot-detection.json', // Path to ML model

    // === Browser Compatibility ===
    enablePolyfills: true,              // Load polyfills for older browsers
    fallbackMode: false,                // Use basic validation only

    // === Custom Validation ===
    customValidators: {},               // Custom field validators
    customBotRules: [],                 // Custom bot detection rules

    // === Form Behavior ===
    autoInitialize: true,               // Auto-initialize forms with data-validate="true"
    preventSubmitOnFail: true,          // Prevent form submission on validation failure
    allowBypass: false,                 // Allow bypass with special parameter
    bypassParameter: 'security_bypass', // Parameter name for bypass

    // === Event Configuration ===
    trackMouseMovement: true,           // Track mouse movement events
    trackKeystrokes: true,              // Track keystroke events
    trackFocusEvents: true,             // Track focus/blur events
    trackScrollEvents: true,            // Track scroll events
    trackClickEvents: true,             // Track click events
    trackResizeEvents: true,            // Track window resize events

    // === Security Levels ===
    securityLevel: 'normal',            // 'low', 'normal', 'high', 'paranoid'

    // === Localization ===
    language: 'en',                     // Language for error messages
    messages: {                         // Custom error messages
        botDetected: 'Automated behavior detected',
        formTooFast: 'Form submitted too quickly',
        formExpired: 'Form session has expired',
        honeypotFilled: 'Invalid form submission',
        csrfInvalid: 'Security token invalid',
        generalError: 'Validation failed'
    }
};

// Initialize with options
const validator = new SecurityValidator(options);
```

### Security Level Presets

```javascript
// Predefined security configurations
const securityLevels = {
    low: {
        enableBotDetection: true,
        botDetectionThreshold: 80,
        minFormTime: 1000,
        thresholds: {
            minMouseMovements: 1,
            minKeystrokes: 1,
            minFocusEvents: 0
        }
    },

    normal: {
        enableBotDetection: true,
        botDetectionThreshold: 60,
        minFormTime: 2000,
        thresholds: {
            minMouseMovements: 5,
            minKeystrokes: 3,
            minFocusEvents: 1
        }
    },

    high: {
        enableBotDetection: true,
        botDetectionThreshold: 40,
        minFormTime: 3000,
        thresholds: {
            minMouseMovements: 10,
            minKeystrokes: 5,
            minFocusEvents: 2
        }
    },

    paranoid: {
        enableBotDetection: true,
        botDetectionThreshold: 20,
        minFormTime: 5000,
        thresholds: {
            minMouseMovements: 20,
            minKeystrokes: 10,
            minFocusEvents: 3
        },
        enableMachineLearning: true,
        collectMetrics: true
    }
};

// Use preset
const validator = new SecurityValidator({
    securityLevel: 'high'
});
```

## Setup Methods

### Method 1: Automatic Initialization

```html
<!-- Forms with data-validate="true" are automatically secured -->
<form data-validate="true" method="post">
    <!-- Form fields -->
</form>

<script src="security-validator.js"></script>
<!-- Auto-initializes on DOMContentLoaded -->
```

### Method 2: Manual Global Initialization

```javascript
// Initialize all forms manually
document.addEventListener('DOMContentLoaded', function() {
    const validator = SecurityValidator.init({
        debugMode: true,
        securityLevel: 'high'
    });

    // Validator is now available as window.securityValidator
    console.log('Security validator ready:', window.securityValidator);
});
```

### Method 3: Per-Form Initialization

```javascript
// Initialize specific forms
const validator = new SecurityValidator();

document.querySelectorAll('.secure-form').forEach(form => {
    validator.initializeForm(form);
});

// Or initialize single form
const contactForm = document.getElementById('contact-form');
validator.initializeForm(contactForm);
```

### Method 4: Programmatic Control

```javascript
// Full control over initialization
const validator = new SecurityValidator({
    autoInitialize: false  // Disable auto-initialization
});

// Custom form selection logic
function initializeSecureForms() {
    const forms = document.querySelectorAll('form[action*="/secure/"]');
    forms.forEach(form => {
        if (shouldSecureForm(form)) {
            validator.initializeForm(form);
        }
    });
}

function shouldSecureForm(form) {
    // Custom logic to determine if form needs security
    return form.querySelector('input[type="password"]') ||
           form.querySelector('input[name="email"]');
}

// Initialize when ready
document.addEventListener('DOMContentLoaded', initializeSecureForms);
```

### Method 5: AJAX/SPA Integration

```javascript
// For Single Page Applications
class SPASecurityManager {
    constructor() {
        this.validator = new SecurityValidator({
            autoInitialize: false
        });
    }

    // Call when new content is loaded
    initializeNewContent(container) {
        const forms = container.querySelectorAll('form');
        forms.forEach(form => {
            this.validator.initializeForm(form);
        });
    }

    // Call before navigation
    cleanup() {
        this.validator.reset();
    }
}

// Usage in SPA
const spaManager = new SPASecurityManager();

// After loading new page content
spaManager.initializeNewContent(document.getElementById('main-content'));
```

### Method 6: Framework Integration

#### React Integration

```jsx
import { useEffect, useRef } from 'react';
import SecurityValidator from './security-validator';

function SecureForm({ onSubmit, children }) {
    const formRef = useRef();
    const validatorRef = useRef();

    useEffect(() => {
        if (formRef.current && !validatorRef.current) {
            validatorRef.current = new SecurityValidator({
                autoInitialize: false,
                debugMode: process.env.NODE_ENV === 'development'
            });

            validatorRef.current.initializeForm(formRef.current);
        }

        return () => {
            if (validatorRef.current) {
                validatorRef.current.reset();
            }
        };
    }, []);

    const handleSubmit = (e) => {
        if (validatorRef.current) {
            const validation = validatorRef.current.validateForm(formRef.current);
            if (!validation.valid) {
                e.preventDefault();
                return;
            }
        }
        onSubmit(e);
    };

    return (
        <form ref={formRef} onSubmit={handleSubmit}>
            {children}
        </form>
    );
}
```

#### Vue Integration

```vue
<template>
    <form ref="form" @submit="handleSubmit">
        <slot></slot>
    </form>
</template>

<script>
import SecurityValidator from './security-validator';

export default {
    name: 'SecureForm',
    data() {
        return {
            validator: null
        };
    },
    mounted() {
        this.validator = new SecurityValidator({
            autoInitialize: false,
            debugMode: this.$development
        });

        this.validator.initializeForm(this.$refs.form);
    },
    beforeUnmount() {
        if (this.validator) {
            this.validator.reset();
        }
    },
    methods: {
        handleSubmit(event) {
            if (this.validator) {
                const validation = this.validator.validateForm(this.$refs.form);
                if (!validation.valid) {
                    event.preventDefault();
                    return;
                }
            }
            this.$emit('submit', event);
        }
    }
};
</script>
```

#### Angular Integration

```typescript
import { Component, ElementRef, OnInit, OnDestroy } from '@angular/core';
import { SecurityValidator } from './security-validator';

@Component({
    selector: 'app-secure-form',
    template: `
        <form #form (ngSubmit)="handleSubmit($event)">
            <ng-content></ng-content>
        </form>
    `
})
export class SecureFormComponent implements OnInit, OnDestroy {
    private validator: SecurityValidator;

    constructor(private elementRef: ElementRef) {}

    ngOnInit() {
        const form = this.elementRef.nativeElement.querySelector('form');

        this.validator = new SecurityValidator({
            autoInitialize: false,
            debugMode: !environment.production
        });

        this.validator.initializeForm(form);
    }

    ngOnDestroy() {
        if (this.validator) {
            this.validator.reset();
        }
    }

    handleSubmit(event: Event) {
        if (this.validator) {
            const form = event.target as HTMLFormElement;
            const validation = this.validator.validateForm(form);

            if (!validation.valid) {
                event.preventDefault();
                return;
            }
        }
    }
}
```

## Advanced Configuration

### Custom Bot Detection Rules

```javascript
const validator = new SecurityValidator({
    customBotRules: [
        {
            name: 'perfectTiming',
            check: (data) => {
                // Detect suspiciously perfect timing
                return data.formTime % 1000 === 0;
            },
            score: 30,
            message: 'Perfect timing detected'
        },
        {
            name: 'noScrolling',
            check: (data) => {
                // Detect forms submitted without scrolling
                return data.scrollEvents === 0 && data.formHeight > window.innerHeight;
            },
            score: 25,
            message: 'No scrolling on long form'
        }
    ]
});
```

### Custom Field Validators

```javascript
const validator = new SecurityValidator({
    customValidators: {
        email: (value) => {
            const valid = /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(value);
            return {
                valid: valid,
                message: valid ? '' : 'Please enter a valid email address'
            };
        },

        phone: (value) => {
            const cleaned = value.replace(/\D/g, '');
            const valid = cleaned.length >= 10 && cleaned.length <= 15;
            return {
                valid: valid,
                message: valid ? '' : 'Please enter a valid phone number'
            };
        },

        strongPassword: (value) => {
            const hasUpper = /[A-Z]/.test(value);
            const hasLower = /[a-z]/.test(value);
            const hasNumber = /\d/.test(value);
            const hasSpecial = /[!@#$%^&*]/.test(value);
            const isLongEnough = value.length >= 8;

            const valid = hasUpper && hasLower && hasNumber && hasSpecial && isLongEnough;

            return {
                valid: valid,
                message: valid ? '' : 'Password must contain uppercase, lowercase, number, special character, and be 8+ characters'
            };
        }
    }
});
```

### Event Reporting Configuration

```javascript
const validator = new SecurityValidator({
    reportingEndpoint: '/api/security-events',
    collectMetrics: true,

    // Custom event filtering
    shouldReportEvent: (eventType, data) => {
        // Only report high-severity events
        return data.score >= 50;
    },

    // Custom event data
    customEventData: () => ({
        sessionId: getSessionId(),
        userId: getCurrentUserId(),
        pageUrl: window.location.href,
        referrer: document.referrer
    })
});
```

### Performance Optimization

```javascript
const validator = new SecurityValidator({
    // Reduce event processing for better performance
    eventSampling: 0.5,          // Process 50% of events
    batchSize: 100,              // Larger batch size
    maxDataPoints: 500,          // Limit stored data
    cleanupInterval: 30000,      // More frequent cleanup

    // Disable expensive features if needed
    enableWebWorker: true,       // Offload to worker thread
    enableMachineLearning: false, // Disable ML if not needed

    // Optimize event tracking
    trackMouseMovement: true,
    trackKeystrokes: true,
    trackScrollEvents: false,    // Disable if not needed
    trackResizeEvents: false     // Disable if not needed
});
```

## API Reference

### Core Methods

```javascript
// Constructor
const validator = new SecurityValidator(options);

// Form management
validator.initializeForm(formElement);
validator.validateForm(formElement);
validator.reset();

// Security analysis
const securityInfo = validator.getSecurityInfo();
const botAnalysis = validator.detectBotBehavior(formTime);
const xssCheck = validator.detectXSS(content);

// Utility methods
validator.log(message);
validator.showValidationError(form, message);
validator.addCSRFToken(form);

// Static methods
SecurityValidator.init(options);
```

### Event Callbacks

```javascript
const validator = new SecurityValidator({
    // Event callbacks
    onFormInitialized: (form) => {
        console.log('Form initialized:', form.id);
    },

    onValidationFailed: (form, result) => {
        console.log('Validation failed:', result);
        // Custom handling
    },

    onBotDetected: (form, analysis) => {
        console.log('Bot detected:', analysis);
        // Send alert, block user, etc.
    },

    onSecurityEvent: (eventType, data) => {
        console.log('Security event:', eventType, data);
        // Custom analytics
    }
});
```

This standalone guide provides everything needed to implement the JavaScript Security Validator independently of the PHP framework, with comprehensive configuration options and setup methods for various environments and use cases.