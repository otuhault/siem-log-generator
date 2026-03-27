/**
 * Form validation module
 * Provides reusable validation functions and form validation utilities
 */

import { state } from './state.js';

/**
 * Validation rules with error messages
 */
const ValidationRules = {
    required: (value, fieldName) => {
        if (!value || (typeof value === 'string' && value.trim() === '')) {
            return `${fieldName} is required`;
        }
        return null;
    },

    minLength: (value, min, fieldName) => {
        if (value && value.length < min) {
            return `${fieldName} must be at least ${min} characters`;
        }
        return null;
    },

    maxLength: (value, max, fieldName) => {
        if (value && value.length > max) {
            return `${fieldName} must not exceed ${max} characters`;
        }
        return null;
    },

    minValue: (value, min, fieldName) => {
        const num = parseFloat(value);
        if (!isNaN(num) && num < min) {
            return `${fieldName} must be at least ${min}`;
        }
        return null;
    },

    maxValue: (value, max, fieldName) => {
        const num = parseFloat(value);
        if (!isNaN(num) && num > max) {
            return `${fieldName} must not exceed ${max}`;
        }
        return null;
    },

    isNumber: (value, fieldName) => {
        if (value && isNaN(parseFloat(value))) {
            return `${fieldName} must be a valid number`;
        }
        return null;
    },

    isInteger: (value, fieldName) => {
        if (value && !Number.isInteger(parseFloat(value))) {
            return `${fieldName} must be a whole number`;
        }
        return null;
    },

    isUrl: (value, fieldName) => {
        if (!value) return null;
        // Simple URL validation - must start with http:// or https://
        const urlPattern = /^https?:\/\/[^\s/$.?#].[^\s]*$/i;
        if (!urlPattern.test(value)) {
            return `${fieldName} must be a valid URL (starting with http:// or https://)`;
        }
        return null;
    },

    isPort: (value, fieldName) => {
        const port = parseInt(value);
        if (isNaN(port) || port < 1 || port > 65535) {
            return `${fieldName} must be a valid port number (1-65535)`;
        }
        return null;
    },

    isFilePath: (value, fieldName) => {
        if (!value) return null;
        // Basic path validation - must start with / or be a relative path
        const pathPattern = /^(\/|\.\/|\.\.\/|[a-zA-Z]:[\\/])/;
        if (!pathPattern.test(value)) {
            return `${fieldName} must be a valid file path`;
        }
        return null;
    },

    isHecToken: (value, fieldName) => {
        if (!value) return null;
        // HEC token format: UUID format or similar token
        const tokenPattern = /^[a-fA-F0-9-]{8,}$/;
        if (!tokenPattern.test(value)) {
            return `${fieldName} must be a valid HEC token`;
        }
        return null;
    },

    noSpecialChars: (value, fieldName) => {
        if (!value) return null;
        // Allow alphanumeric, spaces, hyphens, underscores
        const pattern = /^[a-zA-Z0-9\s\-_]+$/;
        if (!pattern.test(value)) {
            return `${fieldName} contains invalid characters`;
        }
        return null;
    },

    isValidIndex: (value, fieldName) => {
        if (!value) return null;
        // Splunk index naming: lowercase, no special chars except underscore
        const pattern = /^[a-z][a-z0-9_]*$/;
        if (!pattern.test(value)) {
            return `${fieldName} must be lowercase and start with a letter (only letters, numbers, underscores allowed)`;
        }
        return null;
    }
};

/**
 * Show validation error on a field
 * @param {HTMLElement} field - The form field element
 * @param {string} message - Error message to display
 */
function showFieldError(field, message) {
    // Remove any existing error
    clearFieldError(field);

    // Add error class to field
    field.classList.add('validation-error');

    // Create error message element
    const errorDiv = document.createElement('div');
    errorDiv.className = 'validation-error-message';
    errorDiv.textContent = message;

    // Insert after the field (or after parent if it's in a special container)
    const insertAfter = field.closest('.checkbox-group') || field;
    insertAfter.parentNode.insertBefore(errorDiv, insertAfter.nextSibling);
}

/**
 * Clear validation error from a field
 * @param {HTMLElement} field - The form field element
 */
function clearFieldError(field) {
    field.classList.remove('validation-error');

    // Remove error message
    const parent = field.closest('.form-group');
    if (parent) {
        const errorMsg = parent.querySelector('.validation-error-message');
        if (errorMsg) {
            errorMsg.remove();
        }
    }
}

/**
 * Clear all validation errors from a form
 * @param {HTMLFormElement} form - The form element
 */
export function clearFormErrors(form) {
    form.querySelectorAll('.validation-error').forEach(field => {
        field.classList.remove('validation-error');
    });
    form.querySelectorAll('.validation-error-message').forEach(msg => {
        msg.remove();
    });
}

/**
 * Validate a single field with multiple rules
 * @param {HTMLElement} field - The form field
 * @param {Array} rules - Array of validation rule objects
 * @returns {boolean} True if valid
 */
function validateField(field, rules) {
    const value = field.value;
    const fieldName = field.dataset.fieldName || field.name || 'Field';

    for (const rule of rules) {
        let error = null;

        switch (rule.type) {
            case 'required':
                error = ValidationRules.required(value, fieldName);
                break;
            case 'minLength':
                error = ValidationRules.minLength(value, rule.value, fieldName);
                break;
            case 'maxLength':
                error = ValidationRules.maxLength(value, rule.value, fieldName);
                break;
            case 'minValue':
                error = ValidationRules.minValue(value, rule.value, fieldName);
                break;
            case 'maxValue':
                error = ValidationRules.maxValue(value, rule.value, fieldName);
                break;
            case 'isNumber':
                error = ValidationRules.isNumber(value, fieldName);
                break;
            case 'isInteger':
                error = ValidationRules.isInteger(value, fieldName);
                break;
            case 'isUrl':
                error = ValidationRules.isUrl(value, fieldName);
                break;
            case 'isPort':
                error = ValidationRules.isPort(value, fieldName);
                break;
            case 'isFilePath':
                error = ValidationRules.isFilePath(value, fieldName);
                break;
            case 'isHecToken':
                error = ValidationRules.isHecToken(value, fieldName);
                break;
            case 'noSpecialChars':
                error = ValidationRules.noSpecialChars(value, fieldName);
                break;
            case 'isValidIndex':
                error = ValidationRules.isValidIndex(value, fieldName);
                break;
            case 'custom':
                error = rule.validate(value, fieldName);
                break;
        }

        if (error) {
            showFieldError(field, error);
            return false;
        }
    }

    clearFieldError(field);
    return true;
}

/**
 * Validate the Sender form
 * @param {HTMLFormElement} form - The sender form
 * @returns {object} { isValid: boolean, errors: string[] }
 */
export function validateSenderForm(form) {
    clearFormErrors(form);
    const errors = [];
    let isValid = true;

    // Sender Name
    const nameField = form.querySelector('#senderName');
    if (!validateField(nameField, [
        { type: 'required' },
        { type: 'minLength', value: 2 },
        { type: 'maxLength', value: 100 }
    ])) {
        isValid = false;
        errors.push('Invalid sender name');
    }

    // Log Type
    const logTypeField = form.querySelector('#logType');
    if (!validateField(logTypeField, [
        { type: 'required' }
    ])) {
        isValid = false;
        errors.push('Please select a log type');
    }

    const logType = logTypeField.value;
    const isAttack = !!(logType && state.attackTypes[logType]);

    // Frequency (only for non-attacks)
    if (!isAttack) {
        const frequencyField = form.querySelector('#frequency');
        if (frequencyField && !frequencyField.disabled) {
            if (!validateField(frequencyField, [
                { type: 'required' },
                { type: 'isNumber' },
                { type: 'minValue', value: 0.1 },
                { type: 'maxValue', value: 1000 }
            ])) {
                isValid = false;
                errors.push('Invalid frequency');
            }
        }
    }

    // Attack options
    if (isAttack) {
        const eventsField = form.querySelector('#attackEventsCount');
        if (!validateField(eventsField, [
            { type: 'required' },
            { type: 'isInteger' },
            { type: 'minValue', value: 1 },
            { type: 'maxValue', value: 100000 }
        ])) {
            isValid = false;
            errors.push('Invalid events count');
        }

        const durationField = form.querySelector('#attackDuration');
        if (!validateField(durationField, [
            { type: 'required' },
            { type: 'isInteger' },
            { type: 'minValue', value: 1 },
            { type: 'maxValue', value: 3600 }
        ])) {
            isValid = false;
            errors.push('Invalid duration');
        }
    }

    // Destination
    const destinationType = form.querySelector('input[name="destination_type"]:checked')?.value;

    if (destinationType === 'file') {
        const destField = form.querySelector('#destination');
        if (!validateField(destField, [
            { type: 'required' },
            { type: 'isFilePath' }
        ])) {
            isValid = false;
            errors.push('Invalid file path');
        }
    } else if (destinationType === 'configuration') {
        const configField = form.querySelector('#configurationSelect');
        if (!validateField(configField, [
            { type: 'required' }
        ])) {
            isValid = false;
            errors.push('Please select a HEC destination');
        }
    } else if (destinationType === 'syslog') {
        const hostField = form.querySelector('#syslogHost');
        if (!validateField(hostField, [
            { type: 'required' }
        ])) {
            isValid = false;
            errors.push('Please enter a syslog host');
        }
    }

    // Windows sources validation
    if (logType === 'windows') {
        const checkedSources = form.querySelectorAll('input[name="windows_sources"]:checked');
        if (checkedSources.length === 0) {
            isValid = false;
            errors.push('Please select at least one Windows source');
            const firstCheckbox = form.querySelector('input[name="windows_sources"]');
            if (firstCheckbox) {
                showFieldError(firstCheckbox, 'Select at least one source');
            }
        }
    }

    // Apache log types validation
    if (logType === 'apache') {
        const checkedTypes = form.querySelectorAll('input[name="apache_log_types"]:checked');
        if (checkedTypes.length === 0) {
            isValid = false;
            errors.push('Please select at least one Apache log type');
        }
    }

    // SSH categories validation
    if (logType === 'ssh') {
        const checkedCategories = form.querySelectorAll('input[name="ssh_event_categories"]:checked');
        if (checkedCategories.length === 0) {
            isValid = false;
            errors.push('Please select at least one SSH event category');
        }
    }

    // Palo Alto log types validation
    if (logType === 'paloalto') {
        const checkedTypes = form.querySelectorAll('input[name="paloalto_log_types"]:checked');
        if (checkedTypes.length === 0) {
            isValid = false;
            errors.push('Please select at least one Palo Alto log type');
        }
    }

    return { isValid, errors };
}

/**
 * Validate the Configuration (HEC) form
 * @param {HTMLFormElement} form - The configuration form
 * @returns {object} { isValid: boolean, errors: string[] }
 */
export function validateConfigurationForm(form) {
    clearFormErrors(form);
    const errors = [];
    let isValid = true;

    // Configuration Name
    const nameField = form.querySelector('#configurationName');
    if (!validateField(nameField, [
        { type: 'required' },
        { type: 'minLength', value: 2 },
        { type: 'maxLength', value: 100 }
    ])) {
        isValid = false;
        errors.push('Invalid configuration name');
    }

    // URL
    const urlField = form.querySelector('#configurationUrl');
    if (!validateField(urlField, [
        { type: 'required' },
        { type: 'isUrl' }
    ])) {
        isValid = false;
        errors.push('Invalid URL');
    }

    // Port
    const portField = form.querySelector('#configurationPort');
    if (!validateField(portField, [
        { type: 'required' },
        { type: 'isPort' }
    ])) {
        isValid = false;
        errors.push('Invalid port');
    }

    // Token
    const tokenField = form.querySelector('#configurationToken');
    if (!validateField(tokenField, [
        { type: 'required' },
        { type: 'minLength', value: 8 }
    ])) {
        isValid = false;
        errors.push('Invalid HEC token');
    }

    // Optional fields with validation if provided
    const indexField = form.querySelector('#configurationIndex');
    if (indexField.value) {
        if (!validateField(indexField, [
            { type: 'isValidIndex' }
        ])) {
            isValid = false;
            errors.push('Invalid index name');
        }
    }

    return { isValid, errors };
}

/**
 * Setup real-time validation on form fields
 * @param {HTMLFormElement} form - The form to setup
 * @param {Function} validateFn - The validation function to use
 */
export function setupRealtimeValidation(form, validateFn) {
    const inputs = form.querySelectorAll('input, select, textarea');

    inputs.forEach(input => {
        // Validate on blur
        input.addEventListener('blur', () => {
            validateFn(form);
        });

        // Clear error on input
        input.addEventListener('input', () => {
            clearFieldError(input);
        });
    });
}
