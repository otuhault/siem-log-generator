/**
 * Centralized state management for the Log Generator UI
 * All modules share and update this state
 */

export const state = {
    logTypes: {},
    configurations: [],
    attackTypes: {}
};

/**
 * Update log types in state
 * @param {object} types - Log types object
 */
export function setLogTypes(types) {
    state.logTypes = types;
}

/**
 * Update configurations in state
 * @param {array} configs - Configurations array
 */
export function setConfigurations(configs) {
    state.configurations = configs;
}

/**
 * Update attack types in state
 * @param {object} types - Attack types object
 */
export function setAttackTypes(types) {
    state.attackTypes = types;
}

/**
 * Get log type name from key
 * @param {string} logType - Log type key
 * @returns {string} Human-readable name
 */
export function getLogTypeName(logType) {
    // Handle attack types (direct key lookup)
    if (state.attackTypes[logType]) {
        return state.attackTypes[logType].name;
    }
    // Handle sourcetypes
    if (state.logTypes[logType]) {
        return state.logTypes[logType].name;
    }
    return logType;
}
