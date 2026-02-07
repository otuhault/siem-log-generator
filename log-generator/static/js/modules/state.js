/**
 * Centralized state management for the Log Generator UI
 * All modules share and update this state
 */

export const state = {
    logTypes: {},
    configurations: [],
    attacks: [],
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
 * Update attacks in state
 * @param {array} attacksList - Attacks array
 */
export function setAttacks(attacksList) {
    state.attacks = attacksList;
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
 * @param {string} logType - Log type key (can be 'attack:id' format)
 * @returns {string} Human-readable name
 */
export function getLogTypeName(logType) {
    // Handle attack types
    if (logType && logType.startsWith('attack:')) {
        const attackId = logType.replace('attack:', '');
        const attack = state.attacks.find(a => a.id === attackId);
        if (attack) {
            return '⚔ ' + attack.name;
        }
        return 'Attack';
    }
    // Handle sourcetypes
    if (state.logTypes[logType]) {
        return state.logTypes[logType].name;
    }
    return logType;
}
