/**
 * Centralized sourcetype configuration
 * Maps sourcetype IDs to their UI elements and form parameters
 */
export const SOURCETYPE_CONFIG = {
    'windows': {
        checkboxGroup: 'windows_sources',
        optionKey: 'sources',
        formGroups: ['windowsSourcesGroup', 'renderFormatGroup'],
        additionalFields: { render_format: 'renderFormat' }
    },
    'apache': {
        checkboxGroup: 'apache_log_types',
        optionKey: 'log_types',
        formGroups: ['apacheLogTypesGroup']
    },
    'ssh': {
        checkboxGroup: 'ssh_event_categories',
        optionKey: 'event_categories',
        formGroups: ['sshEventCategoriesGroup']
    },
    'paloalto': {
        checkboxGroup: 'paloalto_log_types',
        optionKey: 'log_types',
        formGroups: ['paloaltoLogTypesGroup']
    },
    'active_directory': {
        checkboxGroup: 'ad_event_categories',
        optionKey: 'event_categories',
        formGroups: ['adEventCategoriesGroup']
    },
    'cisco_ios': {
        checkboxGroup: 'cisco_ios_event_categories',
        optionKey: 'event_categories',
        formGroups: ['ciscoIOSEventCategoriesGroup']
    },
    'cisco_asa': {
        checkboxGroup: 'cisco_asa_event_categories',
        optionKey: 'event_categories',
        formGroups: ['ciscoASAEventCategoriesGroup']
    },
    'zscaler': {
        checkboxGroup: 'zscaler_log_types',
        optionKey: 'log_types',
        formGroups: ['zscalerLogTypesGroup']
    },
    'auditd': {
        checkboxGroup: 'auditd_event_categories',
        optionKey: 'event_categories',
        formGroups: ['auditdEventCategoriesGroup']
    },
    'fortigate': {
        checkboxGroup: 'fortigate_event_categories',
        optionKey: 'event_categories',
        formGroups: ['fortigateEventCategoriesGroup']
    },
    'sysmon': {
        checkboxGroup: 'sysmon_event_categories',
        optionKey: 'event_categories',
        formGroups: ['sysmonEventCategoriesGroup']
    }
};

/**
 * Get all form group IDs for hiding/showing
 */
export function getAllFormGroupIds() {
    const groups = new Set();
    Object.values(SOURCETYPE_CONFIG).forEach(config => {
        config.formGroups.forEach(groupId => groups.add(groupId));
    });
    return Array.from(groups);
}
