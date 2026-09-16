#!/usr/bin/env python3
"""
Log Generator - SIEM Testing Tool
Main application with web interface for managing log senders
"""

from flask import Flask, render_template, request, jsonify
import json
import os
from datetime import datetime
import log_senders
from log_senders import SenderManager
from configuration_manager import ConfigurationManager
from simulation_manager import SimulationManager
from environment_manager import (EnvironmentManager,
    ENTITY_TYPES, ENTITY_TYPE_LABELS,
    ACCOUNT_TYPES, ACCOUNT_TYPE_LABELS)
from ta_registry import TA_REGISTRY, list_tas, get_ta, get_sourcetype_info
from syslog_framing import delivery_description
from network_pools import NetworkPoolManager
from a_i_mapping import AIMappingManager
from syslog_destinations import SyslogDestinationsManager

app = Flask(__name__)
app.config['SECRET_KEY'] = 'dev-key-change-in-production'

# Initialize managers — order matters: config_mgr & syslog_dests_mgr before SenderManager
configuration_manager = ConfigurationManager()
syslog_destinations_manager = SyslogDestinationsManager()
sender_manager = SenderManager(
    config_mgr=configuration_manager,
    syslog_dests_mgr=syslog_destinations_manager,
)
simulation_manager = SimulationManager()

# Nothing generated before this process started is still running. Simulations
# first: stopping one deletes its own senders, which the second call would
# otherwise only disable.
simulation_manager.reconcile_after_restart(sender_manager)
sender_manager.reconcile_after_restart()

# The one environment every sender and attack reads. A second instance here used
# to take the API's writes while log_senders kept the copy it loaded at import,
# so an entity or account created in the UI reached no sender and no attack
# until the application restarted.
env_manager = log_senders.environment_manager()
network_pool_manager = NetworkPoolManager()
ai_mapping_manager = AIMappingManager()

@app.route('/')
def index():
    """Main dashboard"""
    return render_template('index.html')

@app.route('/api/senders', methods=['GET'])
def get_senders():
    """Get all senders"""
    return jsonify(sender_manager.get_all_senders())

@app.route('/api/senders/<sender_id>', methods=['GET'])
def get_sender(sender_id):
    """Get a specific sender"""
    sender = sender_manager.get_sender(sender_id)
    if sender:
        return jsonify(sender)
    return jsonify({'error': 'Sender not found'}), 404

@app.route('/api/senders', methods=['POST'])
def create_sender():
    """Create a new sender"""
    data = request.json
    try:
        sender_id = sender_manager.create_sender(
            name=data['name'],
            log_type=data['log_type'],
            frequency=data['frequency'],
            enabled=data.get('enabled', False),
            options=data.get('options', {}),
            destination=data.get('destination'),
            destination_type=data.get('destination_type', 'file'),
            configuration_id=data.get('configuration_id'),
            syslog_destination_id=data.get('syslog_destination_id'),
            syslog_host=data.get('syslog_host'),
            syslog_port=data.get('syslog_port', 514),
            syslog_protocol=data.get('syslog_protocol', 'udp'),
            duration_seconds=data.get('duration_seconds', 0),
        )
        return jsonify({'success': True, 'sender_id': sender_id})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 400

@app.route('/api/senders/<sender_id>', methods=['PUT'])
def update_sender(sender_id):
    """Update sender configuration"""
    data = request.json
    try:
        sender_manager.update_sender(sender_id, data)
        return jsonify({'success': True})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 400

@app.route('/api/senders/<sender_id>', methods=['DELETE'])
def delete_sender(sender_id):
    """Delete a sender"""
    try:
        sender_manager.delete_sender(sender_id)
        return jsonify({'success': True})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 400

@app.route('/api/senders/<sender_id>/toggle', methods=['POST'])
def toggle_sender(sender_id):
    """Enable/disable a sender"""
    try:
        sender_manager.toggle_sender(sender_id)
        return jsonify({'success': True})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 400

@app.route('/api/senders/<sender_id>/clone', methods=['POST'])
def clone_sender(sender_id):
    """Clone a sender"""
    try:
        new_id = sender_manager.clone_sender(sender_id)
        return jsonify({'success': True, 'sender_id': new_id})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 400

@app.route('/api/configurations', methods=['GET'])
def get_configurations():
    """Get all configurations"""
    return jsonify(configuration_manager.get_all_configurations())

@app.route('/api/configurations/<config_id>', methods=['GET'])
def get_configuration(config_id):
    """Get a specific configuration"""
    config = configuration_manager.get_configuration(config_id)
    if config:
        return jsonify(config)
    return jsonify({'error': 'Configuration not found'}), 404

@app.route('/api/configurations', methods=['POST'])
def create_configuration():
    """Create a new configuration"""
    data = request.json
    try:
        config_id = configuration_manager.create_configuration(
            name=data['name'],
            url=data['url'],
            port=data['port'],
            token=data['token'],
            index=data.get('index'),
            sourcetype=data.get('sourcetype'),
            host=data.get('host'),
            source=data.get('source')
        )
        return jsonify({'success': True, 'configuration_id': config_id})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 400

@app.route('/api/configurations/<config_id>', methods=['PUT'])
def update_configuration(config_id):
    """Update configuration"""
    data = request.json
    try:
        configuration_manager.update_configuration(config_id, data)
        return jsonify({'success': True})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 400

@app.route('/api/configurations/<config_id>', methods=['DELETE'])
def delete_configuration(config_id):
    """Delete a configuration"""
    try:
        configuration_manager.delete_configuration(config_id)
        return jsonify({'success': True})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 400

@app.route('/api/configurations/<config_id>/clone', methods=['POST'])
def clone_configuration(config_id):
    """Clone a configuration"""
    try:
        new_id = configuration_manager.clone_configuration(config_id)
        return jsonify({'success': True, 'configuration_id': new_id})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 400

@app.route('/api/configurations/test', methods=['POST'])
def test_configuration():
    """Test a HEC configuration connection"""
    data = request.json
    try:
        from hec_sender import HECSender

        # Create a temporary HEC sender with the provided config
        hec_sender = HECSender(
            url=data['url'],
            port=data['port'],
            token=data['token'],
            index=data.get('index'),
            sourcetype=data.get('sourcetype'),
            host=data.get('host'),
            source=data.get('source')
        )

        # Send a test event
        test_event = "Log Generator - HEC Connection Test"
        success = hec_sender.send_event(test_event)
        hec_sender.close()

        if success:
            return jsonify({'success': True, 'message': 'Connection successful! Test event sent.'})
        else:
            return jsonify({'success': False, 'error': 'Failed to send test event. Check your HEC configuration.'})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 400

@app.route('/api/log-types', methods=['GET'])
def get_log_types():
    """Get available log types"""
    return jsonify(sender_manager.get_available_log_types())

@app.route('/api/catalog', methods=['GET'])
def get_catalog():
    """Data sources and attacks, as the Catalog tab lists them."""
    from catalog import build_catalog
    return jsonify(build_catalog())

@app.route('/api/attack-types', methods=['GET'])
def get_attack_types():
    """Get available attack types with their options"""
    from attack_generators import AttackGeneratorFactory
    return jsonify(AttackGeneratorFactory.get_available_attack_types())

@app.route('/api/simulations', methods=['GET'])
def get_simulations():
    """Get all simulations, expiring any whose window has closed."""
    return jsonify(simulation_manager.get_all_simulations(sender_manager))


@app.route('/api/simulations', methods=['POST'])
def create_simulation():
    """Create a new simulation"""
    data = request.json
    try:
        sim_id = simulation_manager.create_simulation(
            name=data['name'],
            duration_seconds=data.get('duration_seconds'),
            duration_hours=data.get('duration_hours'),
            sourcetypes=data['sourcetypes'],
            destination=data.get('destination'),
            destination_type=data.get('destination_type', 'file'),
            configuration_id=data.get('configuration_id'),
            hec_index=data.get('hec_index'),
            syslog_host=data.get('syslog_host'),
            syslog_port=data.get('syslog_port', 514),
            syslog_protocol=data.get('syslog_protocol', 'udp'),
        )
        return jsonify({'success': True, 'simulation_id': sim_id})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 400


@app.route('/api/simulations/<sim_id>', methods=['PUT'])
def update_simulation(sim_id):
    """Rewrite a stopped simulation in place."""
    data = request.json
    try:
        simulation_manager.update_simulation(
            sim_id,
            name=data['name'],
            duration_seconds=data.get('duration_seconds'),
            duration_hours=data.get('duration_hours'),
            sourcetypes=data['sourcetypes'],
            destination=data.get('destination'),
            destination_type=data.get('destination_type', 'file'),
            configuration_id=data.get('configuration_id'),
            hec_index=data.get('hec_index'),
            syslog_host=data.get('syslog_host'),
            syslog_port=data.get('syslog_port', 514),
            syslog_protocol=data.get('syslog_protocol', 'udp'),
        )
        return jsonify({'success': True, 'simulation_id': sim_id})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 400


@app.route('/api/simulations/<sim_id>', methods=['DELETE'])
def delete_simulation(sim_id):
    """Delete a simulation"""
    try:
        simulation_manager.delete_simulation(sim_id, sender_manager)
        return jsonify({'success': True})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 400


@app.route('/api/simulations/<sim_id>/start', methods=['POST'])
def start_simulation(sim_id):
    """Start a simulation"""
    try:
        simulation_manager.start_simulation(sim_id, sender_manager)
        return jsonify({'success': True})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 400


@app.route('/api/simulations/<sim_id>/stop', methods=['POST'])
def stop_simulation(sim_id):
    """Stop a simulation"""
    try:
        simulation_manager.stop_simulation(sim_id, sender_manager)
        return jsonify({'success': True})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 400


@app.route('/api/simulations/calculate', methods=['POST'])
def calculate_simulation():
    """Preview frequencies without creating a simulation"""
    data = request.json
    try:
        seconds = simulation_manager._duration_seconds(
            data.get('duration_seconds'), data.get('duration_hours'))
        result = []
        for st in data.get('sourcetypes', []):
            log_type = st['log_type']
            options = st.get('options', {})
            volume_bytes = simulation_manager._entry_bytes(st)
            freq = simulation_manager.calculate_frequency(
                volume_bytes, seconds, log_type, options)
            result.append({
                'log_type': log_type,
                'volume_bytes': volume_bytes,
                'frequency': freq,
                # Measured on the generator, so the form stops mirroring a table
                # that had drifted by up to 100%.
                'avg_log_size': simulation_manager.average_log_size(log_type, options),
            })
        return jsonify({'success': True, 'sourcetypes': result})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 400


# ──────────────────────────────────────────────────────────────────────────────
# Environment (Entities & Accounts)
# ──────────────────────────────────────────────────────────────────────────────

@app.route('/api/environment/counts', methods=['GET'])
def get_env_counts():
    """Return per-log-type entity/account counts for the sourcetype dropdown."""
    from log_generators.registry import REGISTRY
    from attack_generators import ATTACK_REGISTRY
    all_types = list(REGISTRY.keys()) + list(ATTACK_REGISTRY.keys())
    return jsonify(env_manager.get_counts_by_log_type(all_types))


@app.route('/api/environment/impact/<log_type>', methods=['GET'])
def get_env_impact(log_type):
    """Return pool availability rows for a given log_type (used by the sender form)."""
    rows = env_manager.get_impact(log_type)
    return jsonify(rows)


@app.route('/api/environment/attack-impact/<attack_type>', methods=['GET'])
def get_attack_env_impact(attack_type):
    """Environment-backed fields of one attack, with how many values each has."""
    from attack_generators import ATTACK_REGISTRY
    definition = ATTACK_REGISTRY.get(attack_type)
    if not definition:
        return jsonify({'error': 'Attack not found'}), 404
    return jsonify(env_manager.get_attack_impact(definition.get('ai_fields', {})))


@app.route('/api/environment/meta', methods=['GET'])
def get_env_meta():
    """Return entity/account type enumerations and current stats."""
    return jsonify({
        'entity_types':        ENTITY_TYPES,
        'entity_type_labels':  ENTITY_TYPE_LABELS,
        'account_types':       ACCOUNT_TYPES,
        'account_type_labels': ACCOUNT_TYPE_LABELS,
        'stats':               env_manager.get_stats(),
        'has_data':            env_manager.has_data(),
        'settings':            env_manager.get_settings(),
    })


@app.route('/api/environment/settings', methods=['PUT'])
def update_env_settings():
    """Environment-wide settings (currently the AD domain)."""
    return jsonify({'success': True,
                    'settings': env_manager.update_settings(request.json or {})})

# --- Entities ---

@app.route('/api/entities', methods=['GET'])
def get_entities():
    return jsonify(env_manager.get_all_entities())

@app.route('/api/entities/<entity_id>', methods=['GET'])
def get_entity(entity_id):
    entity = env_manager.get_entity(entity_id)
    if entity:
        return jsonify(entity)
    return jsonify({'error': 'Entity not found'}), 404

@app.route('/api/entities', methods=['POST'])
def create_entity():
    data = request.json
    try:
        entity_id = env_manager.create_entity(
            name=data['name'],
            entity_type=data['type'],
            ip=data.get('ip', ''),
            nt_host=data.get('nt_host', ''),
            mac=data.get('mac', ''),
            fqdn=data.get('fqdn', ''),
            os=data.get('os', ''),
        )
        return jsonify({'success': True, 'entity_id': entity_id})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 400

@app.route('/api/entities/<entity_id>', methods=['PUT'])
def update_entity(entity_id):
    data = request.json
    try:
        env_manager.update_entity(entity_id, data)
        return jsonify({'success': True})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 400

@app.route('/api/entities/<entity_id>', methods=['DELETE'])
def delete_entity(entity_id):
    try:
        env_manager.delete_entity(entity_id)
        return jsonify({'success': True})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 400

# --- Accounts ---

@app.route('/api/accounts', methods=['GET'])
def get_accounts():
    return jsonify(env_manager.get_all_accounts())

@app.route('/api/accounts/<account_id>', methods=['GET'])
def get_account(account_id):
    acc = env_manager.get_account(account_id)
    if acc:
        return jsonify(acc)
    return jsonify({'error': 'Account not found'}), 404

@app.route('/api/accounts', methods=['POST'])
def create_account():
    data = request.json
    try:
        account_id = env_manager.create_account(
            username=data['username'],
            email=data.get('email', ''),
            account_type=data.get('type', 'standard'),
            linked_entity=data.get('linked_entity'),
        )
        return jsonify({'success': True, 'account_id': account_id})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 400

@app.route('/api/accounts/<account_id>', methods=['PUT'])
def update_account(account_id):
    data = request.json
    try:
        env_manager.update_account(account_id, data)
        return jsonify({'success': True})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 400

@app.route('/api/accounts/<account_id>', methods=['DELETE'])
def delete_account(account_id):
    try:
        env_manager.delete_account(account_id)
        return jsonify({'success': True})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 400


# --- TA Registry (V2) ---

@app.route('/api/ta-registry', methods=['GET'])
def get_ta_registry():
    """Get all TAs in registry"""
    tas_list = []
    for ta_name in list_tas():
        ta = get_ta(ta_name)
        tas_list.append({
            'name': ta_name,
            'full_name': ta['name'],
            'display_name': ta.get('display_name', ta['name']),
            'vendor': ta['vendor'],
            'description': ta.get('description', ''),
            'sourcetype_count': len(ta.get('sourcetypes', []))
        })
    return jsonify({'tas': tas_list})


@app.route('/api/ta-registry/<ta_name>', methods=['GET'])
def get_ta_detail(ta_name):
    """Get details for a specific TA"""
    ta = get_ta(ta_name)
    if not ta:
        return jsonify({'error': 'TA not found'}), 404
    return jsonify({
        'name': ta_name,
        'full_name': ta['name'],
        'display_name': ta.get('display_name', ta['name']),
        'vendor': ta['vendor'],
        'description': ta.get('description', ''),
        'hec_default_sourcetype': ta.get('hec_default_sourcetype'),
        # Windows keys its wire metadata on render_format; the form picks the
        # entry matching the selected format. Sourcetype-level equivalents ride
        # along inside `sourcetypes`, which is returned verbatim.
        'hec_default_sourcetype_by_render_format':
            ta.get('hec_default_sourcetype_by_render_format'),
        'syslog_viable': ta.get('syslog_viable', True),
        # Present only for TAs that need framing added; one that frames itself
        # or is never collected over syslog declares none, and the form then
        # offers no delivery format at all.
        'syslog_framing': ta.get('syslog_framing'),
        # Which delivery formats each destination offers, and the default. The
        # form renders this rather than working the rules out itself.
        'delivery': delivery_description(ta),
        'sourcetypes': ta.get('sourcetypes', [])
    })


@app.route('/api/ta-registry/<ta_name>/<sourcetype>', methods=['GET'])
def get_sourcetype_detail(ta_name, sourcetype):
    """Get details for a specific sourcetype"""
    info = get_sourcetype_info(ta_name, sourcetype)
    if not info:
        return jsonify({'error': 'Sourcetype not found'}), 404

    # Add A&I mapping info
    ai_mapping = ai_mapping_manager.get_mapping(ta_name, sourcetype)

    return jsonify({
        'ta_name': ta_name,
        'sourcetype': sourcetype,
        'name': info.get('name', ''),
        'description': info.get('description', ''),
        'datamodels': info.get('datamodels', []),
        'eventtypes': info.get('eventtypes', []),
        'tags': info.get('tags', []),
        'entity_types': list(info.get('entity_types', [])),
        'account_types': list(info.get('account_types', [])),
        'a_i_fields': list(ai_mapping.keys()),
        'a_i_mapping': ai_mapping
    })


# --- Network Pools (V2) ---

@app.route('/api/network-pools', methods=['GET'])
def get_network_pools():
    """Get all network pool categories and their pools"""
    categories = {}
    for category in network_pool_manager.list_categories():
        pools = network_pool_manager.list_pools(category)
        categories[category] = [
            {
                'name': p['name'],
                'range': p['range'],
                'type': p['type'],
                'ip_count': len(network_pool_manager.get_pool(category, p['name']))
            }
            for p in pools
        ]
    return jsonify({'categories': categories})


@app.route('/api/network-pools/<category>', methods=['GET'])
def get_network_category(category):
    """Get pools in a specific category"""
    try:
        pools = network_pool_manager.list_pools(category)
        return jsonify({
            'category': category,
            'pools': [
                {
                    'name': p['name'],
                    'range': p['range'],
                    'type': p['type'],
                    'ip_count': len(network_pool_manager.get_pool(category, p['name']))
                }
                for p in pools
            ]
        })
    except ValueError as e:
        return jsonify({'error': str(e)}), 404


@app.route('/api/network-pools/<category>', methods=['POST'])
def create_network_pool(category):
    """Create a new pool in a category"""
    data = request.json
    try:
        network_pool_manager.create_pool(
            category=category,
            name=data['name'],
            range_str=data['range'],
            type_=data.get('type', 'cidr')
        )
        return jsonify({'success': True, 'message': f"Pool '{data['name']}' created"})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 400


@app.route('/api/network-pools/<category>/<pool_name>', methods=['PUT'])
def update_network_pool(category, pool_name):
    """Update an existing pool"""
    data = request.json
    try:
        network_pool_manager.update_pool(
            category=category,
            name=pool_name,
            range_str=data['range'],
            type_=data.get('type', 'cidr')
        )
        return jsonify({'success': True})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 400


@app.route('/api/network-pools/<category>/<pool_name>', methods=['DELETE'])
def delete_network_pool(category, pool_name):
    """Delete a pool"""
    try:
        network_pool_manager.delete_pool(category, pool_name)
        return jsonify({'success': True})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 400


# --- A&I Mapping (V2) ---

@app.route('/api/a-i-mapping/<ta_name>/<sourcetype>', methods=['GET'])
def get_ai_mapping(ta_name, sourcetype):
    """Get A&I field mappings for a sourcetype"""
    mapping = ai_mapping_manager.get_mapping(ta_name, sourcetype)
    if not mapping:
        return jsonify({'error': 'Mapping not found'}), 404

    return jsonify({
        'ta_name': ta_name,
        'sourcetype': sourcetype,
        'fields': mapping,
        'entity_types': list(ai_mapping_manager.get_entity_types_for_sourcetype(ta_name, sourcetype)),
        'account_types': list(ai_mapping_manager.get_account_types_for_sourcetype(ta_name, sourcetype))
    })


@app.route('/api/environment/sourcetype-context/<ta_name>/<sourcetype>', methods=['GET'])
def get_sourcetype_context(ta_name, sourcetype):
    """Get complete A&I context for a TA/sourcetype (mutable fields, available entities/accounts)."""
    try:
        context = env_manager.get_sourcetype_context(ta_name, sourcetype)
        if not context:
            return jsonify({'error': 'Sourcetype not found'}), 404
        return jsonify(context)
    except Exception as e:
        return jsonify({'error': str(e)}), 400


@app.route('/api/environment/sourcetype-impact/<ta_name>/<sourcetype>', methods=['GET'])
def get_sourcetype_impact(ta_name, sourcetype):
    """Get A&I field impact for a TA/sourcetype."""
    try:
        impact = env_manager.get_impact_for_sourcetype(ta_name, sourcetype)
        return jsonify({'ta_name': ta_name, 'sourcetype': sourcetype, 'fields': impact})
    except Exception as e:
        return jsonify({'error': str(e)}), 400


# ──────────────────────────────────────────────────────────────────────────────
# Syslog Destinations
# ──────────────────────────────────────────────────────────────────────────────

@app.route('/api/syslog-destinations', methods=['GET'])
def get_syslog_destinations():
    return jsonify(syslog_destinations_manager.get_all_destinations())


@app.route('/api/syslog-destinations/<dest_id>', methods=['GET'])
def get_syslog_destination(dest_id):
    d = syslog_destinations_manager.get_destination(dest_id)
    if d:
        return jsonify(d)
    return jsonify({'error': 'Syslog destination not found'}), 404


@app.route('/api/syslog-destinations', methods=['POST'])
def create_syslog_destination():
    data = request.json
    try:
        dest_id = syslog_destinations_manager.create_destination(
            name=data['name'],
            host=data['host'],
            port=data['port'],
            protocol=data.get('protocol', 'udp'),
        )
        return jsonify({'success': True, 'destination_id': dest_id})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 400


@app.route('/api/syslog-destinations/<dest_id>', methods=['PUT'])
def update_syslog_destination(dest_id):
    data = request.json
    try:
        syslog_destinations_manager.update_destination(dest_id, data)
        return jsonify({'success': True})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 400


@app.route('/api/syslog-destinations/<dest_id>', methods=['DELETE'])
def delete_syslog_destination(dest_id):
    try:
        syslog_destinations_manager.delete_destination(dest_id)
        return jsonify({'success': True})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 400


@app.route('/api/syslog-destinations/<dest_id>/clone', methods=['POST'])
def clone_syslog_destination(dest_id):
    try:
        new_id = syslog_destinations_manager.clone_destination(dest_id)
        return jsonify({'success': True, 'destination_id': new_id})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 400


@app.route('/api/syslog-destinations/test', methods=['POST'])
def test_syslog_destination():
    """Send a test event to a syslog endpoint without persisting it."""
    data = request.json
    try:
        from syslog_sender import SyslogSender
        sender = SyslogSender(
            host=data['host'],
            port=int(data['port']),
            protocol=data.get('protocol', 'udp'),
        )
        ok = sender.send_event("Log Generator - Syslog Connection Test")
        sender.close()
        if ok:
            return jsonify({'success': True, 'message': 'Test event sent.'})
        return jsonify({'success': False, 'error': 'Failed to send test event.'}), 400
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 400


if __name__ == '__main__':
    from listen_address import is_local, resolve

    # Resolved here rather than left to the server: Werkzeug reports a busy port
    # only after failing to bind, and its message cannot mention -p. The
    # reloader re-executes this file, so the work happens once in the parent and
    # the child inherits the decision through the environment.
    resolved = os.environ.get('LOG_GENERATOR_RESOLVED')
    if resolved:
        host, _, port = resolved.rpartition(':')
        port = int(port)
    else:
        host, port = resolve()
        os.environ['LOG_GENERATOR_RESOLVED'] = f'{host}:{port}'

    # The debugger is an arbitrary-code console. It is worth having while the
    # server answers only this machine, and not worth it a moment later: the
    # PIN in front of it derives from predictable host data. The reloader stays
    # either way — it is what makes editing pleasant and it exposes nothing.
    app.run(host=host, port=port, debug=True, use_debugger=is_local(host))
