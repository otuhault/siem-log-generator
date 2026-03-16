#!/usr/bin/env python3
"""
Log Generator - SIEM Testing Tool
Main application with web interface for managing log senders
"""

from flask import Flask, render_template, request, jsonify
import json
import os
from datetime import datetime
from log_senders import SenderManager
from configuration_manager import ConfigurationManager
from simulation_manager import SimulationManager

app = Flask(__name__)
app.config['SECRET_KEY'] = 'dev-key-change-in-production'

# Initialize managers
sender_manager = SenderManager()
configuration_manager = ConfigurationManager()
simulation_manager = SimulationManager()

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
            configuration_id=data.get('configuration_id')
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

@app.route('/api/attack-types', methods=['GET'])
def get_attack_types():
    """Get available attack types with their options"""
    from attack_generators import AttackGeneratorFactory
    return jsonify(AttackGeneratorFactory.get_available_attack_types())

@app.route('/api/simulations', methods=['GET'])
def get_simulations():
    """Get all simulations"""
    return jsonify(simulation_manager.get_all_simulations())


@app.route('/api/simulations', methods=['POST'])
def create_simulation():
    """Create a new simulation"""
    data = request.json
    try:
        sim_id = simulation_manager.create_simulation(
            name=data['name'],
            duration_hours=float(data['duration_hours']),
            sourcetypes=data['sourcetypes'],
            destination=data.get('destination'),
            destination_type=data.get('destination_type', 'file'),
            configuration_id=data.get('configuration_id'),
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
        duration_seconds = float(data['duration_hours']) * 3600
        result = []
        for st in data.get('sourcetypes', []):
            log_type = st['log_type']
            volume_gb = float(st.get('volume_gb', 0))
            freq = simulation_manager.calculate_frequency(volume_gb, duration_seconds, log_type)
            result.append({'log_type': log_type, 'volume_gb': volume_gb, 'frequency': freq})
        return jsonify({'success': True, 'sourcetypes': result})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 400


if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5001)
