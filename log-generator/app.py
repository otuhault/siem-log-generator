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
from attacks_manager import AttacksManager

app = Flask(__name__)
app.config['SECRET_KEY'] = 'dev-key-change-in-production'

# Initialize managers
sender_manager = SenderManager()
configuration_manager = ConfigurationManager()
attacks_manager = AttacksManager()

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

@app.route('/api/log-types', methods=['GET'])
def get_log_types():
    """Get available log types"""
    return jsonify(sender_manager.get_available_log_types())

# Attacks API endpoints
@app.route('/api/attacks', methods=['GET'])
def get_attacks():
    """Get all attacks"""
    return jsonify(attacks_manager.get_all_attacks())

@app.route('/api/attacks/<attack_id>', methods=['GET'])
def get_attack(attack_id):
    """Get a specific attack"""
    attack = attacks_manager.get_attack(attack_id)
    if attack:
        return jsonify(attack)
    return jsonify({'error': 'Attack not found'}), 404

@app.route('/api/attacks', methods=['POST'])
def create_attack():
    """Create a new attack"""
    data = request.json
    try:
        attack_id = attacks_manager.create_attack(
            name=data['name'],
            description=data['description'],
            log_type=data['log_type'],
            example=data['example']
        )
        return jsonify({'success': True, 'attack_id': attack_id})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 400

@app.route('/api/attacks/<attack_id>', methods=['PUT'])
def update_attack(attack_id):
    """Update attack"""
    data = request.json
    try:
        attacks_manager.update_attack(attack_id, data)
        return jsonify({'success': True})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 400

@app.route('/api/attacks/<attack_id>', methods=['DELETE'])
def delete_attack(attack_id):
    """Delete an attack"""
    try:
        attacks_manager.delete_attack(attack_id)
        return jsonify({'success': True})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 400

@app.route('/api/attacks/<attack_id>/clone', methods=['POST'])
def clone_attack(attack_id):
    """Clone an attack"""
    try:
        new_id = attacks_manager.clone_attack(attack_id)
        return jsonify({'success': True, 'attack_id': new_id})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 400

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5001)
