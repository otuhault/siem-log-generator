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

app = Flask(__name__)
app.config['SECRET_KEY'] = 'dev-key-change-in-production'

# Initialize sender manager
sender_manager = SenderManager()

@app.route('/')
def index():
    """Main dashboard"""
    return render_template('index.html')

@app.route('/api/senders', methods=['GET'])
def get_senders():
    """Get all senders"""
    return jsonify(sender_manager.get_all_senders())

@app.route('/api/senders', methods=['POST'])
def create_sender():
    """Create a new sender"""
    data = request.json
    try:
        sender_id = sender_manager.create_sender(
            name=data['name'],
            log_type=data['log_type'],
            destination=data['destination'],
            frequency=data['frequency'],
            enabled=data.get('enabled', False)
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

@app.route('/api/log-types', methods=['GET'])
def get_log_types():
    """Get available log types"""
    return jsonify(sender_manager.get_available_log_types())

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)
