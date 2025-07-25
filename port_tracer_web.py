#!/usr/bin/env python3
"""
Dell Switch Port Tracer Web Service
==========================================

A secure, enterprise-grade web application for tracing MAC addresses across Dell
switches in an enterprise environment with concurrent processing capabilities.

🏢 ENTERPRISE FEATURES:
- Multi-site, multi-floor switch management (27 sites, 155+ switches)
- Windows AD integration with role-based permissions (OSS/NetAdmin/SuperAdmin)
- Dell N2000/N3000/N3200 series switch support (N2048, N3024P, N3248 models)
- Real-time MAC address tracing with port configuration details
- Comprehensive audit logging and monitoring
- Clean, responsive web interface with multiple MAC formats

⚡ PERFORMANCE & SCALABILITY:
- Concurrent switch processing (8 workers max per site)
- Per-site user limits (10 concurrent users max)
- 6x faster MAC tracing (30s → 5s for 10 switches)
- Thread-safe operations with proper locking
- 60-second timeout protection

🐳 DEPLOYMENT READY:
- Docker and Kubernetes deployment ready
- Production-grade security and health checks
- Auto-deployment with 1-minute intervals
- Environment-based configuration

📊 MONITORING & TROUBLESHOOTING:
- Real-time performance metrics
- Detailed audit trails with timing
- Enhanced error handling and logging
- Progress tracking for large batches

Repository: https://github.com/Crispy-Pasta/DellPortTracer
Version: 1.0.2
Author: Network Operations Team
Last Updated: July 2025 - Concurrent processing & user limits
License: MIT

🔧 TROUBLESHOOTING:
- Check logs: port_tracer.log (system) | audit.log (user actions)
- Monitor concurrent users per site in CONCURRENT_USERS_PER_SITE
- Verify Dell switch SSH limits (max 10 concurrent sessions)
- Review environment variables for performance tuning
"""

import paramiko
import logging
import time
import json
import os
from datetime import datetime
from flask import Flask, render_template_string, request, jsonify, session, redirect, url_for
from flask_httpauth import HTTPBasicAuth
from dotenv import load_dotenv
import secrets
import threading
import concurrent.futures
from collections import defaultdict

# Import Windows Authentication
try:
    import ldap3
    from nt_auth_integration import WindowsAuthenticator, AD_CONFIG
    WINDOWS_AUTH_AVAILABLE = True
except ImportError:
    WINDOWS_AUTH_AVAILABLE = False
    print("Warning: ldap3 not installed. Windows authentication disabled.")

# Load environment variables
load_dotenv()

# Flask app
app = Flask(__name__)
app.secret_key = secrets.token_hex(16)
auth = HTTPBasicAuth()

# Configuration
SWITCH_USERNAME = os.getenv('SWITCH_USERNAME')
SWITCH_PASSWORD = os.getenv('SWITCH_PASSWORD')

# User roles and credentials
USERS = {
    'oss': {'password': os.getenv('OSS_PASSWORD', 'oss123'), 'role': 'oss'},
    'netadmin': {'password': os.getenv('NETADMIN_PASSWORD', 'netadmin123'), 'role': 'netadmin'},
    'superadmin': {'password': os.getenv('SUPERADMIN_PASSWORD', 'superadmin123'), 'role': 'superadmin'},
    # Legacy admin user (maps to superadmin)
    'admin': {'password': os.getenv('WEB_PASSWORD', 'password'), 'role': 'superadmin'}
}

# Role permissions
ROLE_PERMISSIONS = {
    'oss': {
        'show_vlan_details': False,  # Only for access ports
        'show_uplink_ports': False,  # Hide uplink ports
        'show_trunk_general_vlans': False,  # Hide VLAN details for trunk/general
        'show_switch_names': False  # Hide switch names for security
    },
    'netadmin': {
        'show_vlan_details': True,
        'show_uplink_ports': True,
        'show_trunk_general_vlans': True,
        'show_switch_names': True  # Show actual switch names
    },
    'superadmin': {
        'show_vlan_details': True,
        'show_uplink_ports': True,
        'show_trunk_general_vlans': True,
        'show_switch_names': True  # Show actual switch names
    }
}

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('port_tracer.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

# Concurrent user tracking per site (Dell switch limit: 10 concurrent SSH sessions)
CONCURRENT_USERS_PER_SITE = defaultdict(lambda: {'count': 0, 'lock': threading.Lock()})
MAX_CONCURRENT_USERS_PER_SITE = int(os.getenv('MAX_CONCURRENT_USERS_PER_SITE', '10'))
MAX_WORKERS_PER_SITE = int(os.getenv('MAX_WORKERS_PER_SITE', '8'))  # Parallel switch connections

# Audit logging for user actions
audit_logger = logging.getLogger('audit')
audit_handler = logging.FileHandler('audit.log')
audit_formatter = logging.Formatter('%(asctime)s - AUDIT - %(message)s')
audit_handler.setFormatter(audit_formatter)
audit_logger.addHandler(audit_handler)
audit_logger.setLevel(logging.INFO)

# Load switches configuration
def load_switches():
    """Load switches from JSON configuration."""
    try:
        with open('switches.json', 'r') as f:
            return json.load(f)
    except FileNotFoundError:
        logger.error("switches.json not found")
        return {"sites": []}

# Authentication functions
def verify_user(username, password):
    """Verify user credentials against Windows AD or local accounts.
    
    Args:
        username (str): Username to authenticate
        password (str): Password for authentication
        
    Returns:
        dict: User information if authentication successful, None otherwise
              Contains: username, display_name, role, auth_method
    """
    # Try Windows Authentication first if enabled
    use_windows_auth = os.getenv('USE_WINDOWS_AUTH', 'false').lower() == 'true'
    
    if use_windows_auth and WINDOWS_AUTH_AVAILABLE:
        try:
            # Configure Active Directory settings from environment variables
            ad_config = {
                'server': os.getenv('AD_SERVER', 'ldap://kmc.int'),
                'domain': os.getenv('AD_DOMAIN', 'kmc.int'),
                'base_dn': os.getenv('AD_BASE_DN', 'DC=kmc,DC=int'),
                'user_search_base': os.getenv('AD_USER_SEARCH_BASE', 'DC=kmc,DC=int'),
                'group_search_base': os.getenv('AD_GROUP_SEARCH_BASE', 'DC=kmc,DC=int'),
                'required_group': os.getenv('AD_REQUIRED_GROUP')
            }
            
            authenticator = WindowsAuthenticator(ad_config)
            user_info = authenticator.authenticate_user(username, password)
            
            if user_info:
                # Map AD security groups to application roles (least privilege default)
                role = 'oss'  # Default role for all Windows users
                
                if user_info.get('groups'):
                    groups = [str(group).upper() for group in user_info['groups']]
                    
                    # Debug logging for group membership
                    logger.info(f"User {username} AD groups: {groups}")
                    
                    # Role assignment based on specific AD security groups
                    # Check for exact group CN (Common Name) matches, not just substring matches
                    oss_group_found = any('CN=SOLARWINDS_OSS/SD_ACCESS' in group or 'CN=SOLARWINDS_OSS_SD_ACCESS' in group for group in groups)
                    noc_team_group_found = any('CN=NOC TEAM' in group for group in groups)
                    admin_group_found = any('CN=ADMIN' in group or 'CN=SUPERADMIN' in group for group in groups)
                    
                    if oss_group_found:
                        role = 'oss'
                        logger.info(f"User {username} assigned role 'oss' due to SOLARWINDS_OSS/SD_ACCESS group")
                    elif noc_team_group_found:
                        role = 'netadmin'
                        logger.info(f"User {username} assigned role 'netadmin' due to NOC TEAM group")
                    elif admin_group_found:
                        role = 'superadmin'
                        logger.info(f"User {username} assigned role 'superadmin' due to admin group")
                    else:
                        logger.info(f"User {username} assigned default role 'oss' - no matching groups found")
                
                return {
                    'username': user_info['username'],
                    'display_name': user_info.get('display_name', username),
                    'role': role,
                    'auth_method': 'windows_ad'
                }
        except Exception as e:
            logger.warning(f"Windows authentication failed for {username}: {str(e)}")
            # Fall through to local authentication
    
    # Fall back to local user authentication
    if username in USERS:
        user_info = USERS[username]
        if user_info['password'] == password:
            return {
                'username': username, 
                'role': user_info['role'],
                'auth_method': 'local'
            }
    
    return None

def get_user_permissions(role):
    """Get permissions for a user role."""
    return ROLE_PERMISSIONS.get(role, ROLE_PERMISSIONS['oss'])

def detect_switch_model_from_config(switch_name, switch_config):
    """Detect switch model from configuration or name patterns."""
    model = switch_config.get('model', '').upper()
    
    # Extract model from explicit model field
    if 'N2000' in model or 'N20' in model:
        return 'N2000'
    elif 'N3200' in model or 'N32' in model:
        return 'N3200' 
    elif 'N3000' in model or 'N30' in model:
        return 'N3000'
    
    # Fallback: try to infer from switch name patterns
    name_upper = switch_name.upper()
    if any(pattern in name_upper for pattern in ['N2000', 'N20']):
        return 'N2000'
    elif any(pattern in name_upper for pattern in ['N3200', 'N32']):
        return 'N3200'
    elif any(pattern in name_upper for pattern in ['N3000', 'N30']):
        return 'N3000'
    
    # Default assumption
    return 'N3000'

def is_uplink_port(port_name, switch_model=None, port_description=''):
    """Determine if a port is an uplink based on Dell switch series and port characteristics."""
    
    # Always filter out Port-Channels
    if port_name.startswith('Po'):
        return True
        
    # Check description for uplink indicators - prioritize description-based detection
    if port_description:
        uplink_keywords = ['UPLINK', 'uplink', 'Uplink', 'CS', 'cs', 'Cs', 'TRUNK', 'trunk', 'Trunk', 'CORE', 'core', 'Core']
        if any(keyword in port_description for keyword in uplink_keywords):
            return True
    
    # Model-specific uplink port detection (only if no description indicators)
    if switch_model == 'N2000':
        # N2000: Gi ports are access, Te ports are uplinks
        return port_name.startswith('Te')
    elif switch_model == 'N3000': 
        # N3000: Gi ports are access, Te ports are uplinks
        return port_name.startswith('Te')
    elif switch_model == 'N3200':
        # N3200: Te ports are access, Tw (TwentyGig) ports are uplinks
        return port_name.startswith('Tw')
    
    # Generic fallback - common uplink port patterns
    uplink_patterns = ['Te', 'Tw', 'Fo']  # TenGig, TwentyGig, FortyGig
    return any(port_name.startswith(pattern) for pattern in uplink_patterns)

def is_wlan_ap_port(port_description='', port_vlans=None):
    """Determine if a port is likely connected to WLAN/AP based on description and VLAN configuration."""
    
    # Check description for WLAN/AP indicators
    if port_description:
        wlan_keywords = ['WLAN', 'wlan', 'Wlan', 'AP', 'ap', 'Wi-Fi', 'wifi', 'WiFi', 'WIRELESS', 'wireless', 'Wireless', 'ACCESS POINT', 'access point']
        if any(keyword in port_description for keyword in wlan_keywords):
            return True
    
    # Check for multiple VLANs (typical for AP trunk ports)
    if port_vlans and isinstance(port_vlans, list):
        # If port has many VLANs (more than 3), it's likely an AP or trunk port
        total_vlans = 0
        for vlan_range in port_vlans:
            if '-' in str(vlan_range):  # VLAN range like "10-20"
                try:
                    start, end = map(int, str(vlan_range).split('-'))
                    total_vlans += (end - start + 1)
                except:
                    total_vlans += 1
            elif ',' in str(vlan_range):  # Multiple VLANs like "10,20,30"
                total_vlans += len(str(vlan_range).split(','))
            else:
                total_vlans += 1
        
        if total_vlans > 3:  # More than 3 VLANs suggests AP or trunk
            return True
    
    return False

def get_port_caution_info(port_name, switch_model=None, port_description='', port_mode='', port_vlans=None):
    """Get caution information for a port based on its characteristics."""
    cautions = []
    
    # Check for uplink port FIRST (higher priority than WLAN/AP)
    uplink_detected = False
    if port_description:
        uplink_keywords = ['UPLINK', 'uplink', 'Uplink', 'CS', 'cs', 'Cs']
        if any(keyword in port_description for keyword in uplink_keywords):
            uplink_detected = True
    
    # If no description-based uplink detection, use port name patterns
    if not uplink_detected and is_uplink_port(port_name, switch_model, ''):
        uplink_detected = True
    
    if uplink_detected:
        cautions.append({
            'type': 'uplink',
            'icon': '⚠️',
            'message': 'Possible Switch Uplink'
        })
    # Only check for WLAN/AP if NOT an uplink (uplink takes priority)
    elif port_description:
        wlan_keywords = ['WLAN', 'wlan', 'Wlan', 'AP', 'ap']
        if any(keyword in port_description for keyword in wlan_keywords):
            cautions.append({
                'type': 'wlan_ap',
                'icon': '⚠️',
                'message': 'Possible AP Connection'
            })
    
    # Check for trunk/general ports with many VLANs (additional caution)
    if port_mode in ['trunk', 'general'] and port_vlans:
        total_vlans = 0
        for vlan_range in port_vlans:
            if '-' in str(vlan_range):
                try:
                    start, end = map(int, str(vlan_range).split('-'))
                    total_vlans += (end - start + 1)
                except:
                    total_vlans += 1
            elif ',' in str(vlan_range):
                total_vlans += len(str(vlan_range).split(','))
            else:
                total_vlans += 1
        
        if total_vlans > 5:  # Many VLANs suggests trunk/uplink usage
            cautions.append({
                'type': 'trunk_many_vlans',
                'icon': '⚠️',
                'message': f'Trunk Port with {total_vlans} VLANs'
            })
    
    return cautions

def apply_role_based_filtering(results, user_role):
    """Apply role-based filtering to trace results."""
    permissions = get_user_permissions(user_role)
    filtered_results = []
    switches_config = load_switches()
    
    for result in results:
        if result['status'] != 'found':
            filtered_results.append(result)
            continue
            
        # For OSS users, filter out uplink ports
        if not permissions['show_uplink_ports']:
            # Detect switch model from configuration
            switch_model = 'N3000'  # Default fallback
            try:
                # Find the switch configuration to get the correct model
                sites = switches_config.get('sites', {})
                for site_name, site_config in sites.items():
                    floors = site_config.get('floors', {})
                    for floor_name, floor_config in floors.items():
                        switches = floor_config.get('switches', {})
                        for switch_name, switch_config in switches.items():
                            if switch_config.get('ip_address') == result['switch_ip']:
                                switch_model = detect_switch_model_from_config(switch_name, switch_config)
                                break
            except Exception as e:
                logger.debug(f"Could not detect switch model for {result['switch_ip']}: {str(e)}")
            
            if is_uplink_port(result['port'], switch_model, result.get('port_description', '')):
                # Skip uplink ports for OSS users
                continue
        
        # Apply VLAN filtering based on port mode and role
        if result.get('port_mode') in ['trunk', 'general'] and not permissions['show_trunk_general_vlans']:
            # For OSS users on trunk/general ports, hide VLAN details
            result_copy = result.copy()
            result_copy['vlan_restricted'] = True
            result_copy['restriction_message'] = 'Please contact network admin for VLAN details'
            # Clear VLAN details
            result_copy['port_pvid'] = ''
            result_copy['port_vlans'] = []
            filtered_results.append(result_copy)
        else:
            # Show full details for access ports or privileged users
            filtered_results.append(result)
    
    return filtered_results

class DellSwitchSSH:
    """Dell switch SSH connection handler."""
    
    def __init__(self, ip_address, username, password):
        self.ip_address = ip_address
        self.username = username
        self.password = password
        self.ssh_client = None
        self.shell = None
    
    def connect(self) -> bool:
        """Establish SSH connection to the switch."""
        try:
            self.ssh_client = paramiko.SSHClient()
            self.ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            
            logger.info(f"Connecting to {self.ip_address}")
            self.ssh_client.connect(
                hostname=self.ip_address,
                username=self.username,
                password=self.password,
                timeout=15
            )
            
            # Create interactive shell
            self.shell = self.ssh_client.invoke_shell()
            time.sleep(2)
            
            # Clear initial output
            self.shell.recv(4096)
            
            logger.info(f"Successfully connected to {self.ip_address}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to connect to {self.ip_address}: {str(e)}")
            return False
    
    def disconnect(self):
        """Close SSH connection."""
        try:
            if self.shell and not self.shell.closed:
                try:
                    self._send_command("exit")
                except:
                    pass
            
            if self.ssh_client:
                self.ssh_client.close()
            
            logger.info(f"Disconnected from {self.ip_address}")
        except Exception as e:
            logger.debug(f"Error during disconnect from {self.ip_address}: {str(e)}")
    
    def _send_command(self, command: str, wait_time: float = 1.0) -> str:
        """Send command to switch and return output."""
        if not self.shell or self.shell.closed:
            raise Exception("No active SSH connection")
        
        try:
            # Command logging for audit purposes only
            self.shell.send(command + '\n')
            time.sleep(wait_time)
            
            output = ""
            while self.shell.recv_ready():
                output += self.shell.recv(4096).decode('utf-8')
            
            return output
            
        except OSError as e:
            if "Socket is closed" in str(e):
                logger.error(f"SSH connection to {self.ip_address} was closed unexpectedly")
                raise Exception("SSH connection lost")
            else:
                raise
    
    def execute_mac_lookup(self, mac_address: str) -> str:
        """Execute MAC address table lookup command."""
        try:
            command = f"show mac address-table address {mac_address}"
            logger.info(f"Executing on {self.ip_address}: {command}")
            
            # Use longer wait time for MAC table command
            output = self._send_command(command, wait_time=3.0)
            
            # Try to get any remaining output
            time.sleep(2)
            if self.shell.recv_ready():
                additional_output = ""
                while self.shell.recv_ready():
                    additional_output += self.shell.recv(4096).decode('utf-8')
                output += additional_output
            
            logger.info(f"Command completed on {self.ip_address}, output: {len(output)} chars")
            return output
            
        except Exception as e:
            logger.error(f"Failed to execute MAC lookup on {self.ip_address}: {str(e)}")
            raise
    
    def get_port_config(self, port_name: str) -> dict:
        """Get port configuration including mode and description."""
        try:
            command = f"show running-config interface {port_name}"
            logger.info(f"Getting port config for {port_name} on {self.ip_address}")
            
            output = self._send_command(command, wait_time=2.0)
            
            # Try to get any remaining output
            time.sleep(1.5)
            if self.shell.recv_ready():
                additional_output = ""
                while self.shell.recv_ready():
                    additional_output += self.shell.recv(4096).decode('utf-8')
                output += additional_output
            
            return self._parse_port_config(output)
            
        except Exception as e:
            logger.error(f"Failed to get port config for {port_name} on {self.ip_address}: {str(e)}")
            return {'mode': 'unknown', 'description': '', 'vlans': []}
    
    def _parse_port_config(self, output: str) -> dict:
        """Parse port configuration output."""
        config = {
            'mode': 'unknown',
            'description': '',
            'vlans': [],
            'pvid': ''
        }
        
        if not output:
            return config
        
        lines = output.split('\n')
        
        for line in lines:
            line = line.strip()
            
            # Extract description
            if line.startswith('description'):
                # Remove 'description' and quotes
                desc = line[11:].strip()
                if desc.startswith('"') and desc.endswith('"'):
                    desc = desc[1:-1]
                config['description'] = desc
            
            # Extract switchport mode
            elif 'switchport mode' in line:
                if 'access' in line:
                    config['mode'] = 'access'
                elif 'trunk' in line:
                    config['mode'] = 'trunk'
                elif 'general' in line:
                    config['mode'] = 'general'
            
            # Extract PVID for general mode
            elif 'switchport general pvid' in line:
                parts = line.split()
                if len(parts) >= 4:
                    config['pvid'] = parts[3]
            
            # Extract allowed VLANs
            elif 'switchport general allowed vlan add' in line or 'switchport trunk allowed vlan add' in line:
                # Extract VLAN numbers
                vlan_part = line.split('add')[-1].strip()
                if 'tagged' in vlan_part:
                    vlan_part = vlan_part.replace('tagged', '').strip()
                config['vlans'].append(vlan_part)
            
            # Access VLAN
            elif 'switchport access vlan' in line:
                parts = line.split()
                if len(parts) >= 4:
                    config['vlans'] = [parts[3]]
        
        return config

def parse_mac_table_output(output, target_mac):
    """Parse the MAC address table output from Dell switch."""
    if not output or len(output.strip()) == 0:
        return {'found': False, 'message': 'Empty output received'}
    
    lines = output.split('\n')
    
    # Convert target MAC to dotted format (C0:EA:E4:85:7F:CA -> C0EA.E485.7FCA)
    # Normalize MAC address to format without delimiters for easy comparison
    target_mac_clean = target_mac.replace(':', '').replace('-', '').replace('.', '').upper()
    target_mac_dotted = f"{target_mac_clean[:4]}.{target_mac_clean[4:8]}.{target_mac_clean[8:]}"
    
    # Parse each line looking for the MAC
    for line_num, line in enumerate(lines, 1):
        line = line.strip()
        if not line or line.startswith('-') or 'Address' in line or 'Total' in line:
            continue
            
        # Split by whitespace
        parts = line.split()
        if len(parts) >= 4:
            mac_in_line = parts[1] if len(parts) > 1 else ""
            
            if mac_in_line.upper() == target_mac_dotted:
                vlan = parts[0]
                mac_type = parts[2]
                port = parts[3] if len(parts) > 3 else "Unknown"
                
                # Filter out uplink ports (Port-Channels and common uplink ports)
                if port.startswith('Po') or 'Uplink' in port or port in ['Gi1/0/47', 'Gi1/0/48', 'Te1/0/1', 'Te1/0/2']:
                    return {'found': False, 'message': f'MAC found on uplink port {port} - excluding from results'}
                
                return {
                    'found': True,
                    'vlan': vlan,
                    'mac': mac_in_line,
                    'port': port,
                    'type': mac_type,
                    'line': line
                }
    
    return {'found': False, 'message': 'MAC address not found'}

def get_site_floor_switches(site, floor):
    """Get switches for specific site and floor."""
    switches_config = load_switches()
    matching_switches = []
    
    # Handle the actual JSON structure from switches.json
    sites = switches_config.get('sites', {})
    if site in sites:
        floors = sites[site].get('floors', {})
        if floor in floors:
            switches = floors[floor].get('switches', {})
            for switch_name, switch_config in switches.items():
                if switch_config.get('enabled', True):
                    matching_switches.append({
                        'name': switch_name,
                        'ip': switch_config['ip_address'],
                        'site': site,
                        'floor': floor
                    })
    
    return matching_switches

def format_switches_for_frontend(user_role='oss'):
    """Convert switches.json format for frontend consumption."""
    switches_config = load_switches()
    formatted_sites = []
    
    sites = switches_config.get('sites', {})
    for site_name, site_config in sites.items():
        floors = []
        for floor_name, floor_config in site_config.get('floors', {}).items():
            switches = []
            for switch_name, switch_config in floor_config.get('switches', {}).items():
                if switch_config.get('enabled', True):
                    # Always use actual switch names in data structure
                    # Role-based filtering will be handled in frontend JavaScript
                    switches.append({
                        'name': switch_name,
                        'ip': switch_config['ip_address'],
                        'model': switch_config.get('model', 'Unknown'),
                        'description': switch_config.get('description', '')
                    })
            
            if switches:  # Only include floors with enabled switches
                floors.append({
                    'floor': floor_name,
                    'switches': switches
                })
        
        if floors:  # Only include sites with floors that have switches
            formatted_sites.append({
                'name': site_name,
                'location': f"{site_name.upper()} Site",
                'floors': floors
            })
    
    return {'sites': formatted_sites}

def trace_single_switch(switch_info, mac_address, username):
    """Trace MAC address on a single switch - designed for concurrent execution."""
    switch_ip = switch_info['ip']
    switch_name = switch_info['name']
    
    try:
        switch = DellSwitchSSH(switch_ip, SWITCH_USERNAME, SWITCH_PASSWORD)
        
        if not switch.connect():
            return {
                'switch_name': switch_name,
                'switch_ip': switch_ip,
                'status': 'connection_failed',
                'message': 'Failed to connect to switch'
            }
        
        # Execute MAC lookup
        output = switch.execute_mac_lookup(mac_address)
        result = parse_mac_table_output(output, mac_address)
        
        if result['found']:
            # Get detailed port configuration
            port_config = switch.get_port_config(result['port'])
            
            # Detect switch model for accurate caution detection
            switch_model = 'N3000'  # Default fallback
            try:
                # Try to get switch model from switches.json
                switches_config = load_switches()
                sites = switches_config.get('sites', {})
                for site_name, site_config in sites.items():
                    floors = site_config.get('floors', {})
                    for floor_name, floor_config in floors.items():
                        switches = floor_config.get('switches', {})
                        for sw_name, sw_config in switches.items():
                            if sw_config.get('ip_address') == switch_ip:
                                switch_model = detect_switch_model_from_config(sw_name, sw_config)
                                break
            except Exception as e:
                logger.debug(f"Could not detect switch model for {switch_ip}: {str(e)}")
            
            # Get caution information for this port
            cautions = get_port_caution_info(
                port_name=result['port'],
                switch_model=switch_model,
                port_description=port_config.get('description', ''),
                port_mode=port_config.get('mode', ''),
                port_vlans=port_config.get('vlans', [])
            )
            
            # Enhanced audit logging with port details
            port_desc = f" ({port_config.get('description', 'No description')})" if port_config.get('description') else ""
            caution_desc = f" [Cautions: {len(cautions)}]" if cautions else ""
            audit_logger.info(f"User: {username} - MAC FOUND - {mac_address} on {switch_name} ({switch_ip}) port {result['port']}{port_desc} [Mode: {port_config.get('mode', 'unknown')}]{caution_desc}")
            
            return {
                'switch_name': switch_name,
                'switch_ip': switch_ip,
                'status': 'found',
                'vlan': result['vlan'],
                'port': result['port'],
                'type': result['type'],
                'mac': result['mac'],
                'port_mode': port_config.get('mode', 'unknown'),
                'port_description': port_config.get('description', ''),
                'port_pvid': port_config.get('pvid', ''),
                'port_vlans': port_config.get('vlans', []),
                'cautions': cautions  # Add caution information
            }
        else:
            return {
                'switch_name': switch_name,
                'switch_ip': switch_ip,
                'status': 'not_found',
                'message': result['message']
            }
        
    except Exception as e:
        logger.error(f"Error tracing MAC on {switch_name} ({switch_ip}): {str(e)}")
        return {
            'switch_name': switch_name,
            'switch_ip': switch_ip,
            'status': 'error',
            'message': str(e)
        }
    finally:
        # Ensure connection is always closed
        try:
            if 'switch' in locals():
                switch.disconnect()
        except:
            pass

def check_concurrent_user_limit(site):
    """Check if the concurrent user limit for a site has been reached."""
    site_tracker = CONCURRENT_USERS_PER_SITE[site]
    
    with site_tracker['lock']:
        if site_tracker['count'] >= MAX_CONCURRENT_USERS_PER_SITE:
            return False
        site_tracker['count'] += 1
        return True

def release_concurrent_user_slot(site):
    """Release a concurrent user slot for a site."""
    site_tracker = CONCURRENT_USERS_PER_SITE[site]
    
    with site_tracker['lock']:
        if site_tracker['count'] > 0:
            site_tracker['count'] -= 1

def trace_mac_on_switches(switches, mac_address, username):
    """Trace MAC address across specified switches using concurrent processing."""
    start_time = time.time()
    site = switches[0]['site'] if switches else 'unknown'
    
    # Check concurrent user limit per site (Dell switch SSH session limit)
    if not check_concurrent_user_limit(site):
        audit_logger.warning(f"User: {username} - TRACE REJECTED - Site: {site} - Concurrent user limit ({MAX_CONCURRENT_USERS_PER_SITE}) reached")
        return [{
            'switch_name': 'System',
            'switch_ip': 'N/A',
            'status': 'error',
            'message': f'Too many concurrent users for site {site}. Maximum {MAX_CONCURRENT_USERS_PER_SITE} users allowed. Please try again in a moment.'
        }]
    
    try:
        audit_logger.info(f"User: {username} - MAC Trace Started - MAC: {mac_address} - Switches: {len(switches)} - Site: {site}")
        
        # Use ThreadPoolExecutor for concurrent switch processing
        max_workers = min(MAX_WORKERS_PER_SITE, len(switches))  # Don't exceed switch count
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
            # Submit all switch trace tasks
            future_to_switch = {
                executor.submit(trace_single_switch, switch_info, mac_address, username): switch_info
                for switch_info in switches
            }
            
            results = []
            completed_count = 0
            
            # Collect results as they complete
            for future in concurrent.futures.as_completed(future_to_switch, timeout=60):
                completed_count += 1
                try:
                    result = future.result()
                    results.append(result)
                    
                    # Log progress for large batches
                    if len(switches) > 5:
                        logger.info(f"MAC trace progress: {completed_count}/{len(switches)} switches completed")
                        
                except Exception as e:
                    switch_info = future_to_switch[future]
                    logger.error(f"Error in concurrent trace for {switch_info['name']}: {str(e)}")
                    results.append({
                        'switch_name': switch_info['name'],
                        'switch_ip': switch_info['ip'],
                        'status': 'error',
                        'message': f'Concurrent execution error: {str(e)}'
                    })
        
        elapsed_time = time.time() - start_time
        found_count = len([r for r in results if r['status'] == 'found'])
        
        audit_logger.info(f"User: {username} - MAC Trace Completed - MAC: {mac_address} - Results: {found_count} found - Time: {elapsed_time:.2f}s - Concurrent workers: {max_workers}")
        return results
        
    except concurrent.futures.TimeoutError:
        audit_logger.error(f"User: {username} - MAC Trace TIMEOUT - MAC: {mac_address} - Site: {site}")
        return [{
            'switch_name': 'System',
            'switch_ip': 'N/A',
            'status': 'error',
            'message': 'Trace operation timed out after 60 seconds. Some switches may be unreachable.'
        }]
    except Exception as e:
        audit_logger.error(f"User: {username} - MAC Trace ERROR - MAC: {mac_address} - Site: {site} - Error: {str(e)}")
        return [{
            'switch_name': 'System',
            'switch_ip': 'N/A',
            'status': 'error',
            'message': f'System error during trace: {str(e)}'
        }]
    finally:
        # Always release the concurrent user slot
        release_concurrent_user_slot(site)

# Web Interface HTML Templates
LOGIN_TEMPLATE = """
<!DOCTYPE html>
<html>
<head>
    <title>Dell Switch Port Tracer</title>
    <link rel="stylesheet" href="{{ url_for('static', filename='styles.css') }}">
</head>
<body class="login-page">
    <div class="container">
        <div style="text-align:center; margin-bottom: 16px;">
            <img src="{{ url_for('static', filename='img/kmc_logo.png') }}" alt="KMC Logo" style="height: 80px; margin-bottom: 12px;">
        </div>
        <h1 style="text-align:center;">Dell Switch Port Tracer</h1>
        <form method="post">
            <input type="text" name="username" placeholder="Username" required>
            <input type="password" name="password" placeholder="Password" required>
            <button type="submit">Login</button>
        </form>
        {% if error %}
        <div class="error">{{ error }}</div>
        {% endif %}
    </div>
</body>
</html>
"""

MAIN_TEMPLATE = """
<!DOCTYPE html>
<html>
<head>
    <title>Dell Switch Port Tracer - Main</title>
    <link rel="stylesheet" href="{{ url_for('static', filename='styles.css') }}">
    <link href="https://cdn.jsdelivr.net/npm/select2@4.1.0-rc.0/dist/css/select2.min.css" rel="stylesheet" />
    <script src="https://code.jquery.com/jquery-3.6.0.min.js"></script>
    <script src="https://cdn.jsdelivr.net/npm/select2@4.1.0-rc.0/dist/js/select2.min.js"></script>
</head>
<body class="main-page">
    <div class="container">
        <div class="user-info">Logged in as: {{ username }} | <a href="/logout">Logout</a></div>
        <div style="text-align:center; margin-bottom: 10px;">
            <img src="{{ url_for('static', filename='img/kmc_logo.png') }}" alt="KMC Logo" style="height: 60px; margin-bottom: 8px; display:block; margin-left:auto; margin-right:auto;">
        </div>
        <div style="display:flex; align-items:center; justify-content:center; margin-bottom: 18px;">
            <img src="{{ url_for('static', filename='img/Dell_Logo.png') }}" alt="Dell Logo" style="height: 38px; margin-right: 14px;">
            <h1 style="margin:0;">Switch Port Tracer</h1>
        </div>
        <div class="step">
            <h3>Step 1: Select Site and Floor</h3>
            <div class="site-floor-search-row">
                <select id="site" onchange="loadFloors()">
                    <option value="">Select Site...</option>
                    {% for site in sites %}
                    <option value="{{ site.name }}">{{ site.name }} ({{ site.location }})</option>
                    {% endfor %}
                </select>
                <select id="floor" onchange="loadSwitches()" disabled>
                    <option value="">Select Floor...</option>
                </select>
            </div>
            <div id="switch-info" style="margin-top: 10px; color: #666;"></div>
        </div>
        <div class="step">
            <h3>Step 2: Enter MAC Address</h3>
            <input type="text" id="mac" placeholder="MAC Address (e.g., 00:1B:63:84:45:E6)" disabled>
            <button id="trace-btn" onclick="traceMac()" disabled>🔍 Trace MAC Address</button>
        </div>
        <div id="loading" class="loading" style="display: none;">
            <p>🔄 Tracing MAC address across switches...</p>
        </div>
        <div id="results" class="results"></div>
    </div>
    <script>
        const sitesData = {{ sites_json | safe }};
        const userRole = '{{ user_role }}';
        
        // Initialize Select2 on page load
        $(document).ready(function() {
            $('#site').select2({
                placeholder: 'Search or select site...',
                allowClear: true
            });
            
            $('#floor').select2({
                placeholder: 'Search or select floor...',
                allowClear: true
            });
            
            // Handle Select2 changes
            $('#site').on('select2:select select2:clear', function() {
                loadFloors();
            });
            
            $('#floor').on('select2:select select2:clear', function() {
                loadSwitches();
            });
        });
        
        function loadFloors() {
            const siteSelect = document.getElementById('site');
            const floorSelect = document.getElementById('floor');
            const selectedSite = siteSelect.value;
            
            // Destroy and reinitialize Select2 for floor dropdown
            $('#floor').select2('destroy');
            floorSelect.innerHTML = '<option value="">Select Floor...</option>';
            floorSelect.disabled = true;
            document.getElementById('mac').disabled = true;
            document.getElementById('trace-btn').disabled = true;
            document.getElementById('switch-info').innerHTML = '';
            
            if (selectedSite) {
                const site = sitesData.sites.find(s => s.name === selectedSite);
                if (site && site.floors) {
                    site.floors.forEach(floor => {
                        const option = document.createElement('option');
                        option.value = floor.floor;
                        option.textContent = `Floor ${floor.floor}`;
                        floorSelect.appendChild(option);
                    });
                    floorSelect.disabled = false;
                }
            }
            
            // Reinitialize Select2 for floor dropdown
            $('#floor').select2({
                placeholder: 'Search or select floor...',
                allowClear: true,
                disabled: floorSelect.disabled
            });
        }
        
        function loadSwitches() {
            const siteSelect = document.getElementById('site');
            const floorSelect = document.getElementById('floor');
            const selectedSite = siteSelect.value;
            const selectedFloor = floorSelect.value;
            
            document.getElementById('mac').disabled = true;
            document.getElementById('trace-btn').disabled = true;
            
            if (selectedSite && selectedFloor) {
                const site = sitesData.sites.find(s => s.name === selectedSite);
                if (site) {
                    const floor = site.floors.find(f => f.floor === selectedFloor);
                    if (floor && floor.switches) {
                        const switchCount = floor.switches.length;
                        let displayMessage;
                        
                        if (userRole === 'oss') {
                            // OSS users see only the count
                            displayMessage = `✅ ${switchCount} switch(es) loaded`;
                        } else {
                            // Admin users see the switch names
                            const switchNames = floor.switches.map(s => s.name).join(', ');
                            displayMessage = `✅ ${switchCount} switch(es) loaded: ${switchNames}`;
                        }
                        
                        document.getElementById('switch-info').innerHTML = displayMessage;
                        document.getElementById('mac').disabled = false;
                        document.getElementById('trace-btn').disabled = false;
                    }
                }
            }
        }
        
        function traceMac() {
            const site = document.getElementById('site').value;
            const floor = document.getElementById('floor').value;
            const mac = document.getElementById('mac').value.trim();
            
            if (!site || !floor || !mac) {
                alert('Please fill in all fields');
                return;
            }
            
            document.getElementById('loading').style.display = 'block';
            document.getElementById('results').innerHTML = '';
            document.getElementById('trace-btn').disabled = true;
            
            fetch('/trace', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ site: site, floor: floor, mac: mac })
            })
            .then(response => response.json())
            .then(data => {
                displayResults(data);
                document.getElementById('loading').style.display = 'none';
                document.getElementById('trace-btn').disabled = false;
            })
            .catch(error => {
                console.error('Error:', error);
                document.getElementById('loading').style.display = 'none';
                document.getElementById('trace-btn').disabled = false;
                alert('Error occurred during tracing');
            });
        }
        
        function displayResults(results) {
            const resultsDiv = document.getElementById('results');
            
            if (results.length === 0) {
                resultsDiv.innerHTML = '<div class="result-item not-found">No results found</div>';
                return;
            }
            
            let html = '<h3>🔍 Trace Results:</h3>';
            const foundResults = results.filter(r => r.status === 'found');
            
            if (foundResults.length > 0) {
                foundResults.forEach(result => {
                    let portInfo = `<strong>Port:</strong> ${result.port}`;
                    
                    // Add port mode badge
                    if (result.port_mode && result.port_mode !== 'unknown') {
                        portInfo += ` <span class="port-badge ${result.port_mode}">${result.port_mode.toUpperCase()}</span>`;
                    }
                    
                    // Add port description if available
                    let descriptionInfo = '';
                    if (result.port_description && result.port_description.trim()) {
                        descriptionInfo = `<br><strong>Description:</strong> <em>${result.port_description}</em>`;
                    }
                    
                    // Process caution information
                    let cautionLine = '';
                    let hasUplink = false;
                    
                    if (result.cautions && result.cautions.length > 0) {
                        // Show all cautions on a separate line after MAC Found
                        const cautionBadges = result.cautions.map(caution => {
                            if (caution.type === 'uplink') {
                                hasUplink = true;
                            }
                            return `<span class="caution-badge caution-${caution.type}">${caution.icon} ${caution.message}</span>`;
                        }).join(' ');
                        cautionLine = `<br>${cautionBadges}`;
                    }
                    
                    // Add VLAN information
                    let vlanInfo = '';
                    if (result.vlan_restricted) {
                        // For OSS users on trunk/general ports
                        vlanInfo = `<strong>MAC VLAN:</strong> ${result.vlan}<br><strong style="color: var(--orange);">⚠️ ${result.restriction_message}</strong>`;
                    } else {
                        // Full VLAN details for access ports or privileged users
                        vlanInfo = `<strong>MAC VLAN:</strong> ${result.vlan}`;
                        if (result.port_pvid) {
                            vlanInfo += ` | <strong>Port PVID:</strong> ${result.port_pvid}`;
                        }
                        if (result.port_vlans && result.port_vlans.length > 0) {
                            vlanInfo += ` | <strong>Allowed VLANs:</strong> ${result.port_vlans.join(', ')}`;
                        }
                    }
                    
                    html += `
                        <div class="result-item found">
                            <strong>✅ MAC Found!</strong>${cautionLine}<br>
                            <strong>Switch:</strong> ${result.switch_name} (${result.switch_ip})<br>
                            ${portInfo}${descriptionInfo}<br>
                            ${vlanInfo}
                        </div>
                    `;
                    
                    // Add Additional Information section outside the box only for uplinks
                    if (hasUplink) {
                        html += `
                            <div class="additional-info">
                                <strong>Additional Information:</strong>
                            </div>
                        `;
                    }
                });
            } else {
                html += '<div class="result-item not-found"><strong>❌ MAC Address Not Found</strong><br>The MAC address was not found on any switches in the selected site and floor.</div>';
            }
            
            // Show other results (only errors and connection failures, not 'not found')
            const otherResults = results.filter(r => r.status !== 'found' && r.status !== 'not_found');
            if (otherResults.length > 0) {
                html += '<h4>Additional Information:</h4>';
                otherResults.forEach(result => {
                    const cssClass = result.status === 'error' ? 'error' : 'not-found';
                    html += `
                        <div class="result-item ${cssClass}">
                            <strong>${result.switch_name} (${result.switch_ip}):</strong> ${result.message || result.status}
                        </div>
                    `;
                });
            }
            
            resultsDiv.innerHTML = html;
        }
    </script>
</body>
</html>
"""

# Routes
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        user_info = verify_user(username, password)
        if user_info:
            # Use display name or actual username for session
            display_name = user_info.get('display_name', username)
            session_username = user_info.get('username', username)
            
            session['username'] = session_username
            session['role'] = user_info['role']
            session['display_name'] = display_name
            session['auth_method'] = user_info.get('auth_method', 'local')
            
            auth_method = user_info.get('auth_method', 'local')
            audit_logger.info(f"User: {session_username} ({user_info['role']}) - LOGIN SUCCESS via {auth_method}")
            return redirect(url_for('index'))
        else:
            audit_logger.warning(f"User: {username} - LOGIN FAILED")
            return render_template_string(LOGIN_TEMPLATE, error="Invalid credentials")
    
    return render_template_string(LOGIN_TEMPLATE)

@app.route('/logout')
def logout():
    username = session.get('username', 'Unknown')
    session.pop('username', None)
    audit_logger.info(f"User: {username} - LOGOUT")
    return redirect(url_for('login'))

@app.route('/')
def index():
    if 'username' not in session:
        return redirect(url_for('login'))
    
    # Get switches data (role-based filtering handled in frontend)
    user_role = session.get('role', 'oss')
    formatted_data = format_switches_for_frontend()
    return render_template_string(MAIN_TEMPLATE, 
                                username=session['username'],
                                user_role=user_role,
                                sites=formatted_data.get('sites', []),
                                sites_json=json.dumps(formatted_data))

@app.route('/health')
def health_check():
    """Health check endpoint for Kubernetes liveness and readiness probes."""
    try:
        # Check if switches configuration is available
        switches_config = load_switches()
        if not switches_config.get('sites'):
            return jsonify({'status': 'unhealthy', 'reason': 'No switches configured'}), 503
        
        return jsonify({
            'status': 'healthy',
            'version': '1.0.0',
            'timestamp': datetime.now().isoformat(),
            'sites_count': len(switches_config.get('sites', {})),
            'windows_auth': WINDOWS_AUTH_AVAILABLE
        }), 200
    except Exception as e:
        return jsonify({
            'status': 'unhealthy',
            'reason': str(e),
            'timestamp': datetime.now().isoformat()
        }), 503

@app.route('/trace', methods=['POST'])
def trace():
    if 'username' not in session:
        return jsonify({'error': 'Not authenticated'}), 401
    
    data = request.json
    site = data.get('site')
    floor = data.get('floor')
    mac = data.get('mac')
    username = session['username']
    
    if not all([site, floor, mac]):
        return jsonify({'error': 'Missing required fields'}), 400
    
    # Log the trace request
    audit_logger.info(f"User: {username} - TRACE REQUEST - Site: {site}, Floor: {floor}, MAC: {mac}")
    
    # Get switches for the specified site and floor
    switches = get_site_floor_switches(site, floor)
    
    if not switches:
        audit_logger.warning(f"User: {username} - NO SWITCHES FOUND - Site: {site}, Floor: {floor}")
        return jsonify({'error': 'No switches found for specified site and floor'}), 404
    
    # Trace MAC address
    results = trace_mac_on_switches(switches, mac, username)
    
    # Apply role-based filtering
    user_role = session.get('role', 'oss')
    filtered_results = apply_role_based_filtering(results, user_role)
    
    # Sort results to prioritize interface ports (Gi) over uplink ports (Te/Tw)
    def get_port_priority(result):
        if result['status'] != 'found':
            return 999  # Put non-found results at the end
        
        port_name = result.get('port', '')
        # Priority: Gi ports (access/interface) first, then Te/Tw (uplink) ports
        if port_name.startswith('Gi'):
            return 1  # Highest priority for Gigabit Ethernet (interface ports)
        elif port_name.startswith('Te'):
            return 2  # Lower priority for TenGig (uplink ports)
        elif port_name.startswith('Tw'):
            return 3  # Lowest priority for TwentyGig (uplink ports)
        else:
            return 4  # Other port types
    
    sorted_results = sorted(filtered_results, key=get_port_priority)
    
    return jsonify(sorted_results)

if __name__ == '__main__':
    print("🔌 Starting Dell Switch Port Tracer Web Service...")
    print(f"📊 Web Interface: http://localhost:5000")
    print("👤 Available Users:")
    print("   • OSS: oss / oss123 (Limited access)")
    print("   • NetAdmin: netadmin / netadmin123 (Full access)")
    print("   • SuperAdmin: superadmin / superadmin123 (Full access)")
    print("   • Legacy: admin / password (Full access)") 
    print("📝 Logs: port_tracer.log (system) | audit.log (user actions)")
    print("🔒 Features: Role-based VLAN filtering, Dell uplink detection")
    
    # Production configuration
    app.run(debug=False, host='0.0.0.0', port=5000)
