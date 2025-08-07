#!/usr/bin/env python3
"""
Dell Switch Port Tracer & VLAN Manager - Enterprise Edition
===========================================================

A comprehensive network management solution for Dell switches featuring
MAC address tracing and advanced VLAN management capabilities.

🏢 ENTERPRISE FEATURES:
- Multi-site, multi-floor switch management (27+ sites, 155+ switches)
- Advanced VLAN Manager with port assignment and safety checks
- Windows AD integration with role-based permissions (OSS/NetAdmin/SuperAdmin)
- Dell N2000/N3000/N3200 series switch support (N2048, N3024P, N3248 models)
- Real-time MAC address tracing with port configuration details
- Comprehensive audit logging and monitoring
- Modern, responsive web interface with KMC branding

🔧 VLAN MANAGEMENT CAPABILITIES:
- Port VLAN assignment with safety validation
- Uplink port protection and detection
- VLAN creation and naming standardization
- Port description management
- Preview and confirmation workflows
- Switch model-aware interface naming

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
- CPU safety monitoring
- Switch protection status monitoring
- Detailed audit trails with timing
- Enhanced error handling and logging
- Progress tracking for large batches

Repository: https://github.com/Crispy-Pasta/DellPortTracer
Version: 2.1.1
Author: Network Operations Team
Last Updated: January 2025 - VLAN Manager & Enhanced UI
License: MIT

🔧 TROUBLESHOOTING:
- Check logs: port_tracer.log (system) | audit.log (user actions)
- Monitor concurrent users per site in CONCURRENT_USERS_PER_SITE
- Verify Dell switch SSH limits (max 10 concurrent sessions)
- Review environment variables for performance tuning
- VLAN operations require NetAdmin or SuperAdmin privileges
"""

import paramiko
import logging
import logging.handlers
import time
import psutil
import json
import os
from datetime import datetime
from flask import Flask, render_template_string, request, jsonify, session, redirect, url_for
from flask_httpauth import HTTPBasicAuth
from flask_sqlalchemy import SQLAlchemy
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

# Load CPU Safety Monitor
from cpu_safety_monitor import initialize_cpu_monitor, get_cpu_monitor

# Load Switch Protection Monitor
try:
    from switch_protection_monitor import initialize_switch_protection_monitor, get_switch_protection_monitor
    SWITCH_PROTECTION_AVAILABLE = True
except ImportError:
    SWITCH_PROTECTION_AVAILABLE = False

# Load environment variables first
load_dotenv()

# Flask app
app = Flask(__name__)
app.secret_key = secrets.token_hex(16)
auth = HTTPBasicAuth()

# Database configuration - PostgreSQL by default
postgres_host = os.getenv('POSTGRES_HOST', 'localhost')
postgres_port = os.getenv('POSTGRES_PORT', '5432')
postgres_db = os.getenv('POSTGRES_DB', 'dell_port_tracer')
postgres_user = os.getenv('POSTGRES_USER', 'dell_tracer_user')
postgres_password = os.getenv('POSTGRES_PASSWORD', 'dell_tracer_pass')

# Construct PostgreSQL connection URL
default_db_url = f'postgresql://{postgres_user}:{postgres_password}@{postgres_host}:{postgres_port}/{postgres_db}'

# Allow override via DATABASE_URL environment variable
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('DATABASE_URL', default_db_url)
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SQLALCHEMY_ENGINE_OPTIONS'] = {
    'pool_recycle': 300,  # Recycle connections every 5 minutes
    'pool_pre_ping': True  # Verify connections before use
}

# Initialize database
from database import db, Site, Floor, Switch
db.init_app(app)

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

# Configure logging with optional syslog support
handlers = [
    logging.FileHandler('port_tracer.log'),
    logging.StreamHandler()
]

# Add syslog handler if configured and available (SolarWinds SEM compatible)
syslog_server = os.getenv('SYSLOG_SERVER')
syslog_enabled = os.getenv('SYSLOG_ENABLED', 'false').lower() == 'true'
if syslog_enabled and syslog_server and syslog_server.lower() not in ['', 'none', 'disabled']:
    try:
        syslog_port = int(os.getenv('SYSLOG_PORT', 514))
        # Use facility LOCAL0 (16) for custom applications - SolarWinds SEM friendly
        syslog_handler = logging.handlers.SysLogHandler(
            address=(syslog_server, syslog_port),
            facility=logging.handlers.SysLogHandler.LOG_LOCAL0
        )
        # RFC3164 compliant format for better SolarWinds SEM parsing
        syslog_formatter = logging.Formatter(
            'Dell-Port-Tracer[%(process)d]: %(levelname)s - %(funcName)s - %(message)s'
        )
        syslog_handler.setFormatter(syslog_formatter)
        handlers.append(syslog_handler)
        print(f"✅ Syslog logging enabled for SolarWinds SEM: {syslog_server}:{syslog_port} (LOCAL0 facility)")
        
        # Send initial test message to confirm syslog connectivity
        test_logger = logging.getLogger('syslog_test')
        test_logger.addHandler(syslog_handler)
        test_logger.setLevel(logging.INFO)
        test_logger.info("Dell Port Tracer application started - Syslog connectivity test")
        
    except Exception as e:
        print(f"⚠️  Warning: Could not connect to syslog server {syslog_server}: {str(e)}")
        print("   Continuing without syslog logging...")

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=handlers
)
logger = logging.getLogger(__name__)

# Log credential loading status for monitoring (after logger is initialized)
logger.info(f"Switch credentials loaded - Username: {'SET' if SWITCH_USERNAME else 'NOT_SET'}, Password: {'SET' if SWITCH_PASSWORD else 'NOT_SET'}")

# CPU Safety configuration (override concurrent limits based on CPU protection zones)
cpu_monitor = initialize_cpu_monitor(
    green_threshold=float(os.getenv('CPU_GREEN_THRESHOLD', '40')),
    yellow_threshold=float(os.getenv('CPU_YELLOW_THRESHOLD', '60')),
    red_threshold=float(os.getenv('CPU_RED_THRESHOLD', '80'))
)

# Switch Protection Monitor initialization
switch_monitor = None
if SWITCH_PROTECTION_AVAILABLE:
    switch_monitor = initialize_switch_protection_monitor(
        max_connections_per_switch=int(os.getenv('MAX_CONNECTIONS_PER_SWITCH', '8')),
        max_total_connections=int(os.getenv('MAX_TOTAL_CONNECTIONS', '64')),
        commands_per_second_limit=int(os.getenv('COMMANDS_PER_SECOND_LIMIT', '10'))
    )
    logger.info("Switch protection monitor initialized")
else:
    logger.warning("Switch protection monitor not available - switches may be vulnerable to overload")

# Concurrent user tracking per site (Dell switch limit: 10 concurrent SSH sessions)
CONCURRENT_USERS_PER_SITE = defaultdict(lambda: {'count': 0, 'lock': threading.Lock()})
MAX_CONCURRENT_USERS_PER_SITE = int(os.getenv('MAX_CONCURRENT_USERS_PER_SITE', '10'))
MAX_WORKERS_PER_SITE = int(os.getenv('MAX_WORKERS_PER_SITE', '8'))  # Parallel switch connections

# Audit logging for user actions (with optional syslog support)
audit_logger = logging.getLogger('audit')
audit_handler = logging.FileHandler('audit.log')
audit_formatter = logging.Formatter('%(asctime)s - AUDIT - %(message)s')
audit_handler.setFormatter(audit_formatter)
audit_logger.addHandler(audit_handler)

# Add syslog handler for audit logs if syslog is enabled
if syslog_enabled and syslog_server and syslog_server.lower() not in ['', 'none', 'disabled']:
    try:
        audit_syslog_handler = logging.handlers.SysLogHandler(
            address=(syslog_server, syslog_port),
            facility=logging.handlers.SysLogHandler.LOG_LOCAL1  # Use LOCAL1 for audit logs
        )
        audit_syslog_formatter = logging.Formatter(
            'Dell-Port-Tracer-AUDIT[%(process)d]: %(levelname)s - %(message)s'
        )
        audit_syslog_handler.setFormatter(audit_syslog_formatter)
        audit_logger.addHandler(audit_syslog_handler)
        print(f"✅ Audit syslog logging enabled: {syslog_server}:{syslog_port} (LOCAL1 facility)")
    except Exception as e:
        print(f"⚠️  Warning: Could not configure audit syslog: {str(e)}")

audit_logger.setLevel(logging.INFO)

# Load switches configuration
def load_switches():
    """Load switches from PostgreSQL."""
    try:
        sites_with_switches = {}
        sites = Site.query.all()
        for site in sites:
            floors = Floor.query.filter_by(site_id=site.id).all()
            floors_with_switches = {}
            for floor in floors:
                switches = Switch.query.filter_by(floor_id=floor.id, enabled=True).all()
                switch_data = [{'name': sw.name, 'ip': sw.ip_address} for sw in switches]
                if switch_data:
                    floors_with_switches[floor.name] = switch_data
            if floors_with_switches:
                sites_with_switches[site.name] = floors_with_switches
        if not sites_with_switches:
            return {"sites": []}
        else:
            return {"sites": sites_with_switches}
    except Exception as e:
        logger.error(f"Failed to load switches from the database: {str(e)}")
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
    # Check for N3248 first (explicit Dell N3248 model detection)
    if 'N3248' in model:
        return 'N3200'
    elif 'N2000' in model or 'N20' in model:
        return 'N2000'
    elif 'N3200' in model or 'N32' in model:
        return 'N3200' 
    elif 'N3000' in model or 'N30' in model:
        return 'N3000'
    
    # Fallback: try to infer from switch name patterns
    name_upper = switch_name.upper()
    if any(pattern in name_upper for pattern in ['N2000', 'N20']):
        return 'N2000'
    elif any(pattern in name_upper for pattern in ['N3200', 'N32', 'N3248']):
        return 'N3200'
    elif any(pattern in name_upper for pattern in ['N3000', 'N30']):
        return 'N3000'
    
    # Default assumption (only if unknown model)
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
            'icon': '🚨',
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
        
        # Removed trunk_many_vlans caution as requested
        pass
    
    return cautions

def apply_role_based_filtering(results, user_role):
    """Apply role-based filtering to trace results."""
    permissions = get_user_permissions(user_role)
    filtered_results = []
    
    for result in results:
        if result['status'] != 'found':
            filtered_results.append(result)
            continue
            
        # For OSS users, filter out uplink ports
        if not permissions['show_uplink_ports']:
            # Detect switch model from database first, then fallback to configuration
            switch_model = 'N3000'  # Default fallback
            try:
                # Try to get switch model from database with Flask app context
                with app.app_context():
                    switch_obj = Switch.query.filter_by(ip_address=result['switch_ip']).first()
                    if switch_obj and switch_obj.model:
                        # Use database switch model directly
                        switch_model = detect_switch_model_from_config(switch_obj.name, {'model': switch_obj.model})
                    else:
                        # Fallback to JSON configuration
                        switches_config = load_switches()
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
    """Dell switch SSH connection handler with protection monitoring."""
    
    def __init__(self, ip_address, username, password, switch_monitor=None):
        self.ip_address = ip_address
        self.username = username
        self.password = password
        self.ssh_client = None
        self.shell = None
        self.switch_monitor = switch_monitor
    
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
        success = False
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
            success = True
            return output
            
        except Exception as e:
            logger.error(f"Failed to execute MAC lookup on {self.ip_address}: {str(e)}")
            raise
        finally:
            # Record command execution for monitoring
            if self.switch_monitor:
                self.switch_monitor.record_command_execution(self.ip_address, success)
    
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
    """Get switches for specific site and floor from database."""
    try:
        # Query database for switches
        site_obj = Site.query.filter_by(name=site).first()
        if not site_obj:
            return []
            
        floor_obj = Floor.query.filter_by(site_id=site_obj.id, name=floor).first()
        if not floor_obj:
            return []
            
        switches = Switch.query.filter_by(floor_id=floor_obj.id, enabled=True).all()
        
        matching_switches = []
        for switch in switches:
            matching_switches.append({
                'name': switch.name,
                'ip': switch.ip_address,
                'site': site,
                'floor': floor
            })
        
        return matching_switches
    except Exception as e:
        logger.error(f"Database error in get_site_floor_switches: {str(e)}")
        # Fallback to JSON if database fails
        return get_site_floor_switches_json(site, floor)

def get_site_floor_switches_json(site, floor):
    """Fallback function to get switches from JSON when database fails."""
    switches_config = load_switches()
    matching_switches = []
    
    # Handle the JSON structure from database fallback
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
    """Convert PostgreSQL database format for frontend consumption."""
    try:
        # Query PostgreSQL database for all sites with floors and switches
        sites = Site.query.all()
        formatted_sites = []
        
        for site in sites:
            floors = []
            for floor in site.floors:
                switches = []
                # Only include enabled switches
                enabled_switches = [s for s in floor.switches if s.enabled]
                
                for switch in enabled_switches:
                    # Always use actual switch names in data structure
                    # Role-based filtering will be handled in frontend JavaScript
                    switches.append({
                        'name': switch.name,
                        'ip': switch.ip_address,
                        'model': switch.model or 'Unknown',
                        'description': switch.description or ''
                    })
                
                if switches:  # Only include floors with enabled switches
                    floors.append({
                        'floor': floor.name,
                        'switches': switches
                    })
            
            if floors:  # Only include sites with floors that have switches
                formatted_sites.append({
                    'name': site.name,
                    'location': f"{site.name.upper()} Site",
                    'floors': floors
                })
        
        return {'sites': formatted_sites}
        
    except Exception as e:
        logger.error(f"Database error in format_switches_for_frontend: {str(e)}")
        # Fallback to JSON if database fails
        return format_switches_for_frontend_json(user_role)

def format_switches_for_frontend_json(user_role='oss'):
    """Fallback function to convert database format for frontend consumption."""
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
    
    # Check switch-side protection limits before attempting connection
    if switch_monitor and SWITCH_PROTECTION_AVAILABLE:
        if not switch_monitor.acquire_switch_connection(switch_ip, username):
            return {
                'switch_name': switch_name,
                'switch_ip': switch_ip,
                'status': 'connection_rejected',
                'message': 'Switch connection rejected due to protection limits. Please try again in a moment.'
            }
    
    try:
        # Log connection attempt for monitoring
        logger.debug(f"Attempting connection to switch {switch_ip}")
        
        switch = DellSwitchSSH(switch_ip, SWITCH_USERNAME, SWITCH_PASSWORD, switch_monitor)
        
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
                # Try to get switch model from database first, then fallback to configuration
                with app.app_context():
                    switch_obj = Switch.query.filter_by(ip_address=switch_ip).first()
                    if switch_obj and switch_obj.model:
                        # Use database switch model directly
                        switch_model = detect_switch_model_from_config(switch_obj.name, {'model': switch_obj.model})
                    else:
                        # Fallback to JSON configuration
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
        
        # Always release switch connection slot
        if switch_monitor and SWITCH_PROTECTION_AVAILABLE:
            switch_monitor.release_switch_connection(switch_ip, username)

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
MANAGE_TEMPLATE = """
<!DOCTYPE html>
<html>
<head>
    <title>Manage Switches</title>
    <link rel="stylesheet" href="{{ url_for('static', filename='styles.css') }}?v=4.0">
    <link href="https://cdn.jsdelivr.net/npm/select2@4.1.0-rc.0/dist/css/select2.min.css" rel="stylesheet" />
    <script src="https://code.jquery.com/jquery-3.6.0.min.js"></script>
    <script src="https://cdn.jsdelivr.net/npm/select2@4.1.0-rc.0/dist/js/select2.min.js"></script>
    <style>
        .manage-container {
            display: flex;
            gap: 15px;
            margin-top: 0px;
            align-items: flex-start;
            max-width: 100%;
            overflow-x: auto;
            min-height: 280px;
        }
        .form-container, .table-container {
            flex: 1;
        }
        .form-container {
            max-width: 280px;
            flex-shrink: 0;
            min-height: 300px;
        }
        .table-container {
            min-width: 1000px;
            max-width: calc(100% - 304px);
            flex: 1;
            overflow-x: auto;
        }
        .search-container {
            display: flex;
            gap: 10px;
            margin-bottom: 15px;
            align-items: center;
        }
        #search-input {
            flex: 1;
            padding: 10px 12px;
            border: 1px solid var(--light-blue);
            border-radius: 6px;
            font-size: 14px;
        }
        .stats-bar {
            display: flex;
            gap: 15px;
            margin-bottom: 10px;
            padding: 8px;
            background: #f8fafc;
            border-radius: 8px;
            border: 1px solid var(--light-blue);
        }
        .stat-item {
            text-align: center;
            flex: 1;
        }
        .stat-number {
            font-size: 24px;
            font-weight: bold;
            color: var(--orange);
        }
        .stat-label {
            font-size: 12px;
            color: var(--rich-black);
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }
        .table-wrapper {
            background: white;
            border-radius: 8px;
            border: 1px solid var(--light-blue);
            overflow-x: auto;
            overflow-y: hidden;
        }
                        #switches-table {
                    width: 100%;
                    border-collapse: collapse;
                    font-size: 14px;
                    table-layout: fixed;
                    min-width: 1000px;
                }
        #switches-table th {
            background: var(--deep-navy);
            color: white;
            padding: 12px 8px;
            text-align: left;
            font-weight: 600;
        }
        #switches-table th:nth-child(1) { width: 25%; } /* Name */
        #switches-table th:nth-child(2) { width: 15%; } /* IP Address */
        #switches-table th:nth-child(3) { width: 15%; } /* Model */
        #switches-table th:nth-child(4) { width: 12%; } /* Site */
        #switches-table th:nth-child(5) { width: 8%; text-align: center; } /* Floor */
        #switches-table th:nth-child(6) { width: 12%; text-align: center; } /* Status */
        #switches-table th:nth-child(7) { width: 13%; } /* Actions */
        #switches-table td {
            padding: 8px 6px;
            border-bottom: 1px solid #eee;
            vertical-align: middle;
        }
        #switches-table td:nth-child(5) { text-align: center; } /* Floor */
        #switches-table td:nth-child(6) { text-align: center; } /* Status */
        #switches-table tr:hover {
            background: #f8fafc;
        }
        .action-buttons {
            display: flex;
            gap: 4px;
            justify-content: flex-start;
            flex-wrap: nowrap;
            min-width: 80px;
        }
        .btn-small {
            padding: 4px 6px;
            font-size: 11px;
            border-radius: 4px;
            border: none;
            cursor: pointer;
            font-weight: 500;
            white-space: nowrap;
            min-width: 35px;
            text-align: center;
            display: inline-block;
        }
        .btn-edit {
            background: var(--orange);
            color: white;
        }
        .btn-edit:hover {
            background: var(--deep-navy);
        }
        .btn-delete {
            background: #dc3545;
            color: white;
        }
        .btn-delete:hover {
            background: #c82333;
        }
        .status-badge {
            padding: 3px 8px;
            border-radius: 12px;
            font-size: 10px;
            font-weight: bold;
            text-transform: uppercase;
            display: inline-block;
            text-align: center;
            min-width: 60px;
        }
        .status-enabled {
            background: #d4edda;
            color: #155724;
        }
        .status-disabled {
            background: #f8d7da;
            color: #721c24;
        }
        .toast {
            position: fixed;
            top: 20px;
            right: 20px;
            padding: 15px 20px;
            border-radius: 8px;
            color: white;
            z-index: 1000;
            opacity: 0;
            transition: all 0.3s ease;
            box-shadow: 0 4px 12px rgba(0,0,0,0.15);
            max-width: 300px;
        }
        .toast.show {
            opacity: 1;
            transform: translateX(0);
        }
        .toast.success {
            background: linear-gradient(135deg, #28a745, #20c997);
        }
        .toast.error {
            background: linear-gradient(135deg, #dc3545, #e74c3c);
        }
        .form-group {
            margin-bottom: 8px;
        }
        .form-group label {
            display: block;
            margin-bottom: 3px;
            font-weight: 600;
            color: var(--deep-navy);
        }
        .checkbox-group {
            display: flex;
            align-items: center;
            gap: 8px;
            margin: 10px 0;
        }
        .checkbox-group input[type="checkbox"] {
            width: auto;
            margin: 0;
        }
        .form-actions {
            display: flex;
            gap: 10px;
            margin-top: 15px;
        }
        .btn-secondary {
            background: #6c757d;
            color: white;
        }
        .btn-secondary:hover {
            background: #5a6268;
        }
        .loading {
            text-align: center;
            padding: 20px;
            color: var(--orange);
        }
        .empty-state {
            text-align: center;
            padding: 40px 20px;
            color: #6c757d;
        }
        .empty-state i {
            font-size: 48px;
            margin-bottom: 10px;
            opacity: 0.5;
        }
        /* Fix dropdown widths on manage switches page - Override global styles */
        .manage-page .form-group select {
            max-width: 250px !important;
            width: 250px !important;
            min-width: 250px !important;
        }
        .manage-page .select2-container {
            max-width: 250px !important;
            width: 250px !important;
            min-width: 250px !important;
        }
        .manage-page .select2-container .select2-selection {
            max-width: 250px !important;
            width: 250px !important;
            min-width: 250px !important;
        }
        .manage-page .select2-container--default .select2-selection--single {
            max-width: 250px !important;
            width: 250px !important;
            min-width: 250px !important;
        }
        /* Override specific global selectors */
        body.manage-page #site-select,
        body.manage-page #floor-select {
            max-width: 250px !important;
            width: 250px !important;
            min-width: 250px !important;
        }
        /* Override global Select2 container styles */
        body.manage-page .select2-container {
            max-width: 250px !important;
            width: 250px !important;
            min-width: 250px !important;
        }
        body.manage-page .select2-container--default .select2-selection--single {
            max-width: 250px !important;
            width: 250px !important;
            min-width: 250px !important;
        }
        /* Force Select2 containers in form groups */
        body.manage-page .form-group .select2-container {
            max-width: 250px !important;
            width: 250px !important;
            min-width: 250px !important;
        }
        body.manage-page .form-group .select2-container--default .select2-selection--single {
            max-width: 250px !important;
            width: 250px !important;
            min-width: 250px !important;
        }

    </style>
</head>
<body class="main-page manage-page">
    <div class="container">
        <div class="user-info">Logged in as: {{ username }} | <a href="/logout">Logout</a></div>
        <div style="text-align:center; margin-bottom: 10px;">
            <img src="{{ url_for('static', filename='img/kmc_logo.png') }}" alt="KMC Logo" style="height: 60px; margin-bottom: 8px; display:block; margin-left:auto; margin-right:auto;">
        </div>
        <div style="text-align:center; margin-bottom: 18px;">
            <h1 style="margin:0;">Switch Management</h1>
        </div>
        
        <div class="navigation-bar">
            <div class="nav-links">
                <a href="/" class="nav-link">🔍 Port Tracer</a>
                <a href="/vlan" class="nav-link">🔧 VLAN Manager</a>
                <a href="/manage" class="nav-link active">⚙️ Manage Switches</a>
                <a href="/cpu-status" class="nav-link" target="_blank">📊 CPU Status</a>
                <a href="/switch-protection-status" class="nav-link" target="_blank">🛡️ Protection Status</a>
            </div>
        </div>

        <div class="stats-bar">
            <div class="stat-item">
                <div class="stat-number" id="total-switches">-</div>
                <div class="stat-label">Total Switches</div>
            </div>
            <div class="stat-item">
                <div class="stat-number" id="enabled-switches">-</div>
                <div class="stat-label">Enabled</div>
            </div>
            <div class="stat-item">
                <div class="stat-number" id="disabled-switches">-</div>
                <div class="stat-label">Disabled</div>
            </div>
            <div class="stat-item">
                <div class="stat-number" id="total-sites">-</div>
                <div class="stat-label">Sites</div>
            </div>
        </div>

        <div class="manage-container">
            <div class="form-container">
                <div class="step">
                    <h3>📝 Add/Edit Switch</h3>
                    <form id="switch-form">
                        <input type="hidden" id="switch-id" name="id">
                        
                        <div class="form-group">
                            <label for="switch-name">Switch Name</label>
                            <input type="text" id="switch-name" name="name" placeholder="e.g., SW-F11-R1-VAS-01" required>
                        </div>
                        
                        <div class="form-group">
                            <label for="switch-ip">IP Address</label>
                            <input type="text" id="switch-ip" name="ip_address" placeholder="e.g., 10.50.0.10" required>
                        </div>
                        
                        <div class="form-group">
                            <label for="switch-model">Model</label>
                            <input type="text" id="switch-model" name="model" placeholder="e.g., Dell N3248" required>
                        </div>
                        
                        <div class="form-group">
                            <label for="switch-description">Description</label>
                            <input type="text" id="switch-description" name="description" placeholder="e.g., Floor 11 VAS Switch">
                        </div>
                        
                        <div class="form-group">
                            <label for="site-select">Site</label>
                            <select id="site-select" name="site_id" required>
                                <option value="">Select site...</option>
                            </select>
                        </div>
                        
                        <div class="form-group">
                            <label for="floor-select">Floor</label>
                            <select id="floor-select" name="floor_id" required disabled>
                                <option value="">Select floor...</option>
                            </select>
                        </div>
                        
                        <div class="checkbox-group">
                            <input type="checkbox" id="switch-enabled" name="enabled" checked>
                            <label for="switch-enabled">Switch is enabled</label>
                        </div>
                        
                        <div class="form-actions">
                            <button type="submit" id="save-btn">💾 Save</button>
                            <button type="button" id="clear-form-btn" class="btn-secondary">🗑️ Clear</button>
                        </div>
                    </form>
                </div>
            </div>
            
            <div class="table-container">
                <div class="step">
                    <h3>📋 Switch Inventory</h3>
                    <div class="search-container">
                        <input type="text" id="search-input" placeholder="🔍 Search switches by name, IP, model, site, or floor...">
                        <button type="button" id="refresh-btn" style="padding: 10px 15px; background: var(--orange); color: white; border: none; border-radius: 6px; cursor: pointer;">🔄 Refresh</button>
                    </div>
                    
                    <div class="table-wrapper">
                        <table id="switches-table">
                            <thead>
                                <tr>
                                    <th>Switch Name</th>
                                    <th>IP Address</th>
                                    <th>Model</th>
                                    <th>Site</th>
                                    <th>Floor</th>
                                    <th>Status</th>
                                    <th>Actions</th>
                                </tr>
                            </thead>
                            <tbody>
                                <tr>
                                    <td colspan="7" class="loading">Loading switches...</td>
                                </tr>
                            </tbody>
                        </table>
                    </div>
                </div>
            </div>
        </div>
    </div>
    
    <div id="toast" class="toast"></div>
    
    <script>
        document.addEventListener('DOMContentLoaded', function() {
            const form = document.getElementById('switch-form');
            const tableBody = document.querySelector('#switches-table tbody');
            const siteSelect = document.getElementById('site-select');
            const floorSelect = document.getElementById('floor-select');
            const searchInput = document.getElementById('search-input');
            const toast = document.getElementById('toast');
            const refreshBtn = document.getElementById('refresh-btn');
            let allSwitches = [];
            let allSites = [];

            // Initialize Select2 for both dropdowns with forced width
            $('#site-select').select2({
                placeholder: 'Select site...',
                allowClear: true,
                width: '250px'
            });
            
            $('#floor-select').select2({
                placeholder: 'Select floor...',
                allowClear: true,
                width: '250px'
            });
            
            // Force width after Select2 initialization
            setTimeout(function() {
                $('.manage-page .select2-container').css({
                    'width': '250px !important',
                    'max-width': '250px !important',
                    'min-width': '250px !important'
                });
                $('.manage-page .select2-container .select2-selection').css({
                    'width': '250px !important',
                    'max-width': '250px !important',
                    'min-width': '250px !important'
                });
            }, 100);

            function showToast(message, type) {
                toast.textContent = message;
                toast.className = `toast show ${type}`;
                setTimeout(() => {
                    toast.className = toast.className.replace('show', '');
                }, 4000);
            }

            function updateStats() {
                const total = allSwitches.length;
                const enabled = allSwitches.filter(s => s.enabled).length;
                const disabled = total - enabled;
                const sites = new Set(allSwitches.map(s => s.site_name)).size;

                document.getElementById('total-switches').textContent = total;
                document.getElementById('enabled-switches').textContent = enabled;
                document.getElementById('disabled-switches').textContent = disabled;
                document.getElementById('total-sites').textContent = sites;
            }

            function loadSites() {
                return fetch('/api/sites')
                    .then(response => response.json())
                    .then(data => {
                        allSites = data;
                        
                        // Populate site dropdown
                        siteSelect.innerHTML = '<option value="">Select site...</option>';
                        data.forEach(site => {
                            const option = document.createElement('option');
                            option.value = site.id;
                            option.textContent = site.name;
                            siteSelect.appendChild(option);
                        });
                        $('#site-select').trigger('change');
                        
                        // Initialize floor dropdown as empty and disabled
                        floorSelect.innerHTML = '<option value="">Select floor...</option>';
                        floorSelect.disabled = true;
                        $('#floor-select').trigger('change');
                    });
            }
            
            // Handle site selection to populate floor dropdown
            $('#site-select').on('change', function() {
                const selectedSiteId = $(this).val();
                floorSelect.innerHTML = '<option value="">Select floor...</option>';
                
                if (selectedSiteId) {
                    const selectedSite = allSites.find(site => site.id == selectedSiteId);
                    if (selectedSite) {
                        selectedSite.floors.forEach(floor => {
                            const option = document.createElement('option');
                            option.value = floor.id;
                            option.textContent = floor.name;
                            floorSelect.appendChild(option);
                        });
                        floorSelect.disabled = false;
                    }
                } else {
                    floorSelect.disabled = true;
                }
                $('#floor-select').trigger('change');
            });

            function renderTable(switches) {
                if (switches.length === 0) {
                    tableBody.innerHTML = `
                        <tr>
                            <td colspan="7" class="empty-state">
                                <div>📭</div>
                                <div>No switches found</div>
                                <div style="font-size: 12px; margin-top: 5px;">Try adjusting your search criteria</div>
                            </td>
                        </tr>
                    `;
                    return;
                }

                tableBody.innerHTML = '';
                switches.forEach(switchData => {
                    const row = document.createElement('tr');
                    row.innerHTML = `
                        <td><strong>${switchData.name}</strong></td>
                        <td><code>${switchData.ip_address}</code></td>
                        <td>${switchData.model}</td>
                        <td>${switchData.site_name}</td>
                        <td>${switchData.floor_name.replace('Floor ', '')}</td>
                        <td>
                            <span class="status-badge ${switchData.enabled ? 'status-enabled' : 'status-disabled'}">
                                ${switchData.enabled ? 'Enabled' : 'Disabled'}
                            </span>
                        </td>
                        <td>
                            <div class="action-buttons">
                                <button class="btn-small btn-edit edit-btn" data-id="${switchData.id}" title="Edit switch">
                                    ✏️ Edit
                                </button>
                                <button class="btn-small btn-delete delete-btn" data-id="${switchData.id}" title="Delete switch">
                                    🗑️ Delete
                                </button>
                            </div>
                        </td>
                    `;
                    tableBody.appendChild(row);
                });
            }

            function loadSwitches() {
                tableBody.innerHTML = '<tr><td colspan="7" class="loading">Loading switches...</td></tr>';
                
                fetch('/api/switches')
                    .then(response => response.json())
                    .then(data => {
                        allSwitches = data;
                        renderTable(allSwitches);
                        updateStats();
                    })
                    .catch(error => {
                        console.error('Error:', error);
                        tableBody.innerHTML = '<tr><td colspan="7" class="empty-state">❌ Error loading switches</td></tr>';
                        showToast('Error loading switches', 'error');
                    });
            }

            // Search functionality
            searchInput.addEventListener('input', () => {
                const searchTerm = searchInput.value.toLowerCase();
                const filteredSwitches = allSwitches.filter(sw => 
                    sw.name.toLowerCase().includes(searchTerm) ||
                    sw.ip_address.toLowerCase().includes(searchTerm) ||
                    sw.model.toLowerCase().includes(searchTerm) ||
                    sw.site_name.toLowerCase().includes(searchTerm) ||
                    sw.floor_name.toLowerCase().includes(searchTerm)
                );
                renderTable(filteredSwitches);
            });

            // Form submission
            form.addEventListener('submit', function(event) {
                event.preventDefault();
                const switchId = document.getElementById('switch-id').value;
                const formData = new FormData(form);
                const data = Object.fromEntries(formData.entries());
                const saveBtn = document.getElementById('save-btn');

                // Disable button and show loading state
                saveBtn.disabled = true;
                saveBtn.textContent = switchId ? '🔄 Updating...' : '🔄 Creating...';

                // Convert site_id to floor_id for API compatibility
                if (data.site_id && data.floor_id) {
                    // The floor_id is already correct, just remove site_id
                    delete data.site_id;
                }

                const url = switchId ? `/api/switches/${switchId}` : '/api/switches';
                const method = switchId ? 'PUT' : 'POST';

                fetch(url, {
                    method: method,
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify(data)
                })
                .then(response => response.json())
                .then(result => {
                    if (result.error) {
                        showToast(result.error, 'error');
                    } else {
                        showToast(result.message, 'success');
                        form.reset();
                        document.getElementById('switch-id').value = '';
                        $('#floor-select').val('').trigger('change');
                        loadSwitches();
                    }
                })
                .catch(error => {
                    console.error('Error:', error);
                    showToast('Error saving switch', 'error');
                })
                .finally(() => {
                    saveBtn.disabled = false;
                    saveBtn.textContent = switchId ? '💾 Update' : '💾 Save';
                });
            });

            // Table actions
            tableBody.addEventListener('click', function(event) {
                if (event.target.classList.contains('edit-btn')) {
                    const switchId = event.target.dataset.id;
                    const switchData = allSwitches.find(s => s.id == switchId);
                    
                    document.getElementById('switch-id').value = switchData.id;
                    document.getElementById('switch-name').value = switchData.name;
                    document.getElementById('switch-ip').value = switchData.ip_address;
                    document.getElementById('switch-model').value = switchData.model;
                    document.getElementById('switch-description').value = switchData.description || '';
                    document.getElementById('switch-enabled').checked = switchData.enabled;
                    
                    // Set site first, then floor
                    $('#site-select').val(switchData.site_id).trigger('change');
                    
                    // Wait for floor dropdown to populate, then set floor
                    setTimeout(() => {
                        $('#floor-select').val(switchData.floor_id).trigger('change');
                    }, 100);
                    
                    // Update form button text
                    document.getElementById('save-btn').textContent = '💾 Update';
                    
                    // Scroll to form
                    document.querySelector('.form-container').scrollIntoView({ behavior: 'smooth' });
                    
                } else if (event.target.classList.contains('delete-btn')) {
                    const switchId = event.target.dataset.id;
                    const switchData = allSwitches.find(s => s.id == switchId);
                    
                    if (confirm(`Are you sure you want to delete switch "${switchData.name}" (${switchData.ip_address})?\\n\\nThis action cannot be undone.`)) {
                        fetch(`/api/switches/${switchId}`, { method: 'DELETE' })
                            .then(response => response.json())
                            .then(result => {
                                if (result.error) {
                                    showToast(result.error, 'error');
                                } else {
                                    showToast(result.message, 'success');
                                    loadSwitches();
                                }
                            })
                            .catch(error => {
                                console.error('Error:', error);
                                showToast('Error deleting switch', 'error');
                            });
                    }
                }
            });

            // Clear form
            document.getElementById('clear-form-btn').addEventListener('click', () => {
                form.reset();
                document.getElementById('switch-id').value = '';
                $('#site-select').val('').trigger('change');
                $('#floor-select').val('').trigger('change');
                floorSelect.disabled = true;
                document.getElementById('save-btn').textContent = '💾 Save';
            });

            // Refresh button
            refreshBtn.addEventListener('click', () => {
                loadSwitches();
                showToast('Switches refreshed', 'success');
            });

            // Initialize
            loadSites().then(() => {
                loadSwitches();
            });
        });
    </script>
</body>
</html>
"""
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
            <img src="{{ url_for('static', filename='img/kmc_logo.png') }}" alt="KMC Logo" style="height: 80px; margin-bottom: 6px;">
        </div>
        <h1 style="text-align:center;">Switch Port Tracer</h1>
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
        <div style="text-align:center; margin-bottom: 18px;">
            <h1 style="margin:0;">Switch Port Tracer</h1>
        </div>
        
        <div class="navigation-bar">
            <div class="nav-links">
                <a href="/" class="nav-link active">🔍 Port Tracer</a>
                {% if user_role in ['netadmin', 'superadmin'] %}
                <a href="/vlan" class="nav-link">🔧 VLAN Manager</a>
                <a href="/manage" class="nav-link">⚙️ Manage Switches</a>
                <a href="/cpu-status" class="nav-link" target="_blank">📊 CPU Status</a>
                <a href="/switch-protection-status" class="nav-link" target="_blank">🛡️ Protection Status</a>
                {% endif %}
            </div>
        </div>
        <div class="step">
            <h3>Step 1: Select Site and Floor</h3>
            <div style="margin-bottom: 15px;">
                <select id="site" onchange="loadFloors()">
                    <option value="">Select Site...</option>
                    {% for site in sites %}
                    <option value="{{ site.name }}">{{ site.name }} ({{ site.location }})</option>
                    {% endfor %}
                </select>
            </div>
            <div style="margin-bottom: 15px;">
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
                foundResults.forEach((result, index) => {
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
                    
                    // Check if this result has an uplink caution
                    const hasUplinkCaution = result.cautions && result.cautions.some(caution => caution.type === 'uplink');
                    const resultClass = hasUplinkCaution ? 'result-item found uplink-detected' : 'result-item found';
                    
                    html += `
                        <div class="${resultClass}">
                            <strong>✅ MAC Found!</strong>${cautionLine}<br>
                            <strong>Switch:</strong> ${result.switch_name} (${result.switch_ip})<br>
                            ${portInfo}${descriptionInfo}<br>
                            ${vlanInfo}
                        </div>
                    `;
                    
                    // Add Additional Information section between result boxes (after first result)
                    if (index === 0 && foundResults.length > 1) {
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

# Implement a before_request hook to check CPU load before processing requests
@app.before_request
def check_cpu_before_request():
    # Only check CPU for compute-intensive operations
    if request.endpoint in ['trace']:
        can_accept, reason = cpu_monitor.can_accept_request()
        if not can_accept:
            return jsonify({'status': 'error', 'message': reason}), 503  # Service Unavailable

# Routes
@app.route('/cpu-status')
def cpu_status():
    """CPU monitoring status endpoint for admin users."""
    if 'username' not in session:
        return jsonify({'error': 'Not authenticated'}), 401
    
    user_role = session.get('role', 'oss')
    if user_role not in ['netadmin', 'superadmin']:
        return jsonify({'error': 'Insufficient permissions'}), 403
    
    try:
        stats = cpu_monitor.get_statistics()
        return jsonify(stats), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/switch-protection-status')
def switch_protection_status():
    """Switch protection monitoring status endpoint for admin users."""
    if 'username' not in session:
        return jsonify({'error': 'Not authenticated'}), 401
    
    user_role = session.get('role', 'oss')
    if user_role not in ['netadmin', 'superadmin']:
        return jsonify({'error': 'Insufficient permissions'}), 403
    
    if not switch_monitor or not SWITCH_PROTECTION_AVAILABLE:
        return jsonify({'error': 'Switch protection monitoring not available'}), 503
    
    try:
        global_stats = switch_monitor.get_global_stats()
        return jsonify({
            'status': 'active',
            'timestamp': datetime.now().isoformat(),
            'global_stats': global_stats,
            'configuration': {
                'max_connections_per_switch': switch_monitor.max_connections_per_switch,
                'max_total_connections': switch_monitor.max_total_connections,
                'commands_per_second_limit': switch_monitor.commands_per_second_limit
            }
        }), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500

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
# Use PostgreSQL to check if switches configuration is available
        try:
            site_count = Site.query.count()
            if site_count == 0:
                return jsonify({'status': 'unhealthy', 'reason': 'No sites configured'}), 503
            return jsonify({
                'status': 'healthy',
            })
        except Exception as e:
            logger.error(f"Health check failed: {str(e)}")
            return jsonify({'status': 'unhealthy', 'reason': 'Database connection failed'}), 503
        
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

# CRUD Routes for Switch Management (NetAdmin/SuperAdmin only)
@app.route('/manage')
def manage_switches():
    """Switch management interface for network administrators."""
    if 'username' not in session:
        return redirect(url_for('login'))
    
    user_role = session.get('role', 'oss')
    if user_role not in ['netadmin', 'superadmin']:
        return jsonify({'error': 'Insufficient permissions'}), 403
    
    return render_template_string(MANAGE_TEMPLATE, username=session['username'], user_role=user_role)

@app.route('/api/switches')
def api_get_switches():
    """API endpoint to get all switches with their sites and floors."""
    if 'username' not in session:
        return jsonify({'error': 'Not authenticated'}), 401
    
    user_role = session.get('role', 'oss')
    if user_role not in ['netadmin', 'superadmin']:
        return jsonify({'error': 'Insufficient permissions'}), 403
    
    try:
        switches = db.session.query(Switch, Floor, Site).join(Floor, Switch.floor_id == Floor.id).join(Site, Floor.site_id == Site.id).all()
        
        switches_data = []
        for switch, floor, site in switches:
            switches_data.append({
                'id': switch.id,
                'name': switch.name,
                'ip_address': switch.ip_address,
                'model': switch.model,
                'description': switch.description or '',
                'enabled': switch.enabled,
                'site_name': site.name,
                'floor_name': floor.name,
                'site_id': site.id,
                'floor_id': floor.id
            })
        
        return jsonify(switches_data)
    except Exception as e:
        logger.error(f"Error fetching switches: {str(e)}")
        return jsonify({'error': 'Failed to fetch switches'}), 500

@app.route('/api/sites')
def api_get_sites():
    """API endpoint to get all sites and their floors."""
    if 'username' not in session:
        return jsonify({'error': 'Not authenticated'}), 401
    
    user_role = session.get('role', 'oss')
    if user_role not in ['netadmin', 'superadmin']:
        return jsonify({'error': 'Insufficient permissions'}), 403
    
    try:
        sites = Site.query.all()
        sites_data = []
        
        for site in sites:
            floors_data = []
            for floor in site.floors:
                floors_data.append({
                    'id': floor.id,
                    'name': floor.name
                })
            
            sites_data.append({
                'id': site.id,
                'name': site.name,
                'floors': floors_data
            })
        
        return jsonify(sites_data)
    except Exception as e:
        logger.error(f"Error fetching sites: {str(e)}")
        return jsonify({'error': 'Failed to fetch sites'}), 500

@app.route('/api/switches', methods=['POST'])
def api_create_switch():
    """API endpoint to create a new switch."""
    if 'username' not in session:
        return jsonify({'error': 'Not authenticated'}), 401
    
    user_role = session.get('role', 'oss')
    if user_role not in ['netadmin', 'superadmin']:
        return jsonify({'error': 'Insufficient permissions'}), 403
    
    try:
        data = request.json
        username = session['username']
        
        # Validate required fields
        required_fields = ['name', 'ip_address', 'model', 'floor_id']
        for field in required_fields:
            if not data.get(field):
                return jsonify({'error': f'Missing required field: {field}'}), 400
        
        # Check if switch name or IP already exists
        existing_switch = Switch.query.filter(
            (Switch.name == data['name']) | (Switch.ip_address == data['ip_address'])
        ).first()
        
        if existing_switch:
            return jsonify({'error': 'Switch name or IP address already exists'}), 400
        
        # Create new switch
        new_switch = Switch(
            name=data['name'],
            ip_address=data['ip_address'],
            model=data['model'],
            description=data.get('description', ''),
            enabled=data.get('enabled', True),
            floor_id=data['floor_id']
        )
        
        db.session.add(new_switch)
        db.session.commit()
        
        # Log the action
        audit_logger.info(f"User: {username} - SWITCH CREATED - {data['name']} ({data['ip_address']})")
        
        return jsonify({'message': 'Switch created successfully', 'id': new_switch.id}), 201
        
    except Exception as e:
        db.session.rollback()
        logger.error(f"Error creating switch: {str(e)}")
        return jsonify({'error': 'Failed to create switch'}), 500

@app.route('/api/switches/<int:switch_id>', methods=['PUT'])
def api_update_switch(switch_id):
    """API endpoint to update an existing switch."""
    if 'username' not in session:
        return jsonify({'error': 'Not authenticated'}), 401
    
    user_role = session.get('role', 'oss')
    if user_role not in ['netadmin', 'superadmin']:
        return jsonify({'error': 'Insufficient permissions'}), 403
    
    try:
        switch = Switch.query.get_or_404(switch_id)
        data = request.json
        username = session['username']
        
        # Store old values for audit log
        old_name = switch.name
        old_ip = switch.ip_address
        
        # Check if new name or IP conflicts with other switches
        if data.get('name') and data['name'] != switch.name:
            existing = Switch.query.filter(Switch.name == data['name'], Switch.id != switch_id).first()
            if existing:
                return jsonify({'error': 'Switch name already exists'}), 400
        
        if data.get('ip_address') and data['ip_address'] != switch.ip_address:
            existing = Switch.query.filter(Switch.ip_address == data['ip_address'], Switch.id != switch_id).first()
            if existing:
                return jsonify({'error': 'IP address already exists'}), 400
        
        # Update switch fields
        if 'name' in data:
            switch.name = data['name']
        if 'ip_address' in data:
            switch.ip_address = data['ip_address']
        if 'model' in data:
            switch.model = data['model']
        if 'description' in data:
            switch.description = data['description']
        if 'enabled' in data:
            switch.enabled = data['enabled']
        if 'floor_id' in data:
            switch.floor_id = data['floor_id']
        
        db.session.commit()
        
        # Log the action
        audit_logger.info(f"User: {username} - SWITCH UPDATED - {old_name} ({old_ip}) -> {switch.name} ({switch.ip_address})")
        
        return jsonify({'message': 'Switch updated successfully'})
        
    except Exception as e:
        db.session.rollback()
        logger.error(f"Error updating switch: {str(e)}")
        return jsonify({'error': 'Failed to update switch'}), 500

@app.route('/api/switches/<int:switch_id>', methods=['DELETE'])
def api_delete_switch(switch_id):
    """API endpoint to delete a switch."""
    if 'username' not in session:
        return jsonify({'error': 'Not authenticated'}), 401
    
    user_role = session.get('role', 'oss')
    if user_role not in ['netadmin', 'superadmin']:
        return jsonify({'error': 'Insufficient permissions'}), 403
    
    try:
        switch = Switch.query.get_or_404(switch_id)
        username = session['username']
        
        # Store values for audit log
        switch_name = switch.name
        switch_ip = switch.ip_address
        
        db.session.delete(switch)
        db.session.commit()
        
        # Log the action
        audit_logger.info(f"User: {username} - SWITCH DELETED - {switch_name} ({switch_ip})")
        
        return jsonify({'message': 'Switch deleted successfully'})
        
    except Exception as e:
        db.session.rollback()
        logger.error(f"Error deleting switch: {str(e)}")
        return jsonify({'error': 'Failed to delete switch'}), 500

## VLAN Management API

@app.route('/api/switches/list', methods=['GET'])
def api_get_switches_list():
    """API endpoint to retrieve list of switches for dropdowns with site/floor info."""
    if 'username' not in session:
        return jsonify({'error': 'Not authenticated'}), 401
    
    user_role = session.get('role', 'oss')
    if user_role not in ['netadmin', 'superadmin', 'oss']:
        return jsonify({'error': 'Insufficient permissions'}), 403

    try:
        # Join with floors and sites to get complete information
        switches = db.session.query(Switch, Floor, Site).join(
            Floor, Switch.floor_id == Floor.id
        ).join(
            Site, Floor.site_id == Site.id
        ).filter(Switch.enabled == True).all()
        
        switches_list = []
        for switch, floor, site in switches:
            switches_list.append({
                'id': switch.id,
                'name': switch.name,
                'ip_address': switch.ip_address,
                'model': switch.model,
                'description': switch.description or '',
                'site_name': site.name,
                'floor_name': floor.name,
                'site_id': site.id,
                'floor_id': floor.id
            })
        return jsonify(switches_list)
    except Exception as e:
        logger.error(f"Failed to retrieve switches: {str(e)}")
        return jsonify({'error': 'Failed to retrieve switches'}), 500

@app.route('/api/vlan', methods=['GET'])
def api_get_vlans():
    """API endpoint to retrieve VLAN configurations."""
    if 'username' not in session:
        return jsonify({'error': 'Not authenticated'}), 401
    
    user_role = session.get('role', 'oss')
    if user_role not in ['netadmin', 'superadmin']:
        return jsonify({'error': 'Insufficient permissions'}), 403

    try:
      # Implement VLAN retrieval from managed switches 
        # Placeholder for VLAN retrieval integration
        logger.info("VLAN retrieval not yet implemented")
        return jsonify({'vlans': []})
    except Exception as e:
        logger.error(f"Failed to retrieve VLANs: {str(e)}")
        return jsonify({'error': 'Failed to retrieve VLANs'}), 500

@app.route('/api/vlan', methods=['POST'])
def api_create_vlan():
    """API endpoint to create a VLAN."""
    if 'username' not in session:
        return jsonify({'error': 'Not authenticated'}), 401

    user_role = session.get('role', 'oss')
    if user_role not in ['netadmin', 'superadmin']:
        return jsonify({'error': 'Insufficient permissions'}), 403

    try:
        data = request.json
        vlan_id = data.get('vlan_id')
        vlan_name = data.get('vlan_name')
        description = data.get('description')

        # Implement VLAN creation on Dell switches via SSH
        # Placeholder for VLAN creation integration

        return jsonify({'message': f'VLAN {vlan_id} created successfully'}), 201
    except Exception as e:
        logger.error(f"Failed to create VLAN: {str(e)}")
        return jsonify({'error': 'Failed to create VLAN'}), 500

@app.route('/api/vlan', methods=['PUT'])
def api_update_vlan():
    """API endpoint to update a VLAN."""
    if 'username' not in session:
        return jsonify({'error': 'Not authenticated'}), 401

    user_role = session.get('role', 'oss')
    if user_role not in ['netadmin', 'superadmin']:
        return jsonify({'error': 'Insufficient permissions'}), 403

    try:
        data = request.json
        vlan_id = data.get('vlan_id')
        vlan_name = data.get('vlan_name')
        description = data.get('description')

        # Implement VLAN update on Dell switches via SSH
        # Placeholder for VLAN update integration

        return jsonify({'message': f'VLAN {vlan_id} updated successfully'})
    except Exception as e:
        logger.error(f"Failed to update VLAN: {str(e)}")
        return jsonify({'error': 'Failed to update VLAN'}), 500

@app.route('/api/vlan', methods=['DELETE'])
def api_delete_vlan():
    """API endpoint to delete a VLAN."""
    if 'username' not in session:
        return jsonify({'error': 'Not authenticated'}), 401

    user_role = session.get('role', 'oss')
    if user_role not in ['netadmin', 'superadmin']:
        return jsonify({'error': 'Insufficient permissions'}), 403

    try:
        data = request.json
        vlan_id = data.get('vlan_id')

        # Implement VLAN deletion on Dell switches via SSH
        # Placeholder for VLAN deletion integration

        return jsonify({'message': f'VLAN {vlan_id} deleted successfully'})
    except Exception as e:
        logger.error(f"Failed to delete VLAN: {str(e)}")
        return jsonify({'error': 'Failed to delete VLAN'}), 500

@app.route('/api/change-port-vlan', methods=['PUT'])
def api_change_port_vlan():
    """API endpoint to change a port's VLAN assignment."""
    if 'username' not in session:
        return jsonify({'error': 'Not authenticated'}), 401

    user_role = session.get('role', 'oss')
    if user_role not in ['netadmin', 'superadmin']:
        return jsonify({'error': 'Insufficient permissions'}), 403

    try:
        data = request.json
        port = data.get('port')
        new_vlan_id = data.get('new_vlan_id')
        username = session['username']

        if not port or not new_vlan_id:
            return jsonify({'error': 'Missing required fields: port and new_vlan_id'}), 400

        # Implement port VLAN change on Dell switches via SSH
        # Placeholder for port VLAN change integration
        
        # Log the action
        audit_logger.info(f"User: {username} - PORT VLAN CHANGE - Port: {port} -> VLAN: {new_vlan_id}")

        return jsonify({'message': f'Port {port} VLAN changed to {new_vlan_id} successfully'})
    except Exception as e:
        logger.error(f"Failed to change port VLAN: {str(e)}")
        return jsonify({'error': 'Failed to change port VLAN'}), 500

@app.route('/vlan')
def vlan_management():
    """Advanced VLAN management interface."""
    if 'username' not in session:
        return redirect(url_for('login'))
    
    user_role = session.get('role', 'oss')
    if user_role not in ['netadmin', 'superadmin']:
        return jsonify({'error': 'Insufficient permissions'}), 403
    
    # Load the new advanced VLAN template
    try:
        with open('vlan_template_v2.html', 'r', encoding='utf-8') as f:
            vlan_template = f.read()
    except FileNotFoundError:
        # Fallback to old template if new one doesn't exist
        try:
            with open('vlan_template.html', 'r', encoding='utf-8') as f:
                vlan_template = f.read()
        except FileNotFoundError:
            return jsonify({'error': 'VLAN template not found'}), 500
    except Exception as e:
        logger.error(f"Error reading VLAN template: {str(e)}")
        return jsonify({'error': 'Error loading VLAN template'}), 500
    
    return render_template_string(vlan_template, username=session['username'], user_role=user_role)

# Import and add advanced VLAN management routes
from vlan_management_v2 import vlan_change_workflow

@app.route('/api/vlan/change', methods=['POST'])
def api_change_port_vlan_advanced():
    """Advanced API endpoint for VLAN change workflow with comprehensive safety checks."""
    if 'username' not in session:
        return jsonify({'error': 'Not authenticated'}), 401
    
    user_role = session.get('role', 'oss')
    if user_role not in ['netadmin', 'superadmin']:
        return jsonify({'error': 'Insufficient permissions'}), 403
    
    try:
        data = request.json
        username = session['username']
        
        # Required fields
        required_fields = ['switch_id', 'ports', 'vlan_id', 'vlan_name']
        for field in required_fields:
            if field not in data:
                return jsonify({'error': f'Missing required field: {field}'}), 400
        
        # Optional fields
        description = data.get('description', '')
        force_change = data.get('force_change', False)
        skip_non_access = data.get('skip_non_access', False)
        
        # Execute workflow
        result = vlan_change_workflow(
            switch_id=data['switch_id'],
            ports_input=data['ports'],
            description=description,
            vlan_id=data['vlan_id'],
            vlan_name=data['vlan_name'],
            force_change=force_change,
            skip_non_access=skip_non_access
        )
        
        # Log the operation
        if result['status'] == 'success':
            audit_logger.info(f"User: {username} - VLAN CHANGE - Switch: {result.get('switch_info', {}).get('name', 'unknown')}, VLAN: {data['vlan_id']}, Ports: {data['ports']}")
        else:
            audit_logger.warning(f"User: {username} - VLAN CHANGE FAILED - Switch ID: {data['switch_id']}, Error: {result.get('error', 'unknown')}")
        
        return jsonify(result)
        
    except Exception as e:
        logger.error(f"VLAN change API error: {str(e)}")
        return jsonify({'error': 'Internal server error'}), 500

@app.route('/api/vlan/check', methods=['POST'])
def api_check_vlan():
    """Check VLAN existence on switch."""
    if 'username' not in session:
        return jsonify({'error': 'Not authenticated'}), 401
    
    user_role = session.get('role', 'oss')
    if user_role not in ['netadmin', 'superadmin']:
        return jsonify({'error': 'Insufficient permissions'}), 403
    
    try:
        from vlan_management_v2 import VLANManager
        data = request.json
        switch_id = data.get('switch_id')
        vlan_id = data.get('vlan_id')
        
        if not all([switch_id, vlan_id]):
            return jsonify({'error': 'Missing switch_id or vlan_id'}), 400
        
        # Get switch info
        switch = Switch.query.get(switch_id)
        if not switch:
            return jsonify({'error': 'Switch not found'}), 404
        
        # Initialize VLAN manager
        vlan_manager = VLANManager(
            switch.ip_address,
            SWITCH_USERNAME,
            SWITCH_PASSWORD,
            switch.model
        )
        
        if not vlan_manager.connect():
            return jsonify({'error': 'Could not connect to switch'}), 500
        
        try:
            vlan_info = vlan_manager.get_vlan_info(vlan_id)
            return jsonify(vlan_info)
        finally:
            vlan_manager.disconnect()
            
    except Exception as e:
        logger.error(f"VLAN check API error: {str(e)}")
        return jsonify({'error': 'Internal server error'}), 500

@app.route('/api/port/status', methods=['POST'])
def api_check_port_status():
    """Check port status on switch."""
    if 'username' not in session:
        return jsonify({'error': 'Not authenticated'}), 401
    
    user_role = session.get('role', 'oss')
    if user_role not in ['netadmin', 'superadmin']:
        return jsonify({'error': 'Insufficient permissions'}), 403
    
    try:
        from vlan_management_v2 import VLANManager
        data = request.json
        switch_id = data.get('switch_id')
        ports_input = data.get('ports')
        
        if not all([switch_id, ports_input]):
            return jsonify({'error': 'Missing switch_id or ports'}), 400
        
        # Get switch info
        switch = Switch.query.get(switch_id)
        if not switch:
            return jsonify({'error': 'Switch not found'}), 404
        
        # Initialize VLAN manager
        vlan_manager = VLANManager(
            switch.ip_address,
            SWITCH_USERNAME,
            SWITCH_PASSWORD,
            switch.model
        )
        
        if not vlan_manager.connect():
            return jsonify({'error': 'Could not connect to switch'}), 500
        
        try:
            # Parse ports
            ports = vlan_manager.parse_port_range(ports_input)
            port_statuses = []
            
            for port in ports:
                status = vlan_manager.get_port_status(port)
                status['is_uplink'] = vlan_manager.is_uplink_port(port)
                port_statuses.append(status)
            
            return jsonify({
                'ports': port_statuses,
                'switch_model': switch.model
            })
        finally:
            vlan_manager.disconnect()
            
    except Exception as e:
        logger.error(f"Port status API error: {str(e)}")
        return jsonify({'error': 'Internal server error'}), 500


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
