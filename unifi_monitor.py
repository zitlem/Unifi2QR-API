#!/usr/bin/env python3
"""
UniFi Guest Network QR Code Monitor
Monitors UniFi controller for guest network password changes and automatically updates QR codes.
"""

import requests
import json
import time
import hashlib
import logging
from datetime import datetime, timedelta
from typing import Dict, Optional, List
import urllib3
from influxdb_client import InfluxDBClient, Point
from influxdb_client.client.write_api import SYNCHRONOUS
import schedule
import threading
import os
import sys
from flask import Flask, render_template_string, jsonify, request
import ipaddress
from functools import wraps

# Disable SSL warnings for self-signed certificates
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

class DebugLogger:
    """Configurable debug logging utility"""
    def __init__(self, config: Dict):
        self.config = config.get('monitor', {}).get('debug_settings', {})
        self.level = self.config.get('level', 'NORMAL').upper()
        self.quiet_mode = self.config.get('quiet_mode', False)
        self.errors_only = self.config.get('log_errors_only', False)
        self.max_response_length = self.config.get('max_log_response_length', 500)

        # Debug flags
        self.api_debug = self.config.get('enable_api_debug', False)
        self.schedule_debug = self.config.get('enable_schedule_debug', False)
        self.unifi_debug = self.config.get('enable_unifi_api_debug', False)
        self.influx_debug = self.config.get('enable_influxdb_debug', False)
        self.web_debug = self.config.get('enable_web_debug', False)

        # Logging flags
        self.log_responses = self.config.get('log_unifi_responses', False)
        self.log_writes = self.config.get('log_influxdb_writes', False)
        self.log_success = self.config.get('log_successful_operations', True)

    def should_log(self, category: str, level: str = 'INFO') -> bool:
        """Check if logging should occur based on configuration"""
        if self.quiet_mode and level != 'ERROR':
            return False
        if self.errors_only and level not in ['ERROR', 'WARNING']:
            return False

        # Check category-specific debug flags
        category_flags = {
            'api': self.api_debug,
            'schedule': self.schedule_debug,
            'unifi': self.unifi_debug,
            'influx': self.influx_debug,
            'web': self.web_debug
        }

        if level == 'DEBUG' and category in category_flags:
            return category_flags[category]

        # Level-based filtering
        if self.level == 'SILENT':
            return level == 'ERROR'
        elif self.level == 'MINIMAL':
            return level in ['ERROR', 'WARNING']
        elif self.level == 'NORMAL':
            return level in ['ERROR', 'WARNING', 'INFO']
        elif self.level == 'VERBOSE':
            return level in ['ERROR', 'WARNING', 'INFO', 'DEBUG']
        else:  # FULL
            return True

    def log(self, category: str, level: str, message: str, data: any = None):
        """Log with category and level filtering"""
        if not self.should_log(category, level):
            return

        prefix = f"[{category.upper()}]"

        if level == 'ERROR':
            logging.error(f"{prefix} {message}")
        elif level == 'WARNING':
            logging.warning(f"{prefix} {message}")
        elif level == 'INFO':
            logging.info(f"{prefix} {message}")
        elif level == 'DEBUG':
            logging.debug(f"{prefix} {message}")

        # Log additional data if provided
        if data is not None and self.should_log(category, 'DEBUG'):
            if isinstance(data, (dict, list)):
                data_str = str(data)[:self.max_response_length]
                logging.debug(f"{prefix} Data: {data_str}")
            else:
                logging.debug(f"{prefix} Data: {str(data)[:self.max_response_length]}")

    def log_api_call(self, endpoint: str, method: str = 'GET', response_data: any = None):
        """Log API calls with response data"""
        if self.should_log('api', 'DEBUG'):
            self.log('api', 'DEBUG', f"{method} {endpoint}")
            if response_data and self.log_responses:
                self.log('api', 'DEBUG', f"Response", response_data)

    def log_schedule_event(self, job_name: str, action: str):
        """Log scheduled job events"""
        self.log('schedule', 'DEBUG', f"{action}: {job_name}")

    def log_database_write(self, measurement: str, count: int, success: bool = True):
        """Log database write operations"""
        if success and self.log_writes:
            self.log('influx', 'DEBUG', f"Wrote {count} points to {measurement}")
        elif not success:
            self.log('influx', 'ERROR', f"Failed to write to {measurement}")

    def log_success_operation(self, operation: str, details: str = ""):
        """Log successful operations"""
        if self.log_success:
            self.log('general', 'INFO', f"{operation} completed successfully. {details}".strip())

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('unifi_monitor.log'),
        logging.StreamHandler()
    ]
)

class UniFiController:
    def __init__(self, config: Dict):
        self.config = config
        unifi_config = config['unifi']
        self.enabled = unifi_config.get('enabled', True)

        if not self.enabled:
            logging.info("UniFi controller integration disabled")
            return

        self.host = unifi_config['host'].rstrip('/')
        self.site = unifi_config.get('site', 'default')
        self.session = requests.Session()
        self.session.verify = False  # For self-signed certificates

        # Use username/password authentication (legacy method)
        self.username = unifi_config.get('username')
        self.password = unifi_config.get('password')
        self.cookies = None

    def login(self) -> bool:
        """Authenticate with UniFi controller"""
        if not self.enabled:
            return False

        if not self.username or not self.password:
            logging.error("Username and password required for authentication")
            return False

        try:
            login_url = f"{self.host}/api/auth/login"
            login_data = {
                "username": self.username,
                "password": self.password,
                "remember": False
            }

            response = self.session.post(login_url, json=login_data, timeout=10)
            response.raise_for_status()

            self.cookies = response.cookies
            logging.info("Successfully authenticated with UniFi controller")
            return True

        except Exception as e:
            logging.error(f"Authentication failed: {e}")
            return False

    def get_wireless_networks(self) -> Optional[List[Dict]]:
        """Retrieve all wireless network configurations using legacy API"""
        try:
            # Login if not already authenticated
            if not self.cookies:
                if not self.login():
                    return None

            # Try different UniFi endpoints (UDM/UDM Pro uses different paths)
            endpoints_to_try = [
                f"/proxy/network/api/s/{self.site}/rest/wlanconf",
                f"/api/s/{self.site}/rest/wlanconf",
                f"/api/s/{self.site}/list/wlanconf",
                f"/proxy/network/v2/api/site/{self.site}/wlans",
            ]

            for endpoint in endpoints_to_try:
                try:
                    url = f"{self.host}{endpoint}"
                    logging.debug(f"Trying endpoint: {url}")
                    response = self.session.get(url, cookies=self.cookies, timeout=10)

                    if response.status_code == 200:
                        logging.info(f"Successfully connected using: {endpoint}")
                        data = response.json()

                        # Handle different response formats
                        if isinstance(data, dict):
                            return data.get('data', data.get('wlans', []))
                        elif isinstance(data, list):
                            return data
                        else:
                            return []
                    else:
                        logging.debug(f"Endpoint {endpoint} returned: {response.status_code}")
                except Exception as e:
                    logging.debug(f"Endpoint {endpoint} failed: {e}")
                    continue

            logging.error("All API endpoints failed")
            return None

        except Exception as e:
            logging.error(f"Failed to retrieve wireless networks: {e}")

            # Try re-authentication once
            if self.login():
                try:
                    url = f"{self.host}/api/s/{self.site}/rest/wlanconf"
                    response = self.session.get(url, cookies=self.cookies, timeout=10)
                    response.raise_for_status()
                    data = response.json()
                    return data.get('data', [])
                except Exception as retry_error:
                    logging.error(f"Retry failed: {retry_error}")
            return None

    def get_all_networks(self) -> List[Dict]:
        """Get all wireless networks with all UniFi settings"""
        networks = self.get_wireless_networks()
        if not networks:
            return []

        all_networks = []
        for network in networks:
            # Try multiple password field names (UniFi API changes over time)
            password = (network.get('x_passphrase') or
                       network.get('sae_psk') or
                       network.get('wpa_psk') or
                       network.get('passphrase') or '')

            # Debug password extraction
            if not password:
                logging.warning(f"No password found for {network.get('name')} - all password fields are empty!")
            else:
                logging.info(f"Found password for {network.get('name')}: {'*' * len(password)}")

            # Extract all relevant settings from UniFi for all networks
            all_networks.append({
                'id': network.get('_id'),
                'name': network.get('name'),
                'ssid': network.get('name'),
                'password': password,
                'security': network.get('security', 'wpapsk'),  # UniFi format
                'enabled': network.get('enabled', False),
                'hidden': network.get('hide_ap_ssid', False),  # From UniFi
                'is_guest': network.get('is_guest', False),
                'wpa_mode': network.get('wpa_mode', ''),
                'wpa_enc': network.get('wpa_enc', ''),
                'wep_idx': network.get('wep_idx', 1),
            })

        return all_networks

    def get_wan_throughput(self) -> Optional[Dict]:
        """Get WAN throughput statistics"""
        try:
            if not self.cookies:
                if not self.login():
                    return None

            # Try different endpoints for WAN stats
            endpoints_to_try = [
                f"/api/s/{self.site}/stat/health",
                f"/proxy/network/api/s/{self.site}/stat/health",
                f"/api/s/{self.site}/stat/device"
            ]

            for endpoint in endpoints_to_try:
                try:
                    url = f"{self.host}{endpoint}"
                    response = self.session.get(url, cookies=self.cookies, timeout=10)

                    if response.status_code == 200:
                        data = response.json()

                        # Handle health endpoint
                        if 'stat/health' in endpoint:
                            health_data = data.get('data', [])
                            for item in health_data:
                                if item.get('subsystem') == 'wan':
                                    return {
                                        'wan_ip': item.get('wan_ip'),
                                        'rx_bytes': item.get('rx_bytes', 0),
                                        'tx_bytes': item.get('tx_bytes', 0),
                                        'rx_rate': item.get('rx_bytes-r', 0),  # Rate fields use -r suffix
                                        'tx_rate': item.get('tx_bytes-r', 0),  # Rate fields use -r suffix
                                        'uptime': int(item.get('gw_system-stats', {}).get('uptime', 0)),
                                        'timestamp': time.time()
                                    }

                        # Handle device endpoint - look for gateway device
                        elif 'stat/device' in endpoint:
                            devices = data.get('data', [])
                            for device in devices:
                                device_type = device.get('type')
                                device_name = device.get('name', '')

                                if device_type == 'ugw' or 'Gateway' in device_name or device_type == 'udm':
                                    wan_stats = device.get('stat', {})
                                    return {
                                        'wan_ip': device.get('wan1', {}).get('ip'),
                                        'rx_bytes': wan_stats.get('wan-rx_bytes', 0),
                                        'tx_bytes': wan_stats.get('wan-tx_bytes', 0),
                                        'rx_rate': wan_stats.get('wan-rx_rate', 0),
                                        'tx_rate': wan_stats.get('wan-tx_rate', 0),
                                        'uptime': int(device.get('uptime', 0)),
                                        'timestamp': time.time()
                                    }

                except Exception as e:
                    logging.debug(f"WAN endpoint {endpoint} failed: {e}")
                    continue

            logging.warning("No WAN throughput data found in any endpoint")
            return None

        except Exception as e:
            logging.error(f"Failed to get WAN throughput: {e}")
            return None

    def get_top_clients(self, limit: int = 15) -> Optional[List[Dict]]:
        """Get top clients by data usage"""
        try:
            if not self.cookies:
                if not self.login():
                    return None

            # Try different endpoints for client stats
            endpoints_to_try = [
                f"/proxy/network/api/s/{self.site}/stat/sta",
                f"/api/s/{self.site}/stat/sta",
                f"/proxy/network/api/s/{self.site}/stat/alluser",
                f"/api/s/{self.site}/stat/alluser",
                f"/api/s/{self.site}/rest/user"
            ]

            for endpoint in endpoints_to_try:
                try:
                    url = f"{self.host}{endpoint}"
                    response = self.session.get(url, cookies=self.cookies, timeout=10)

                    if response.status_code == 200:
                        data = response.json()
                        clients = data.get('data', [])

                        if not clients:
                            continue


                        # Process client data and calculate total usage
                        client_usage = []
                        for client in clients:
                            # Get client identification
                            hostname = client.get('hostname', client.get('name', 'Unknown'))
                            mac = client.get('mac', 'Unknown')
                            ip = client.get('ip', 'Unknown')

                            # Get usage stats (bytes)
                            rx_bytes = client.get('rx_bytes', 0)
                            tx_bytes = client.get('tx_bytes', 0)
                            total_bytes = rx_bytes + tx_bytes

                            # Get REAL-TIME usage rates (bytes/sec) - check both wireless and wired
                            is_wired = client.get('is_wired', False)


                            if is_wired:
                                # Wired client - try multiple field combinations
                                rx_rate = int(client.get('wired-rx_bytes-r', 0) or client.get('rx_bytes-r', 0))
                                tx_rate = int(client.get('wired-tx_bytes-r', 0) or client.get('tx_bytes-r', 0))
                                essid = 'Wired'
                            else:
                                # Wireless client - use wireless fields
                                rx_rate = int(client.get('rx_bytes-r', 0))
                                tx_rate = int(client.get('tx_bytes-r', 0))
                                essid = client.get('essid', 'Unknown')

                            # Skip clients with no current activity
                            if rx_rate == 0 and tx_rate == 0:
                                continue

                            # Skip clients with no usage - but allow wired clients with current activity
                            if total_bytes == 0 and (rx_rate == 0 and tx_rate == 0):
                                continue

                            client_usage.append({
                                'hostname': hostname,
                                'mac': mac,
                                'ip': ip,
                                'rx_bytes': rx_bytes,
                                'tx_bytes': tx_bytes,
                                'total_bytes': total_bytes,
                                'rx_rate': rx_rate,
                                'tx_rate': tx_rate,
                                'connected': client.get('is_11r', False) or client.get('is_11k', False) or client.get('authorized', False),
                                'ap_mac': client.get('ap_mac', 'Unknown'),
                                'essid': essid,
                                'channel': client.get('channel', 0),
                                'signal': client.get('signal', 0),
                                'timestamp': time.time()
                            })

                        # Sort by total usage and return top N
                        client_usage.sort(key=lambda x: x['total_bytes'], reverse=True)
                        return client_usage[:limit]

                except Exception as e:
                    logging.debug(f"Client endpoint {endpoint} failed: {e}")
                    continue

            logging.warning("No client data found in any endpoint")
            return None

        except Exception as e:
            logging.error(f"Failed to get client usage: {e}")
            return None

class QRCodeUpdater:
    def __init__(self, config: Dict):
        qr_config = config['qr_api']
        self.enabled = qr_config.get('enabled', True)

        if not self.enabled:
            logging.info("QR API integration disabled")
            return

        self.qr_api_url = qr_config['url'].rstrip('/')
        self.qr_api_key = qr_config['api_key']
        self.wifi_endpoint = qr_config['wifi_endpoint']
        self.update_password_endpoint = qr_config['update_password_endpoint']
        self.library_endpoint = qr_config['library_endpoint']
        self.config = config
        self.network_qr_ids = {}  # Track QR IDs for each network
        self.qr_library_cache = None  # Cache QR library for smart mapping

    def get_headers(self) -> Dict[str, str]:
        """Get API headers with authentication"""
        headers = {'Content-Type': 'application/json'}
        if self.qr_api_key:
            headers['X-API-Key'] = self.qr_api_key
        return headers

    def get_qr_library(self) -> List[Dict]:
        """Get and cache QR library entries"""
        if not self.enabled:
            return []

        if self.qr_library_cache is None:
            try:
                response = requests.get(
                    f"{self.qr_api_url}{self.library_endpoint}",
                    headers=self.get_headers(),
                    timeout=10
                )
                response.raise_for_status()
                library = response.json()

                # Handle different response formats
                if isinstance(library, dict):
                    self.qr_library_cache = library.get('entries', library.get('data', []))
                else:
                    self.qr_library_cache = library
            except Exception as e:
                logging.error(f"Failed to get QR library: {e}")
                self.qr_library_cache = []

        return self.qr_library_cache


    def find_existing_qr(self, ssid: str) -> Optional[str]:
        """Find existing QR code entry for this SSID"""
        try:
            entries = self.get_qr_library()
            for entry in entries:
                if entry.get('ssid') == ssid:
                    return entry.get('qr_id', entry.get('id'))
            return None
        except Exception as e:
            logging.error(f"Failed to search library for {ssid}: {e}")
            return None

    def find_orphaned_qr_by_elimination(self, active_networks: List[Dict]) -> Optional[Dict]:
        """Smart mapping: Find QR entry that doesn't match any active network

        This handles the case where you change a WiFi name - the old QR entry
        becomes orphaned and can be mapped to the unmatched network.
        """
        try:
            entries = self.get_qr_library()
            active_ssids = [net['ssid'] for net in active_networks]
            networks_to_ignore = self.config.get('monitor', {}).get('networks_to_ignore', [])

            # Find QR entries that don't match any active network and aren't ignored
            orphaned_entries = []
            for entry in entries:
                qr_ssid = entry.get('ssid')
                if (qr_ssid not in active_ssids and
                    qr_ssid not in networks_to_ignore):
                    orphaned_entries.append(entry)

            # If exactly one orphaned entry, it's likely our renamed network
            if len(orphaned_entries) == 1:
                logging.info(f"Found orphaned QR entry for potential name change: {orphaned_entries[0]['ssid']} -> QR ID: {orphaned_entries[0]['qr_id']}")
                return orphaned_entries[0]

            return None
        except Exception as e:
            logging.error(f"Failed to find orphaned QR entry: {e}")
            return None

    def create_new_qr(self, network: Dict) -> Optional[str]:
        """Create new QR code entry using UniFi network data"""
        try:
            # Map UniFi security types to QR WiFi app format (exactly as documented)
            security_map = {
                'wpapsk': 'WPA2',      # WPA2-PSK
                'wpa2psk': 'WPA2',     # WPA2-PSK
                'wpa3psk': 'WPA3',     # WPA3-PSK
                'wpapsk2': 'WPA',      # WPA-PSK
                'wep': 'WEP',          # WEP
                'open': 'None',        # Open network
                '': 'None'             # No security
            }

            unifi_security = network.get('security', 'wpapsk').lower()
            qr_security = security_map.get(unifi_security, 'WPA2')

            # Format exactly as QR WiFi documentation specifies
            payload = {
                'ssid': network['ssid'],
                'password': network['password'],
                'security': qr_security,
                'hidden': network.get('hidden', False)
            }

            logging.debug(f"Sending QR API payload: {payload}")

            response = requests.post(
                f"{self.qr_api_url}{self.wifi_endpoint}",
                json=payload,
                headers=self.get_headers(),
                timeout=10
            )
            response.raise_for_status()

            result = response.json()

            # Handle QR WiFi Flask app response format
            if result.get('success'):
                # Response has 'entry' with QR details
                entry = result.get('entry', {})
                qr_id = entry.get('qr_id')

                if qr_id:
                    self.network_qr_ids[network['ssid']] = qr_id
                    logging.info(f"Created new QR code for {network['ssid']}: {qr_id}")
                    return qr_id

            logging.error(f"Unexpected response format: {result}")
            return None

        except Exception as e:
            logging.error(f"Failed to create QR code for {network['ssid']}: {e}")
            return None

    def update_existing_qr(self, qr_id: str, network: Dict) -> bool:
        """Update existing QR code entry using UniFi network data"""
        try:
            # Try password-only update first (more efficient)
            password_payload = {'password': network['password']}

            response = requests.post(
                f"{self.qr_api_url}{self.update_password_endpoint}/{qr_id}",
                json=password_payload,
                headers=self.get_headers(),
                timeout=10
            )

            if response.status_code == 200:
                logging.info(f"Updated password for QR {qr_id}")
                return True

            # Fall back to full update with all UniFi settings
            security_map = {
                'wpapsk': 'WPA2',
                'wpa2psk': 'WPA2',
                'wpa3psk': 'WPA3',
                'wpapsk2': 'WPA',
                'wep': 'WEP',
                'open': 'None',
                '': 'None'
            }

            unifi_security = network.get('security', 'wpapsk').lower()
            qr_security = security_map.get(unifi_security, 'WPA2')

            full_payload = {
                'ssid': network['ssid'],
                'password': network['password'],
                'security': qr_security,
                'hidden': network.get('hidden', False)  # From UniFi
            }

            response = requests.put(
                f"{self.qr_api_url}{self.wifi_endpoint}/{qr_id}",
                json=full_payload,
                headers=self.get_headers(),
                timeout=10
            )
            response.raise_for_status()

            logging.info(f"Updated QR code {qr_id} for network: {network['ssid']}")
            return True

        except Exception as e:
            logging.error(f"Failed to update QR code {qr_id}: {e}")
            return False

    def update_qr_code(self, network: Dict) -> bool:
        """Update or create QR code for network using UniFi data"""
        try:
            ssid = network['ssid']

            # Check if we have a tracked QR ID for this network
            qr_id = self.network_qr_ids.get(ssid)

            # If not tracked, search the library by SSID
            if not qr_id:
                qr_id = self.find_existing_qr(ssid)
                if qr_id:
                    logging.info(f"Found existing QR by SSID match: {ssid} -> {qr_id}")
                    self.network_qr_ids[ssid] = qr_id

            # Always create new if doesn't exist, update if exists
            if qr_id:
                logging.info(f"Updating existing QR code for: {ssid}")
                return self.update_existing_qr(qr_id, network)
            else:
                logging.info(f"Creating new QR code for: {ssid}")
                new_qr_id = self.create_new_qr(network)
                return new_qr_id is not None

        except Exception as e:
            logging.error(f"Failed to update QR code for {network.get('name', 'unknown')}: {e}")
            return False

class InfluxDBWriter:
    def __init__(self, config: Dict):
        influx_config = config.get('influxdb', {})
        self.enabled = influx_config.get('enabled', False)

        if not self.enabled:
            logging.info("InfluxDB integration disabled")
            return

        self.url = influx_config['url']
        self.token = influx_config.get('token', '')
        self.org = influx_config['org']
        self.bucket = influx_config['bucket']

        try:
            self.client = InfluxDBClient(url=self.url, token=self.token, org=self.org)
            self.write_api = self.client.write_api(write_options=SYNCHRONOUS)
            logging.info(f"InfluxDB client initialized: {self.url}")
        except Exception as e:
            logging.error(f"Failed to initialize InfluxDB client: {e}")
            self.enabled = False

    def write_wan_throughput(self, wan_data: Dict):
        """Write WAN throughput data to InfluxDB"""
        if not self.enabled or not wan_data:
            return

        try:
            point = Point("wan_throughput") \
                .tag("wan_ip", wan_data.get('wan_ip', 'unknown')) \
                .field("rx_bytes", wan_data['rx_bytes']) \
                .field("tx_bytes", wan_data['tx_bytes']) \
                .field("rx_rate", wan_data['rx_rate']) \
                .field("tx_rate", wan_data['tx_rate']) \
                .field("uptime", wan_data['uptime']) \
                .time(int(wan_data['timestamp'] * 1000000000))

            self.write_api.write(bucket=self.bucket, record=point)
            logging.debug("WAN throughput data written to InfluxDB")

        except Exception as e:
            logging.error(f"Failed to write WAN data to InfluxDB: {e}")

    def write_client_usage(self, clients: List[Dict]):
        """Write client usage data to InfluxDB"""
        if not self.enabled or not clients:
            return

        try:
            points = []
            for client in clients:
                point = Point("client_usage") \
                    .tag("hostname", client['hostname']) \
                    .tag("mac", client['mac']) \
                    .tag("ip", client['ip']) \
                    .tag("essid", client['essid']) \
                    .tag("ap_mac", client['ap_mac']) \
                    .field("rx_bytes", client['rx_bytes']) \
                    .field("tx_bytes", client['tx_bytes']) \
                    .field("total_bytes", client['total_bytes']) \
                    .field("rx_rate", client['rx_rate']) \
                    .field("tx_rate", client['tx_rate']) \
                    .field("channel", client['channel']) \
                    .field("signal", client['signal']) \
                    .field("connected", client['connected']) \
                    .time(int(client['timestamp'] * 1000000000))

                points.append(point)

            self.write_api.write(bucket=self.bucket, record=points)
            logging.debug(f"Client usage data written to InfluxDB ({len(points)} clients)")

        except Exception as e:
            logging.error(f"Failed to write client data to InfluxDB: {e}")

    def close(self):
        """Close InfluxDB connection"""
        if self.enabled and hasattr(self, 'client'):
            self.client.close()

class TaskScheduler:
    def __init__(self):
        self.scheduler_thread = None
        self.running = False

    def parse_cron_to_schedule(self, cron_expression: str, job_func, job_name: str = ""):
        """Convert cron-like expression to schedule format

        Supported formats:
        5-part (minute hour day month weekday):
        - "*/5 * * * *" - every 5 minutes
        - "0 */2 * * *" - every 2 hours
        - "0 9 * * *" - daily at 9 AM
        - "0 9 * * 1" - weekly on Monday at 9 AM

        6-part (second minute hour day month weekday):
        - "*/30 * * * * *" - every 30 seconds
        - "0 */5 * * * *" - every 5 minutes at 0 seconds
        - "30 */2 * * * *" - every 2 minutes at 30 seconds
        """
        parts = cron_expression.strip().split()
        job_description = f"{job_name} " if job_name else ""

        # Support both 5-part and 6-part cron expressions
        if len(parts) == 6:
            # 6-part: second minute hour day month weekday
            second, minute, hour, day, month, weekday = parts

            # Handle second intervals
            if second.startswith("*/"):
                interval = int(second[2:])
                schedule.every(interval).seconds.do(job_func)
                logging.info(f"Scheduled {job_description}every {interval} seconds: {cron_expression}")
                return

            # Handle minute intervals with specific seconds
            elif minute.startswith("*/"):
                interval = int(minute[2:])
                if second == "0":
                    schedule.every(interval).minutes.do(job_func)
                else:
                    # Schedule library doesn't support minute intervals with specific seconds
                    # Fall back to every minute and check seconds in job
                    schedule.every().minute.do(job_func)
                    logging.warning(f"Approximating {job_description}schedule (checking every minute): {cron_expression}")
                    return
                logging.info(f"Scheduled {job_description}every {interval} minutes: {cron_expression}")
                return

            # Handle hourly intervals with specific seconds/minutes
            elif hour.startswith("*/"):
                interval = int(hour[2:])
                if second == "0" and minute == "0":
                    schedule.every(interval).hours.do(job_func)
                elif second == "0":
                    schedule.every(interval).hours.at(f":{minute.zfill(2)}").do(job_func)
                else:
                    schedule.every(interval).hours.at(f":{minute.zfill(2)}:{second.zfill(2)}").do(job_func)
                logging.info(f"Scheduled {job_description}every {interval} hours: {cron_expression}")
                return

            # Handle daily schedules with seconds
            elif hour.isdigit() and minute.isdigit() and second.isdigit() and day == "*" and weekday == "*":
                time_str = f"{hour.zfill(2)}:{minute.zfill(2)}:{second.zfill(2)}"
                schedule.every().day.at(time_str).do(job_func)
                logging.info(f"Scheduled {job_description}daily at {time_str}: {cron_expression}")
                return

            # Handle weekly schedules with seconds
            elif hour.isdigit() and minute.isdigit() and second.isdigit() and day == "*" and weekday.isdigit():
                time_str = f"{hour.zfill(2)}:{minute.zfill(2)}:{second.zfill(2)}"
                weekdays = ["monday", "tuesday", "wednesday", "thursday", "friday", "saturday", "sunday"]
                weekday_name = weekdays[int(weekday)]
                getattr(schedule.every(), weekday_name).at(time_str).do(job_func)
                logging.info(f"Scheduled {job_description}weekly on {weekday_name} at {time_str}: {cron_expression}")
                return

        elif len(parts) == 5:
            # 5-part: minute hour day month weekday (legacy support)
            minute, hour, day, month, weekday = parts

            # Handle minute intervals
            if minute.startswith("*/"):
                interval = int(minute[2:])

                # Check if this is weekday-specific (e.g., "*/30 * * * 0" - every 30 min on Sunday)
                if weekday.isdigit() and day == "*" and hour == "*":
                    weekdays = ["monday", "tuesday", "wednesday", "thursday", "friday", "saturday", "sunday"]
                    weekday_name = weekdays[int(weekday)]

                    def weekday_interval_wrapper():
                        current_weekday = datetime.now().weekday()  # 0=Monday, 6=Sunday
                        target_weekday = int(weekday) % 7  # Convert cron weekday (0=Sunday) to Python weekday
                        if target_weekday == 0:  # Sunday in cron is 0, but Python weekday Sunday is 6
                            target_weekday = 6
                        else:
                            target_weekday -= 1  # Adjust for Python's 0=Monday vs cron's 1=Monday

                        if current_weekday == target_weekday:
                            job_func()

                    # Schedule to run at the interval but only execute on the right day
                    schedule.every(interval).minutes.do(weekday_interval_wrapper)
                    logging.info(f"Scheduled {job_description}every {interval} minutes on {weekday_name}: {cron_expression}")
                    return
                else:
                    # Regular minute interval (all days)
                    schedule.every(interval).minutes.do(job_func)
                    logging.info(f"Scheduled {job_description}every {interval} minutes: {cron_expression}")
                    return

            # Handle hourly intervals
            elif hour.startswith("*/"):
                interval = int(hour[2:])
                if minute == "0":
                    schedule.every(interval).hours.do(job_func)
                else:
                    schedule.every(interval).hours.at(f":{minute.zfill(2)}").do(job_func)
                logging.info(f"Scheduled {job_description}every {interval} hours: {cron_expression}")
                return

            # Handle daily schedules
            elif hour.isdigit() and minute.isdigit() and day == "*" and weekday == "*":
                time_str = f"{hour.zfill(2)}:{minute.zfill(2)}"
                schedule.every().day.at(time_str).do(job_func)
                logging.info(f"Scheduled {job_description}daily at {time_str}: {cron_expression}")
                return

            # Handle weekly schedules (specific time)
            elif hour.isdigit() and minute.isdigit() and day == "*" and weekday.isdigit():
                time_str = f"{hour.zfill(2)}:{minute.zfill(2)}"
                weekdays = ["monday", "tuesday", "wednesday", "thursday", "friday", "saturday", "sunday"]
                weekday_name = weekdays[int(weekday)]
                getattr(schedule.every(), weekday_name).at(time_str).do(job_func)
                logging.info(f"Scheduled {job_description}weekly on {weekday_name} at {time_str}: {cron_expression}")
                return

            # Handle hourly schedules on specific weekdays (e.g., "0 * * * 1" = every hour on Monday)
            elif minute.isdigit() and hour == "*" and day == "*" and weekday.isdigit():
                weekdays = ["monday", "tuesday", "wednesday", "thursday", "friday", "saturday", "sunday"]
                weekday_name = weekdays[int(weekday)]

                # Create a wrapper function that checks the current weekday
                def weekday_hourly_wrapper():
                    current_weekday = datetime.now().weekday()  # 0=Monday, 6=Sunday
                    target_weekday = int(weekday) % 7  # Convert cron weekday (0=Sunday) to Python weekday
                    if target_weekday == 0:  # Sunday in cron is 0, but Python weekday Sunday is 6
                        target_weekday = 6
                    else:
                        target_weekday -= 1  # Adjust for Python's 0=Monday vs cron's 1=Monday

                    if current_weekday == target_weekday:
                        job_func()

                # Schedule to run every hour and check if it's the right day
                if minute == "0":
                    schedule.every().hour.do(weekday_hourly_wrapper)
                else:
                    schedule.every().hour.at(f":{minute.zfill(2)}").do(weekday_hourly_wrapper)

                logging.info(f"Scheduled {job_description}every hour on {weekday_name}: {cron_expression}")
                return

        # If we get here, the expression is invalid
        logging.error(f"Invalid cron expression (must be 5 or 6 parts): {cron_expression}")

    def add_multiple_schedules(self, cron_expressions: list, job_func, job_name: str = ""):
        """Add multiple cron schedules for the same job function"""
        for cron_expr in cron_expressions:
            self.parse_cron_to_schedule(cron_expr, job_func, job_name)

    def start(self):
        """Start the scheduler in a separate thread"""
        if not self.running:
            self.running = True
            self.scheduler_thread = threading.Thread(target=self._run_scheduler, daemon=True)
            self.scheduler_thread.start()
            logging.info("Task scheduler started")

    def _run_scheduler(self):
        """Run the scheduler loop"""
        while self.running:
            schedule.run_pending()
            time.sleep(1)

    def stop(self):
        """Stop the scheduler"""
        self.running = False
        if self.scheduler_thread:
            self.scheduler_thread.join()
        schedule.clear()
        logging.info("Task scheduler stopped")

class NetworkMonitor:
    def __init__(self, config_file: str = 'monitor_config.json'):
        self.config_file = config_file
        self.state_file = 'network_state.json'
        self.mapping_file = 'network_qr_mapping.json'  # Track UniFi network ID -> QR ID
        self.config = self.load_config()

        # Set logging level from config
        log_level = self.config.get('monitor', {}).get('log_level', 'INFO')
        numeric_level = getattr(logging, log_level.upper(), logging.INFO)
        logging.getLogger().setLevel(numeric_level)

        # Initialize debug logger
        self.debug = DebugLogger(self.config)

        self.unifi = UniFiController(self.config)

        self.qr_updater = QRCodeUpdater(self.config)
        self.influx_writer = InfluxDBWriter(self.config)
        self.scheduler = TaskScheduler()

        self.last_state = self.load_state()
        self.network_mapping = self.load_network_mapping()

    def load_config(self) -> Dict:
        """Load configuration from file"""
        try:
            with open(self.config_file, 'r') as f:
                return json.load(f)
        except FileNotFoundError:
            # Create sample config file
            sample_config = {
                "unifi": {
                    "enabled": True,
                    "host": "https://your-controller-ip:8443",
                    "username": "your-username",
                    "password": "your-password",
                    "site": "default"
                },
                "qr_api": {
                    "enabled": True,
                    "url": "http://your-qr-api-url",
                    "api_key": "your-api-key-if-needed",
                    "wifi_endpoint": "/api/wifi",
                    "update_password_endpoint": "/api/wifi/update-password",
                    "library_endpoint": "/api/library"
                },
                "schedules": {
                    "unifi_wifi_schedule": {
                        "enabled": True,
                        "description": "Schedule for syncing WiFi network settings and QR codes",
                        "cron_expressions": [
                            "*/5 * * * *",
                            "0 */6 * * *"
                        ]
                    },
                    "unifi_wan_throughput_schedule": {
                        "enabled": True,
                        "description": "Schedule for collecting WAN throughput metrics",
                        "cron_expressions": [
                            "*/1 * * * *"
                        ]
                    },
                    "unifi_client_usage_schedule": {
                        "enabled": True,
                        "description": "Schedule for collecting client usage metrics",
                        "cron_expressions": [
                            "*/2 * * * *",
                            "*/10 * * * *"
                        ]
                    }
                },
                "monitor": {
                    "networks_to_monitor": ["Guest", "Visitor"],
                    "log_level": "INFO"
                },
                "influxdb": {
                    "enabled": False,
                    "url": "http://localhost:8086",
                    "token": "your-influxdb-token",
                    "org": "your-org",
                    "bucket": "unifi-metrics"
                }
            }

            with open(self.config_file, 'w') as f:
                json.dump(sample_config, f, indent=2)

            logging.info(f"Created sample config file: {self.config_file}")
            logging.info("Please update the configuration file with your settings")
            exit(1)

    def load_state(self) -> Dict:
        """Load previous network state"""
        try:
            with open(self.state_file, 'r') as f:
                return json.load(f)
        except FileNotFoundError:
            return {}

    def save_state(self, state: Dict):
        """Save current network state"""
        with open(self.state_file, 'w') as f:
            json.dump(state, f, indent=2)

    def load_network_mapping(self) -> Dict:
        """Load UniFi network ID -> QR ID mapping"""
        try:
            with open(self.mapping_file, 'r') as f:
                return json.load(f)
        except FileNotFoundError:
            return {}

    def save_network_mapping(self, mapping: Dict):
        """Save UniFi network ID -> QR ID mapping"""
        with open(self.mapping_file, 'w') as f:
            json.dump(mapping, f, indent=2)

    def get_network_hash(self, network: Dict) -> str:
        """Generate hash for network configuration including password hash"""
        # Include password hash for change detection (but don't store the actual password)
        password_hash = hashlib.md5(network['password'].encode()).hexdigest() if network['password'] else 'none'
        network_str = f"{network['ssid']}:{network['security']}:{network['enabled']}:{password_hash}"
        return hashlib.md5(network_str.encode()).hexdigest()

    def sync_networks_to_qr(self) -> bool:
        """Sync all wireless networks to QR system and write metrics immediately"""
        if not self.unifi.enabled:
            logging.debug("UniFi integration disabled, skipping WiFi sync")
            return True

        # Clear QR library cache to get fresh data for each sync
        if self.qr_updater.enabled:
            self.qr_updater.qr_library_cache = None

        current_networks = self.unifi.get_all_networks()
        if not current_networks:
            logging.warning("No wireless networks found or failed to retrieve networks")
            return False

        current_state = {}
        sync_successful = True

        for network in current_networks:
            if not network['enabled']:
                continue

            # Filter networks using ignore list (monitor all except ignored)
            networks_to_ignore = self.config['monitor'].get('networks_to_ignore', [])
            if network['ssid'] in networks_to_ignore:
                logging.debug(f"Skipping network {network['ssid']} (in ignore list)")
                continue

            network_id = network['id']
            network_hash = self.get_network_hash(network)

            # Store minimal state (no passwords)
            current_state[network_id] = {
                'name': network['name'],
                'ssid': network['ssid'],
                'security': network['security'],
                'hash': network_hash,
                'last_synced': datetime.now().isoformat()
            }

            # Check if this network needs updating
            needs_update = (
                network_id not in self.last_state or
                self.last_state[network_id]['hash'] != network_hash or
                self.config['monitor'].get('force_sync', False)
            )

            # Always check if QR entry still exists (handles deleted QR entries)
            if not needs_update and self.qr_updater.enabled:
                existing_qr = self.qr_updater.find_existing_qr(network['ssid'])
                if not existing_qr:
                    logging.warning(f"QR entry missing for {network['ssid']}, will recreate")
                    needs_update = True

            if needs_update and self.qr_updater.enabled:
                logging.info(f"Processing network: {network['name']}")

                # Check for existing mapping first (most reliable)
                network_id = network['id']
                qr_id = self.network_mapping.get(network_id)

                if qr_id:
                    # Verify the QR still exists in the library
                    if self.qr_updater.find_existing_qr(network['ssid']) or self.verify_qr_exists(qr_id):
                        logging.info(f"Using mapped QR ID {qr_id} for network {network['ssid']}")
                        if self.qr_updater.update_existing_qr(qr_id, network):
                            logging.info(f"QR code updated for: {network['name']}")
                        else:
                            logging.error(f"Failed to update existing QR code for: {network['name']}")
                            sync_successful = False
                    else:
                        # Mapped QR no longer exists, remove mapping and create new
                        logging.warning(f"Mapped QR {qr_id} no longer exists for {network['ssid']}, creating new")
                        del self.network_mapping[network_id]
                        qr_id = None

                if not qr_id and self.qr_updater.enabled:
                    # Try to find by SSID or create new
                    if self.qr_updater.update_qr_code(network):
                        # Clear cache and get fresh QR ID for mapping
                        self.qr_updater.qr_library_cache = None
                        new_qr_id = self.qr_updater.find_existing_qr(network['ssid'])
                        if new_qr_id:
                            self.network_mapping[network_id] = new_qr_id
                            logging.info(f"Created mapping: {network['ssid']} ({network_id}) -> {new_qr_id}")
                        else:
                            logging.warning(f"Could not find new QR ID for mapping: {network['ssid']}")
                        logging.info(f"QR code updated for: {network['name']}")
                    else:
                        logging.error(f"Failed to update QR code for: {network['name']}")
                        sync_successful = False

        # Save current state (without passwords) and network mapping
        self.save_state(current_state)
        self.save_network_mapping(self.network_mapping)
        self.last_state = current_state

        return sync_successful

    def verify_qr_exists(self, qr_id: str) -> bool:
        """Verify a QR ID still exists in the library"""
        try:
            entries = self.qr_updater.get_qr_library()
            for entry in entries:
                if entry.get('qr_id') == qr_id:
                    return True
            return False
        except Exception as e:
            logging.error(f"Failed to verify QR existence {qr_id}: {e}")
            return False

    def setup_scheduled_tasks(self):
        """Setup scheduled tasks based on configuration"""
        schedules_config = self.config.get('schedules', {})

        # UniFi WiFi schedule (includes QR code sync)
        wifi_schedule = schedules_config.get('unifi_wifi_schedule', {})
        if wifi_schedule.get('enabled', True) and self.unifi.enabled:
            cron_expressions = wifi_schedule.get('cron_expressions', ['*/5 * * * *'])
            self.scheduler.add_multiple_schedules(
                cron_expressions,
                self.sync_networks_to_qr,
                "UniFi WiFi sync"
            )
            logging.info(f"UniFi WiFi schedule: {wifi_schedule.get('description', 'No description')}")

        # UniFi WAN throughput schedule
        wan_schedule = schedules_config.get('unifi_wan_throughput_schedule', {})
        if wan_schedule.get('enabled', True) and self.unifi.enabled:
            cron_expressions = wan_schedule.get('cron_expressions', ['*/1 * * * *'])
            self.scheduler.add_multiple_schedules(
                cron_expressions,
                self.collect_wan_metrics,
                "WAN throughput collection"
            )
            logging.info(f"WAN throughput schedule: {wan_schedule.get('description', 'No description')}")

        # UniFi client usage schedule
        client_schedule = schedules_config.get('unifi_client_usage_schedule', {})
        if client_schedule.get('enabled', True) and self.unifi.enabled:
            cron_expressions = client_schedule.get('cron_expressions', ['*/2 * * * *'])
            self.scheduler.add_multiple_schedules(
                cron_expressions,
                self.collect_client_metrics,
                "Client usage collection"
            )
            logging.info(f"Client usage schedule: {client_schedule.get('description', 'No description')}")

    def collect_wan_metrics(self):
        """Collect and write WAN throughput metrics immediately to InfluxDB"""
        try:
            if not self.unifi.enabled:
                self.debug.log('unifi', 'DEBUG', "UniFi integration disabled, skipping WAN metrics")
                return

            self.debug.log_schedule_event('collect_wan_metrics', 'Starting')
            wan_data = self.unifi.get_wan_throughput()

            if wan_data:
                # Write immediately to InfluxDB if enabled
                if self.influx_writer.enabled:
                    self.influx_writer.write_wan_throughput(wan_data)
                    self.debug.log_database_write('wan_throughput', 1, True)
                    self.debug.log('unifi', 'DEBUG', f"WAN throughput: {wan_data['rx_rate']:.2f} RX, {wan_data['tx_rate']:.2f} TX bytes/sec")
                    self.debug.log_success_operation('WAN metrics collection')
                else:
                    self.debug.log('unifi', 'INFO', f"WAN metrics collected but InfluxDB disabled: {wan_data['rx_rate']:.2f} RX, {wan_data['tx_rate']:.2f} TX bytes/sec")
            else:
                self.debug.log('unifi', 'WARNING', "No WAN data returned from UniFi API")
        except Exception as e:
            self.debug.log('unifi', 'ERROR', f"Error collecting WAN metrics: {e}")

    def collect_client_metrics(self):
        """Collect and write client usage metrics immediately to InfluxDB"""
        try:
            if not self.unifi.enabled:
                self.debug.log('unifi', 'DEBUG', "UniFi integration disabled, skipping client metrics")
                return

            self.debug.log_schedule_event('collect_client_metrics', 'Starting')
            top_clients = self.unifi.get_top_clients(15)

            if top_clients:
                # Write immediately to InfluxDB if enabled
                if self.influx_writer.enabled:
                    self.influx_writer.write_client_usage(top_clients)
                    self.debug.log_database_write('client_usage', len(top_clients), True)
                    self.debug.log('unifi', 'DEBUG', f"Client usage written ({len(top_clients)} clients)")
                    self.debug.log_success_operation('Client metrics collection', f"{len(top_clients)} clients processed")
                else:
                    self.debug.log('unifi', 'INFO', f"Client metrics collected but InfluxDB disabled: {len(top_clients)} clients")
            else:
                self.debug.log('unifi', 'WARNING', "No client data returned from UniFi API")
        except Exception as e:
            self.debug.log('unifi', 'ERROR', f"Error collecting client metrics: {e}")

    def run_monitor(self):
        """Main monitoring loop with scheduled tasks"""
        logging.info("Starting UniFi network monitor with scheduled tasks")

        # Setup scheduled tasks
        self.setup_scheduled_tasks()

        # Start the scheduler
        self.scheduler.start()

        try:
            # Keep the main thread alive
            while True:
                time.sleep(10)  # Check every 10 seconds for shutdown

        except KeyboardInterrupt:
            logging.info("Monitor stopped by user")

        finally:
            # Cleanup
            self.scheduler.stop()
            self.influx_writer.close()
            logging.info("Monitor shutdown complete")

class WebInterface:
    def __init__(self, monitor: NetworkMonitor, port: int = 5000):
        self.monitor = monitor
        self.port = port
        self.app = Flask(__name__)
        self.debug = monitor.debug  # Use the same debug logger

        # Load web interface config
        web_config = monitor.config.get('web_interface', {})
        self.allowed_ips = web_config.get('allowed_ips', ['127.0.0.1', '::1'])
        self.allow_all_for_dashboard = web_config.get('allow_all_for_dashboard', True)

        self.debug.log('web', 'INFO', f"Web interface initialized on port {port}")
        self.debug.log('web', 'DEBUG', f"Allowed IPs: {self.allowed_ips}")

        self.setup_routes()

    def check_ip_allowed(self, api_endpoint=True):
        """Decorator to check if client IP is allowed"""
        def decorator(f):
            @wraps(f)
            def decorated_function(*args, **kwargs):
                client_ip = request.environ.get('HTTP_X_FORWARDED_FOR', request.environ.get('REMOTE_ADDR'))

                # Allow dashboard access if configured
                if not api_endpoint and self.allow_all_for_dashboard:
                    return f(*args, **kwargs)

                # Check if IP is in allowed list
                try:
                    client_addr = ipaddress.ip_address(client_ip)
                    for allowed in self.allowed_ips:
                        if '/' in allowed:  # CIDR notation
                            if client_addr in ipaddress.ip_network(allowed, strict=False):
                                return f(*args, **kwargs)
                        else:  # Single IP
                            if client_addr == ipaddress.ip_address(allowed):
                                return f(*args, **kwargs)

                    # IP not allowed
                    self.debug.log('web', 'WARNING', f"Access denied for IP: {client_ip} (endpoint: {request.endpoint})")
                    return jsonify({'success': False, 'message': 'Access denied'}), 403

                except Exception as e:
                    self.debug.log('web', 'ERROR', f"IP check error: {e}")
                    return jsonify({'success': False, 'message': 'Access denied'}), 403

            return decorated_function
        return decorator

    def get_next_schedule_times(self):
        """Get next execution times for scheduled tasks"""
        next_times = {}
        try:
            now = datetime.now()

            for job in schedule.jobs:
                job_func_str = str(job.job_func)
                next_run = job.next_run

                # Debug logging to see what jobs we have
                logging.debug(f"Checking job: {job_func_str}, next_run: {next_run}")

                if next_run:
                    # Check if this is a weekday wrapper function
                    if 'weekday' in job_func_str and 'wrapper' in job_func_str:
                        # This is a weekday-restricted job, calculate actual next execution
                        seconds_until = self._calculate_weekday_restricted_next_run(job)
                        logging.debug(f"Weekday-restricted job seconds_until: {seconds_until}")
                    else:
                        # Regular job, use direct next_run time
                        seconds_until = (next_run - now).total_seconds()

                    if seconds_until and seconds_until > 0:
                        # Check for sync_networks function (WiFi sync)
                        if ('sync_networks' in job_func_str or 'sync_wifi' in job_func_str or
                            'wifi' in job_func_str.lower() or 'weekday_interval_wrapper' in job_func_str or
                            'weekday_hourly_wrapper' in job_func_str):
                            # For WiFi sync, only store the shortest time (closest execution)
                            if 'wifi_sync' not in next_times or seconds_until < next_times['wifi_sync']:
                                next_times['wifi_sync'] = int(seconds_until)
                                logging.debug(f"Added wifi_sync timer: {int(seconds_until)} seconds")
                        elif 'collect_wan' in job_func_str or 'wan' in job_func_str.lower():
                            if 'wan_metrics' not in next_times or seconds_until < next_times['wan_metrics']:
                                next_times['wan_metrics'] = int(seconds_until)
                        elif 'collect_client' in job_func_str or 'client' in job_func_str.lower():
                            if 'client_metrics' not in next_times or seconds_until < next_times['client_metrics']:
                                next_times['client_metrics'] = int(seconds_until)

            logging.debug(f"Final next_times: {next_times}")
            return next_times
        except Exception as e:
            logging.error(f"Error getting schedule times: {e}")
            return {}

    def _calculate_weekday_restricted_next_run(self, job):
        """Calculate next actual execution time for weekday-restricted jobs"""
        try:
            now = datetime.now()

            # Try to extract weekday from the schedule interval
            # This is a heuristic based on common patterns
            if hasattr(job, 'interval') and hasattr(job, 'unit'):
                if job.unit == 'minutes':
                    # This is likely "*/30 * * * 0" pattern (every 30 min on Sunday)
                    interval_minutes = job.interval

                    # Find next Sunday
                    days_until_sunday = (6 - now.weekday()) % 7  # 0=Monday, 6=Sunday

                    if days_until_sunday == 0:  # Today is Sunday
                        # Find next 30-minute interval today
                        current_minute = now.minute
                        next_interval = ((current_minute // interval_minutes) + 1) * interval_minutes

                        if next_interval < 60:
                            # Next interval is still this hour
                            next_execution = now.replace(minute=next_interval, second=0, microsecond=0)
                        else:
                            # Next interval is next hour
                            next_hour = now.hour + 1
                            if next_hour < 24:
                                next_execution = now.replace(hour=next_hour, minute=0, second=0, microsecond=0)
                            else:
                                # Next execution would be next Sunday
                                next_execution = now + timedelta(days=7)
                                next_execution = next_execution.replace(hour=0, minute=0, second=0, microsecond=0)

                        # If calculated time is in the past, go to next Sunday
                        if next_execution <= now:
                            next_execution = now + timedelta(days=7)
                            next_execution = next_execution.replace(hour=0, minute=0, second=0, microsecond=0)
                    else:
                        # Next Sunday at midnight (first interval of the day)
                        next_execution = now + timedelta(days=days_until_sunday)
                        next_execution = next_execution.replace(hour=0, minute=0, second=0, microsecond=0)

                    return (next_execution - now).total_seconds()

                elif job.unit == 'hours':
                    # This is likely "0 * * * 1" pattern (every hour on specific day)
                    # Extract target weekday from the wrapper function
                    current_weekday = now.weekday()  # 0=Monday, 6=Sunday

                    # For hourly jobs, find the next occurrence of the target day
                    # For now, we'll use a heuristic - if it's an hourly weekday job,
                    # find the next occurrence of that weekday
                    target_weekdays = []

                    # Try to determine which weekdays this job runs on by checking job function
                    job_func_str = str(job.job_func)
                    if 'monday' in job_func_str.lower():
                        target_weekdays = [0]  # Monday
                    elif 'tuesday' in job_func_str.lower():
                        target_weekdays = [1]  # Tuesday
                    elif 'wednesday' in job_func_str.lower():
                        target_weekdays = [2]  # Wednesday
                    elif 'thursday' in job_func_str.lower():
                        target_weekdays = [3]  # Thursday
                    elif 'friday' in job_func_str.lower():
                        target_weekdays = [4]  # Friday
                    elif 'saturday' in job_func_str.lower():
                        target_weekdays = [5]  # Saturday
                    elif 'sunday' in job_func_str.lower():
                        target_weekdays = [6]  # Sunday
                    else:
                        # Default to checking multiple weekdays (Monday-Saturday for "0 * * * 1-6" pattern)
                        target_weekdays = [0, 1, 2, 3, 4, 5]  # Mon-Sat

                    # Find next occurrence of any target weekday
                    min_days_until = 7  # Start with next week
                    for target_weekday in target_weekdays:
                        days_until = (target_weekday - current_weekday) % 7
                        if days_until == 0:  # Today
                            # Check if we're past the next hour boundary
                            next_hour_time = now.replace(minute=0, second=0, microsecond=0) + timedelta(hours=1)
                            if next_hour_time > now:
                                days_until = 0  # Use today
                            else:
                                days_until = 7  # Use next week
                        if days_until < min_days_until:
                            min_days_until = days_until

                    if min_days_until == 0:  # Today
                        next_execution = now.replace(minute=0, second=0, microsecond=0) + timedelta(hours=1)
                    else:
                        next_execution = now + timedelta(days=min_days_until)
                        next_execution = next_execution.replace(hour=0, minute=0, second=0, microsecond=0)

                    return (next_execution - now).total_seconds()

            # Fallback to next scheduled run
            return (job.next_run - now).total_seconds()

        except Exception as e:
            logging.debug(f"Error calculating weekday-restricted time: {e}")
            return (job.next_run - now).total_seconds()

    def setup_routes(self):
        """Setup Flask routes"""

        @self.app.route('/')
        @self.check_ip_allowed(api_endpoint=False)
        def index():
            """Main dashboard page"""
            html_template = '''
<!DOCTYPE html>
<html>
<head>
    <title>UniFi Monitor Control Panel</title>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; background: #f5f5f5; }
        .container { max-width: 800px; margin: 0 auto; background: white; padding: 20px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
        h1 { color: #333; text-align: center; margin-bottom: 30px; }
        h2 { color: #555; border-bottom: 2px solid #eee; padding-bottom: 10px; }
        .section { margin-bottom: 30px; }
        .button-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 15px; margin: 20px 0; }
        .btn {
            padding: 12px 20px; border: none; border-radius: 6px; cursor: pointer;
            font-size: 14px; transition: all 0.3s; text-decoration: none;
            display: inline-block; text-align: center; font-weight: bold;
        }
        .btn-primary { background: #007bff; color: white; }
        .btn-primary:hover { background: #0056b3; }
        .btn-success { background: #28a745; color: white; }
        .btn-success:hover { background: #1e7e34; }
        .btn-warning { background: #ffc107; color: #212529; }
        .btn-warning:hover { background: #d39e00; }
        .btn-danger { background: #dc3545; color: white; }
        .btn-danger:hover { background: #c82333; }
        .status {
            padding: 10px; margin: 10px 0; border-radius: 4px;
            background: #d4edda; border: 1px solid #c3e6cb; color: #155724;
        }
        .status.error { background: #f8d7da; border: 1px solid #f5c6cb; color: #721c24; }
        .info-box { background: #e9ecef; padding: 15px; border-radius: 6px; margin: 15px 0; }
        .schedule-info { font-size: 12px; color: #666; margin-top: 5px; }
        .countdown-timer {
            background: #fff3cd; border: 1px solid #ffeaa7; color: #856404;
            padding: 8px 12px; border-radius: 4px; font-weight: bold;
            margin: 5px 0; font-size: 11px;
        }
        .countdown-timer.soon { background: #f8d7da; border-color: #f5c6cb; color: #721c24; }
        .next-schedules { margin: 15px 0; }
        .api-examples { background: #f8f9fa; padding: 15px; border-radius: 6px; margin: 15px 0; }
        .code-block {
            background: #2d3748; color: #e2e8f0; padding: 12px; border-radius: 4px;
            font-family: 'Courier New', monospace; font-size: 12px; margin: 8px 0;
            overflow-x: auto; white-space: pre;
        }
        .endpoint { font-weight: bold; color: #007bff; }
        .method-get { color: #28a745; }
        .method-post { color: #dc3545; }
        .collapsible {
            background-color: #f1f1f1; color: #444; cursor: pointer; padding: 10px;
            width: 100%; border: none; text-align: left; outline: none; border-radius: 4px;
            margin: 5px 0; font-weight: bold;
        }
        .collapsible:hover { background-color: #ddd; }
        .collapsible.active { background-color: #007bff; color: white; }
        .content { display: none; overflow: hidden; background-color: #f9f9f9; padding: 15px; border-radius: 4px; }
    </style>
    <script>
        async function triggerAction(endpoint, buttonId) {
            const button = document.getElementById(buttonId);
            const originalText = button.innerHTML;
            button.innerHTML = 'Working...';
            button.disabled = true;

            try {
                const response = await fetch(endpoint, { method: 'POST' });
                const result = await response.json();

                if (result.success) {
                    showStatus(result.message, 'success');
                } else {
                    showStatus(result.message, 'error');
                }
            } catch (error) {
                showStatus('Error: ' + error.message, 'error');
            }

            button.innerHTML = originalText;
            button.disabled = false;
        }

        function showStatus(message, type) {
            const statusDiv = document.getElementById('status');
            statusDiv.className = type === 'error' ? 'status error' : 'status';
            statusDiv.innerHTML = message;
            statusDiv.style.display = 'block';
            setTimeout(() => statusDiv.style.display = 'none', 5000);
        }

        function confirmRestart() {
            return confirm('Are you sure you want to restart the monitor service? This will temporarily stop all monitoring.');
        }

        let countdownTimers = {};

        function formatTime(seconds) {
            if (seconds <= 0) return 'Now';

            const hours = Math.floor(seconds / 3600);
            const minutes = Math.floor((seconds % 3600) / 60);
            const secs = seconds % 60;

            if (hours > 0) {
                return `${hours}h ${minutes}m ${secs}s`;
            } else if (minutes > 0) {
                return `${minutes}m ${secs}s`;
            } else {
                return `${secs}s`;
            }
        }

        function updateCountdowns() {
            for (const [type, element] of Object.entries(countdownTimers)) {
                if (element.seconds > 0) {
                    element.seconds--;
                    const timerDiv = document.getElementById(`countdown-${type}`);
                    if (timerDiv) {
                        timerDiv.textContent = `Next: ${formatTime(element.seconds)}`;
                        timerDiv.className = element.seconds <= 60 ? 'countdown-timer soon' : 'countdown-timer';
                    }
                } else {
                    // Timer expired, refresh countdown data
                    refreshCountdowns();
                    break;
                }
            }
        }

        async function refreshCountdowns() {
            try {
                const response = await fetch('/api/schedules');
                const data = await response.json();

                if (data.success) {
                    countdownTimers = {};
                    for (const [type, seconds] of Object.entries(data.schedules)) {
                        countdownTimers[type] = { seconds: seconds };
                    }
                }
            } catch (error) {
                console.error('Error refreshing countdowns:', error);
            }
        }

        async function getDebugStatus() {
            try {
                const response = await fetch('/api/debug-status');
                const data = await response.json();

                if (data.success) {
                    document.getElementById('current-debug-level').textContent = data.debug_info.level;
                    showStatus(`Debug Level: ${data.debug_info.level} | Categories: ${Object.entries(data.debug_info.categories).filter(([k,v]) => v).map(([k,v]) => k.toUpperCase()).join(', ') || 'None'}`, 'success');
                } else {
                    showStatus(data.message, 'error');
                }
            } catch (error) {
                showStatus('Error getting debug status: ' + error.message, 'error');
            }
        }

        // Initialize countdowns on page load
        document.addEventListener('DOMContentLoaded', function() {
            refreshCountdowns();
            getDebugStatus(); // Load debug status
            setInterval(updateCountdowns, 1000);
            setInterval(refreshCountdowns, 300000); // Refresh every 5 minutes

            // Setup collapsible sections
            const collapsibles = document.getElementsByClassName('collapsible');
            for (let i = 0; i < collapsibles.length; i++) {
                collapsibles[i].addEventListener('click', function() {
                    this.classList.toggle('active');
                    const content = this.nextElementSibling;
                    if (content.style.display === 'block') {
                        content.style.display = 'none';
                    } else {
                        content.style.display = 'block';
                    }
                });
            }
        });
    </script>
</head>
<body>
    <div class="container">
        <h1>🌐 UniFi Monitor Control Panel</h1>

        <div id="status" style="display:none;"></div>

        <div class="section">
            <h2>📊 Manual Schedule Triggers</h2>
            <div class="info-box">
                <strong>WiFi Sync:</strong> Updates QR codes for all wireless networks
                <div class="schedule-info">Scheduled: Every 30 min on Sunday, every hour Mon-Sat</div>
                <div id="countdown-wifi_sync" class="countdown-timer">Loading...</div>
            </div>
            <div class="button-grid">
                <button class="btn btn-primary" id="wifi-btn" onclick="triggerAction('/trigger/wifi', 'wifi-btn')">
                    🔄 Sync WiFi Networks
                </button>
            </div>
        </div>

        <div class="section">
            <h2>📈 Metrics Collection</h2>
            <div class="info-box">
                <strong>WAN Throughput:</strong> Collects internet speed metrics<br>
                <strong>Client Usage:</strong> Monitors individual device bandwidth
                <div class="next-schedules">
                    <div id="countdown-wan_metrics" class="countdown-timer">Loading...</div>
                    <div id="countdown-client_metrics" class="countdown-timer">Loading...</div>
                </div>
            </div>
            <div class="button-grid">
                <button class="btn btn-success" id="wan-btn" onclick="triggerAction('/trigger/wan', 'wan-btn')">
                    📡 Collect WAN Metrics
                </button>
                <button class="btn btn-success" id="client-btn" onclick="triggerAction('/trigger/clients', 'client-btn')">
                    👥 Collect Client Metrics
                </button>
            </div>
        </div>

        <div class="section">
            <h2>🔧 System Control</h2>
            <div class="button-grid">
                <button class="btn btn-warning" id="status-btn" onclick="triggerAction('/status', 'status-btn')">
                    ℹ️ Service Status
                </button>
                <button class="btn btn-danger" id="restart-btn"
                        onclick="if(confirmRestart()) triggerAction('/restart', 'restart-btn')">
                    🔄 Restart Service
                </button>
            </div>
        </div>

        <div class="section">
            <h2>🔍 Debug Settings</h2>
            <div class="info-box">
                <strong>Current Debug Level:</strong> <span id="current-debug-level">Loading...</span><br>
                <strong>Categories:</strong> API, Schedule, UniFi, InfluxDB, Web
                <div style="margin-top: 10px;">
                    <small>Debug levels: SILENT → MINIMAL → NORMAL → VERBOSE → FULL</small>
                </div>
            </div>
            <div class="button-grid">
                <button class="btn btn-warning" id="debug-status-btn" onclick="getDebugStatus()">
                    🔍 Debug Status
                </button>
            </div>
        </div>

        <div class="section">
            <h2>🔌 API Endpoints</h2>

            <button class="collapsible">📋 Schedule Information</button>
            <div class="content">
                <div class="api-examples">
                    <p><span class="method-get">GET</span> <span class="endpoint">/api/schedules</span></p>
                    <p>Get next execution times for all scheduled tasks (for countdown timers)</p>

                    <strong>Example Request:</strong>
                    <div class="code-block">curl -X GET http://localhost:5000/api/schedules</div>

                    <strong>Example Response:</strong>
                    <div class="code-block">{
  "success": true,
  "schedules": {
    "wifi_sync": 1825,
    "wan_metrics": 3,
    "client_metrics": 3
  }
}</div>

                    <hr style="margin: 15px 0;">

                    <p><span class="method-get">GET</span> <span class="endpoint">/api/debug-status</span></p>
                    <p>Get current debug configuration and logging levels</p>

                    <strong>Example Request:</strong>
                    <div class="code-block">curl -X GET http://localhost:5000/api/debug-status</div>

                    <strong>Example Response:</strong>
                    <div class="code-block">{
  "success": true,
  "debug_info": {
    "level": "NORMAL",
    "categories": {
      "api": false,
      "unifi": false,
      "influx": false
    }
  }
}</div>
                </div>
            </div>

            <button class="collapsible">🔄 Manual Triggers</button>
            <div class="content">
                <div class="api-examples">
                    <p><span class="method-post">POST</span> <span class="endpoint">/trigger/wifi</span></p>
                    <p>Manually trigger WiFi network synchronization and QR code updates</p>

                    <strong>Example Request:</strong>
                    <div class="code-block">curl -X POST http://localhost:5000/trigger/wifi</div>

                    <hr style="margin: 15px 0;">

                    <p><span class="method-post">POST</span> <span class="endpoint">/trigger/wan</span></p>
                    <p>Manually collect WAN throughput metrics</p>

                    <strong>Example Request:</strong>
                    <div class="code-block">curl -X POST http://localhost:5000/trigger/wan</div>

                    <hr style="margin: 15px 0;">

                    <p><span class="method-post">POST</span> <span class="endpoint">/trigger/clients</span></p>
                    <p>Manually collect client usage metrics</p>

                    <strong>Example Request:</strong>
                    <div class="code-block">curl -X POST http://localhost:5000/trigger/clients</div>

                    <strong>Success Response:</strong>
                    <div class="code-block">{
  "success": true,
  "message": "Client metrics collected successfully!"
}</div>
                </div>
            </div>

            <button class="collapsible">🔧 System Control</button>
            <div class="content">
                <div class="api-examples">
                    <p><span class="method-post">POST</span> <span class="endpoint">/status</span></p>
                    <p>Get current service status and configuration info</p>

                    <strong>Example Request:</strong>
                    <div class="code-block">curl -X POST http://localhost:5000/status</div>

                    <hr style="margin: 15px 0;">

                    <p><span class="method-post">POST</span> <span class="endpoint">/restart</span></p>
                    <p>Restart the monitoring service (requires confirmation)</p>

                    <strong>Example Request:</strong>
                    <div class="code-block">curl -X POST http://localhost:5000/restart</div>

                    <strong>Response:</strong>
                    <div class="code-block">{
  "success": true,
  "message": "Service restart initiated... Please refresh page in a few seconds."
}</div>
                </div>
            </div>

            <button class="collapsible">🔒 Security & Access</button>
            <div class="content">
                <div class="api-examples">
                    <strong>IP Whitelisting:</strong>
                    <p>API endpoints are protected by IP whitelisting. Configure allowed IPs in <code>monitor_config.json</code>:</p>

                    <div class="code-block">"web_interface": {
  "enabled": true,
  "port": 5000,
  "allowed_ips": [
    "127.0.0.1",
    "::1",
    "10.1.10.0/24",
    "192.168.2.0/24"
  ],
  "allow_all_for_dashboard": true
}</div>

                    <strong>Current Whitelist:</strong>
                    <ul>
                        <li>🏠 <code>127.0.0.1</code> - Localhost IPv4</li>
                        <li>🏠 <code>::1</code> - Localhost IPv6</li>
                        <li>🌐 <code>10.1.10.0/24</code> - Management network</li>
                        <li>🌐 <code>192.168.2.0/24</code> - Local network</li>
                    </ul>

                    <p><strong>Note:</strong> Dashboard viewing can be allowed for all IPs while API endpoints remain restricted.</p>
                </div>
            </div>
        </div>

        <div class="info-box">
            <strong>💡 Tips:</strong>
            <ul>
                <li>Use manual triggers to test functionality or get immediate updates</li>
                <li>WAN and Client metrics are collected automatically every 5 seconds</li>
                <li>WiFi sync runs on the configured schedule to avoid excessive API calls</li>
                <li>Restart the service if you've made configuration changes</li>
                <li>API endpoints require whitelisted IPs for security</li>
            </ul>
        </div>
    </div>
</body>
</html>
            '''
            return html_template

        @self.app.route('/api/schedules', methods=['GET'])
        def get_schedules():
            """Get next schedule times for countdown timers"""
            try:
                next_times = self.get_next_schedule_times()
                return jsonify({'success': True, 'schedules': next_times})
            except Exception as e:
                return jsonify({'success': False, 'message': f'Error: {str(e)}'})

        @self.app.route('/api/debug-status', methods=['GET'])
        def get_debug_status():
            """Get current debug configuration and status"""
            try:
                debug_info = {
                    'level': self.debug.level,
                    'quiet_mode': self.debug.quiet_mode,
                    'errors_only': self.debug.errors_only,
                    'categories': {
                        'api': self.debug.api_debug,
                        'schedule': self.debug.schedule_debug,
                        'unifi': self.debug.unifi_debug,
                        'influx': self.debug.influx_debug,
                        'web': self.debug.web_debug
                    },
                    'logging_flags': {
                        'log_responses': self.debug.log_responses,
                        'log_writes': self.debug.log_writes,
                        'log_success': self.debug.log_success
                    },
                    'max_response_length': self.debug.max_response_length
                }
                return jsonify({'success': True, 'debug_info': debug_info})
            except Exception as e:
                return jsonify({'success': False, 'message': f'Error: {str(e)}'})

        @self.app.route('/trigger/wifi', methods=['POST'])
        @self.check_ip_allowed(api_endpoint=True)
        def trigger_wifi():
            """Manually trigger WiFi network sync"""
            client_ip = request.environ.get('REMOTE_ADDR', 'unknown')
            self.debug.log('web', 'INFO', f"Manual WiFi sync triggered by {client_ip}")
            try:
                success = self.monitor.sync_networks_to_qr()
                if success:
                    self.debug.log_success_operation('Manual WiFi sync')
                    return jsonify({'success': True, 'message': 'WiFi networks synced successfully!'})
                else:
                    self.debug.log('web', 'WARNING', 'Manual WiFi sync failed')
                    return jsonify({'success': False, 'message': 'WiFi sync failed - check logs for details'})
            except Exception as e:
                self.debug.log('web', 'ERROR', f"Manual WiFi sync failed: {e}")
                return jsonify({'success': False, 'message': f'Error: {str(e)}'})

        @self.app.route('/trigger/wan', methods=['POST'])
        @self.check_ip_allowed(api_endpoint=True)
        def trigger_wan():
            """Manually trigger WAN metrics collection"""
            try:
                self.monitor.collect_wan_metrics()
                return jsonify({'success': True, 'message': 'WAN metrics collected successfully!'})
            except Exception as e:
                logging.error(f"Manual WAN collection failed: {e}")
                return jsonify({'success': False, 'message': f'Error: {str(e)}'})

        @self.app.route('/trigger/clients', methods=['POST'])
        @self.check_ip_allowed(api_endpoint=True)
        def trigger_clients():
            """Manually trigger client metrics collection"""
            try:
                self.monitor.collect_client_metrics()
                return jsonify({'success': True, 'message': 'Client metrics collected successfully!'})
            except Exception as e:
                logging.error(f"Manual client collection failed: {e}")
                return jsonify({'success': False, 'message': f'Error: {str(e)}'})

        @self.app.route('/status', methods=['POST'])
        @self.check_ip_allowed(api_endpoint=True)
        def get_status():
            """Get service status information"""
            try:
                status_info = {
                    'unifi_enabled': self.monitor.unifi.enabled,
                    'influxdb_enabled': self.monitor.influx_writer.enabled,
                    'scheduler_running': self.monitor.scheduler.running if hasattr(self.monitor.scheduler, 'running') else 'Unknown',
                    'uptime': 'Service is running'
                }

                status_msg = f"""
                <strong>Service Status:</strong><br>
                • UniFi Integration: {'✅ Enabled' if status_info['unifi_enabled'] else '❌ Disabled'}<br>
                • InfluxDB Integration: {'✅ Enabled' if status_info['influxdb_enabled'] else '❌ Disabled'}<br>
                • Scheduler: {'✅ Running' if status_info['scheduler_running'] else '❌ Stopped'}<br>
                • Status: {status_info['uptime']}
                """

                return jsonify({'success': True, 'message': status_msg})
            except Exception as e:
                return jsonify({'success': False, 'message': f'Error getting status: {str(e)}'})

        @self.app.route('/restart', methods=['POST'])
        @self.check_ip_allowed(api_endpoint=True)
        def restart_service():
            """Restart the monitoring service"""
            try:
                logging.info("Service restart requested via web interface")

                # Schedule restart in a separate thread to allow response to be sent
                def restart_in_background():
                    time.sleep(2)  # Allow time for response to be sent
                    logging.info("Restarting service...")
                    os.execv(sys.executable, ['python'] + sys.argv)

                restart_thread = threading.Thread(target=restart_in_background, daemon=True)
                restart_thread.start()

                return jsonify({'success': True, 'message': 'Service restart initiated... Please refresh page in a few seconds.'})
            except Exception as e:
                logging.error(f"Restart failed: {e}")
                return jsonify({'success': False, 'message': f'Restart failed: {str(e)}'})

    def run(self):
        """Start the web interface"""
        try:
            logging.info(f"Starting web interface on port {self.port}")
            self.app.run(host='0.0.0.0', port=self.port, debug=False, use_reloader=False)
        except Exception as e:
            logging.error(f"Failed to start web interface: {e}")

def main():
    monitor = NetworkMonitor()

    # Check if web interface is requested or enabled in config
    web_config = monitor.config.get('web_interface', {})
    web_enabled = web_config.get('enabled', False)
    config_port = web_config.get('port', 5000)

    web_port = None

    # Command line --web flag takes precedence
    if '--web' in sys.argv:
        try:
            web_idx = sys.argv.index('--web')
            if web_idx + 1 < len(sys.argv) and sys.argv[web_idx + 1].isdigit():
                web_port = int(sys.argv[web_idx + 1])
            else:
                web_port = config_port  # Use config port instead of hardcoded 5000
        except:
            web_port = config_port
    elif web_enabled:
        # Web interface enabled in config but no --web flag
        web_port = config_port
        logging.info(f"Web interface enabled in config, starting on port {web_port}")

    if web_port:
        # Run with web interface
        web_interface = WebInterface(monitor, web_port)

        # Start monitor in background thread
        monitor_thread = threading.Thread(target=monitor.run_monitor, daemon=True)
        monitor_thread.start()

        # Start web interface (blocking)
        web_interface.run()
    else:
        # Run normal monitor
        monitor.run_monitor()

if __name__ == "__main__":
    main()