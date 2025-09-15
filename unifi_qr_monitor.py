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
from datetime import datetime
from typing import Dict, Optional, List
import urllib3

# Disable SSL warnings for self-signed certificates
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

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

class QRCodeUpdater:
    def __init__(self, config: Dict):
        self.qr_api_url = config['qr_api']['url'].rstrip('/')
        self.qr_api_key = config['qr_api']['api_key']
        self.wifi_endpoint = config['qr_api']['wifi_endpoint']
        self.update_password_endpoint = config['qr_api']['update_password_endpoint']
        self.library_endpoint = config['qr_api']['library_endpoint']
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

        self.unifi = UniFiController(self.config)

        self.qr_updater = QRCodeUpdater(self.config)

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
                    "host": "https://your-controller-ip:8443",
                    "username": "your-username",
                    "password": "your-password",
                    "site": "default"
                },
                "qr_api": {
                    "url": "http://your-qr-api-url",
                    "api_key": "your-api-key-if-needed"
                },
                "monitor": {
                    "check_interval": 60,
                    "networks_to_monitor": ["Guest", "Visitor"]
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
        """Sync all wireless networks to QR system"""
        # Clear QR library cache to get fresh data for each sync
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
            if not needs_update:
                existing_qr = self.qr_updater.find_existing_qr(network['ssid'])
                if not existing_qr:
                    logging.warning(f"QR entry missing for {network['ssid']}, will recreate")
                    needs_update = True

            if needs_update:
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

                if not qr_id:
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

    def run_monitor(self):
        """Main monitoring loop"""
        check_interval = self.config['monitor'].get('check_interval', 60)
        logging.info(f"Starting UniFi wireless network sync (checking every {check_interval}s)")

        while True:
            try:
                if self.sync_networks_to_qr():
                    logging.info("Network sync completed successfully")
                else:
                    logging.warning("Network sync completed with errors")

            except KeyboardInterrupt:
                logging.info("Monitor stopped by user")
                break
            except Exception as e:
                logging.error(f"Error in sync loop: {e}")

            time.sleep(check_interval)

def main():
    monitor = NetworkMonitor()
    monitor.run_monitor()

if __name__ == "__main__":
    main()