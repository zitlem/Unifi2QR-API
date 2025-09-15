# UniFi QR Code Monitor

Automatically monitors UniFi controller for WiFi network changes and updates QR codes via QRWiFi API. (https://github.com/zitlem/QR-WIFI)

## Features

- 🔍 **Real-time monitoring** of UniFi wireless networks
- 🔐 **Automatic password sync** when WiFi passwords change
- 🏷️ **Smart name change handling** using stable network IDs
- 🔄 **Auto-recovery** recreates missing QR codes
- ⚡ **Efficient updates** only processes changed networks
- 🛡️ **Secure** - passwords never stored locally, only hashed for change detection

## Quick Start

1. **Install dependencies:**
   ```bash
   pip install -r requirements.txt
   ```

2. **Configure settings** in `monitor_config.json`:
   ```json
   {
     "unifi": {
       "host": "https://your-controller-ip",
       "username": "your-admin-user",
       "password": "your-password"
     },
     "qr_api": {
       "url": "http://your-qr-server",
       "api_key": "your-api-key"
     }
   }
   ```

3. **Run the monitor:**
   ```bash
   python unifi_qr_monitor.py
   ```

## Configuration

### UniFi Settings
- **host**: UniFi controller URL (https://ip:8443)
- **username**: Admin user with network read permissions
- **password**: User password
- **site**: UniFi site name (default: "default")

### QR API Settings
- **url**: QRWiFi server URL
- **api_key**: API key for authentication
- **wifi_endpoint**: WiFi creation endpoint (default: "/wifi")
- **library_endpoint**: QR library endpoint (default: "/library")

### Monitor Settings
- **check_interval**: Seconds between checks (default: 60)
- **networks_to_ignore**: WiFi networks to skip (e.g., ["IOT", "Management"])
- **log_level**: DEBUG, INFO, WARNING, ERROR
- **force_sync**: Force update all networks (default: false)

## How It Works

1. **Authenticates** with UniFi controller
2. **Retrieves** all wireless network configurations
3. **Detects changes** using password hashes
4. **Updates QR codes** via QRWiFi API
5. **Maintains mappings** between UniFi networks and QR codes
6. **Logs activity** and handles errors gracefully

## Files

- `unifi_qr_monitor.py` - Main monitoring script
- `monitor_config.json` - Configuration file
- `network_qr_mapping.json` - UniFi network ID → QR ID mappings
- `network_state.json` - Network state tracking for change detection
- `requirements.txt` - Python dependencies

## Features

### Smart Network Mapping
- Uses UniFi network IDs for stable tracking
- Survives WiFi name changes
- Automatic QR code recovery if entries are deleted

### Change Detection
- Monitors passwords, names, security settings
- Only updates QR codes when changes detected
- Efficient hash-based comparison

### Error Handling
- Auto-reconnection to UniFi controller
- Missing QR code recreation
- Comprehensive logging for troubleshooting

## Requirements

- Python 3.6+
- UniFi Controller with admin access
- QRWiFi server with API access
- Network connectivity between all systems

## Troubleshooting

**Authentication Issues:**
- Verify UniFi credentials and permissions
- Check UniFi controller URL and port

**Missing Passwords:**
- Ensure UniFi user has admin/full access
- Check UniFi API field names haven't changed

**QR Codes Not Updating:**
- Verify QRWiFi API URL and key
- Check network connectivity to QR server
- Review logs for API errors

## License

Created for personal/internal use. Modify as needed.