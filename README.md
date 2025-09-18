# UniFi QR Code Monitor

Comprehensive monitoring system for UniFi controllers with WiFi QR code management, metrics collection, and web-based control interface.

Automatically QR codes via API. (https://github.com/zitlem/QR-WIFI)

## Features

- 🔍 **Scheduled monitoring** of UniFi wireless networks with configurable cron expressions
- 🔐 **Automatic password sync** when WiFi passwords change
- 🏷️ **Smart name change handling** using stable network IDs
- 🔄 **Auto-recovery** recreates missing QR codes
- ⚡ **Efficient updates** only processes changed networks
- 🛡️ **Secure** - passwords never stored locally, only hashed for change detection
- 📊 **Metrics collection** - WAN throughput and client usage data
- 💾 **InfluxDB integration** for time-series data storage
- 🌐 **Web interface** with manual triggers and real-time countdown timers
- 🐛 **Configurable debug system** with multiple logging levels
- 🔒 **IP whitelisting** for secure API access

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

## Web Interface

Access the web control panel at `http://your-server-ip:80` (configurable port)

### Features:
- **Real-time countdown timers** for scheduled tasks
- **Manual trigger buttons** for WiFi sync, WAN metrics, and client metrics
- **Debug controls** with live logging level adjustment
- **API endpoints** with usage examples
- **IP whitelisting** for secure access

### API Endpoints:
- `GET /api/schedules` - Get countdown timers for scheduled tasks
- `POST /api/trigger/wifi-sync` - Manually trigger WiFi network sync
- `POST /api/trigger/wan-metrics` - Manually collect WAN metrics
- `POST /api/trigger/client-metrics` - Manually collect client metrics
- `GET /api/debug-status` - Get current debug settings
- `POST /api/debug-level` - Change debug level (body: `{"level": "DEBUG"}`)

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

### Scheduling Settings
Configure cron expressions for automated tasks:
- **unifi_wifi_schedule**: WiFi network monitoring (supports day-specific intervals)
- **unifi_wan_throughput_schedule**: WAN metrics collection
- **unifi_client_usage_schedule**: Client usage tracking

Example schedule configuration:
```json
"schedules": {
  "unifi_wifi_schedule": {
    "enabled": true,
    "cron_expressions": [
      "*/30 * * * 0",  // Every 30 minutes on Sunday
      "0 * * * 1",     // Every hour on Monday
      "0 * * * 2"      // Every hour on Tuesday
    ]
  }
}
```

### Monitor Settings
- **networks_to_ignore**: WiFi networks to skip (e.g., ["IOT", "Management"])
- **log_level**: DEBUG, INFO, WARNING, ERROR, CRITICAL
- **force_sync**: Force update all networks (default: false)

### Debug Settings
- **level**: SILENT, MINIMAL, NORMAL, VERBOSE, FULL
- **enable_api_debug**: Enable API call debugging
- **enable_schedule_debug**: Enable scheduler debugging
- **log_successful_operations**: Log successful operations
- **quiet_mode**: Suppress non-critical output

### InfluxDB Settings
- **enabled**: Enable InfluxDB data storage
- **url**: InfluxDB server URL
- **token**: InfluxDB access token
- **org**: InfluxDB organization
- **bucket**: InfluxDB bucket name

### Web Interface Settings
- **enabled**: Enable web interface auto-start
- **port**: Web server port (default: 80)
- **allowed_ips**: IP whitelist with CIDR support
- **allow_all_for_dashboard**: Allow unrestricted dashboard access

## How It Works

### Core Functionality
1. **Authenticates** with UniFi controller
2. **Retrieves** all wireless network configurations
3. **Detects changes** using password hashes
4. **Updates QR codes** via QRWiFi API
5. **Maintains mappings** between UniFi networks and QR codes
6. **Collects metrics** (WAN throughput, client usage)
7. **Stores data** in InfluxDB for analysis
8. **Provides web interface** for manual control and monitoring

### Scheduling System
- **Cron-based scheduling** with support for both 5-part and 6-part expressions
- **Day-specific intervals** (e.g., every 30 minutes on Sunday only)
- **Real-time countdown timers** showing time until next execution
- **Threaded execution** for non-blocking operation

## Files

- `unifi_qr_monitor.py` - Main monitoring script with web interface
- `monitor_config.json` - Comprehensive configuration file
- `network_qr_mapping.json` - UniFi network ID → QR ID mappings
- `network_state.json` - Network state tracking for change detection
- `requirements.txt` - Python dependencies
- `grafana.json` - Grafana dashboard configuration for metrics visualization

## Advanced Features

### Smart Network Mapping
- Uses UniFi network IDs for stable tracking
- Survives WiFi name changes
- Automatic QR code recovery if entries are deleted

### Change Detection
- Monitors passwords, names, security settings
- Only updates QR codes when changes detected
- Efficient hash-based comparison

### Metrics Collection
- **WAN throughput monitoring** - Tracks upload/download speeds
- **Client usage tracking** - Monitors connected devices and data usage
- **InfluxDB integration** - Time-series data storage for analysis
- **Grafana dashboard** - Pre-configured visualization panels

### Error Handling & Debugging
- Auto-reconnection to UniFi controller
- Missing QR code recreation
- **Multi-level debug system** with category-specific controls
- Comprehensive logging for troubleshooting
- **Live debug adjustment** via web interface

### Security
- **IP whitelisting** with CIDR notation support
- **Secure API endpoints** with authentication
- **Password protection** - credentials never stored in plaintext

## Requirements

- Python 3.6+
- UniFi Controller with admin access
- QRWiFi server with API access
- InfluxDB server (optional, for metrics storage)
- Network connectivity between all systems

## Installation

1. **Clone the repository:**
   ```bash
   git clone https://github.com/yourusername/Unifi2QR-API.git
   cd Unifi2QR-API
   ```

2. **Install Python dependencies:**
   ```bash
   pip install -r requirements.txt
   ```

3. **Configure settings:**
   Copy and edit `monitor_config.json` with your specific settings

4. **Run the monitor:**
   ```bash
   python unifi_qr_monitor.py
   ```

The web interface will be available at `http://your-server-ip:80` (if enabled in config).

## Troubleshooting

**Authentication Issues:**
- Verify UniFi credentials and permissions
- Check UniFi controller URL and port
- Ensure firewall allows connections

**Missing Passwords:**
- Ensure UniFi user has admin/full access
- Check UniFi API field names haven't changed

**QR Codes Not Updating:**
- Verify QRWiFi API URL and key
- Check network connectivity to QR server
- Review logs for API errors

**Web Interface Issues:**
- Check IP whitelist configuration
- Verify port is not blocked by firewall
- Review web interface logs in debug mode

**Metrics Collection Problems:**
- Verify InfluxDB connection settings
- Check InfluxDB token permissions
- Enable debug logging for detailed error messages

**Schedule Not Running:**
- Verify cron expressions are valid
- Check if schedules are enabled in config
- Review scheduler debug logs

## License

Created for personal/internal use. Modify as needed.