# Passive Wireless Reconnaissance Payloads

A collection of passive reconnaissance tools for the WiFi Pineapple Pager designed to monitor, detect, and analyze the wireless environment without transmitting. These payloads identify potential attack vectors, rogue devices, and environmental anomalies using official DuckyScript and Bash.

## Quick Start

1. Navigate to the **User** menu on the WiFi Pineapple Pager.
2. Select **Reconnaissance**.
3. Choose the desired payload and press the button to launch.
4. Follow on-screen prompts (e.g., `NUMBER_PICKER`) to configure scan duration.
5. Review live logs on the screen and artifacts in `/tmp/` upon completion.

## Payloads

| Payload | Purpose | Key Alerts |
|---------|---------|------------|
| `rogue-twin-radar` | Detects potential evil twin access points. | New BSSID for known SSID, security downgrade, RSSI anomaly. |
| `beacon-anomaly-watch` | Monitors RF environment for sudden spikes or floods. | SSID spikes, BSSID floods, beacon rate anomalies. |
| `wps-beacon-flagger` | Identifies APs with WPS enabled. | WPS v1.0/v2.0 detection, Lock status. |
| `enterprise-beacon-finder` | Flags WPA2/WPA3-Enterprise networks. | 802.1X/EAP authentication detection. |
| `ot-oui-scout` | Scans for industrial (ICS/OT) hardware by MAC OUI. | Detection of Rockwell, Siemens, Schneider, and other OT vendors. |
| `probe-whisperer` | Captures client probe requests for sensitive SSIDs. | Corporate, internal, or custom SSID patterns found. |
| `hidden-ssid-counter` | Tracks hidden networks and attempts to reveal them. | New hidden BSSID, SSID reveal via client association. |
| `p2p-hotspot-spotter` | Detects mobile hotspots and WiFi Direct devices. | iPhone/Android hotspots, Chromecast, WiFi-Direct P2P. |
| `channel-heatmap` | Visualizes channel congestion with ASCII charts. | Summary report of clearest vs most congested channels. |
| `recon-dashboard` | Unified live view of all passive recon modules. | Multi-vector alerts (Twins, Hidden, Probes, etc.). |

### Detection Payloads

*   **rogue-twin-radar**: Passively monitors for evil twin attacks by alerting when an existing SSID appears with a new MAC address or lower security settings.
*   **beacon-anomaly-watch**: Establishes an RF baseline and triggers an alarm if there is a sudden influx of new SSIDs or beacons, indicating a potential spoofing attack.
*   **wps-beacon-flagger**: Scans beacons for WPS Information Elements to identify access points vulnerable to PIN or PBC attacks.
*   **enterprise-beacon-finder**: Locates WPA2/WPA3-Enterprise networks which may be targets for credential harvesting or RADIUS-based attacks.
*   **ot-oui-scout**: Uses a specialized OUI database to find industrial controllers, PLCs, and SCADA gateways communicating over wireless.

### Monitoring Payloads

*   **probe-whisperer**: Listens for probe requests from nearby devices to identify the SSIDs they are searching for, helping map out corporate or home networks.
*   **hidden-ssid-counter**: Detects the presence of hidden networks and monitors for client associations that reveal the SSID in cleartext.
*   **p2p-hotspot-spotter**: Flags mobile hotspots and Peer-to-Peer networks (WiFi Direct) that often lack the security controls of enterprise infrastructure.

### Analysis Payloads

*   **channel-heatmap**: Scans the 2.4 GHz and 5 GHz bands to produce a visual ASCII heatmap showing channel occupancy and signal distribution.
*   **recon-dashboard**: A comprehensive monitor that runs multiple detection engines simultaneously, providing a live-updating dashboard on the Pager display.

## LED Reference

| State | Meaning | Payloads |
|-------|---------|----------|
| Blue Slow Blink | Monitoring / Scanning | `probe-whisperer`, `hidden-ssid-counter`, `p2p-hotspot-spotter`, `enterprise-finder` |
| Cyan Slow Blink | Monitoring | `rogue-twin-radar` |
| Amber Slow Blink | Scanning / Baseline | `wps-beacon-flagger`, `beacon-anomaly-watch` |
| Magenta Slow Blink | Monitoring | `ot-oui-scout` |
| Blue Pulse | Active Dashboard | `recon-dashboard` |
| Red Double Blink | Evil Twin Detected | `rogue-twin-radar` |
| Red Fast Blink | Anomaly Detected | `beacon-anomaly-watch` |
| Yellow Double Blink | WPS AP Found | `wps-beacon-flagger` |
| Cyan Flash | Hotspot / Interesting SSID | `p2p-hotspot-spotter`, `probe-whisperer`, `recon-dashboard` |
| Yellow Flash | P2P Device / SSID Revealed | `p2p-hotspot-spotter`, `hidden-ssid-counter` |
| Magenta Flash | Hidden / OT Detected | `hidden-ssid-counter`, `ot-oui-scout` |
| Blue Solid Flash | Enterprise Found | `enterprise-beacon-finder` |
| Green Solid | Task Complete | All |

## Configuration

Most payloads use the following common variables which can be adjusted in the `payload.sh` file:

*   `MONITOR_DURATION`: Total run time in seconds (Default: 300)
*   `ARTIFACTS_DIR`: Path where logs and reports are saved (Default: `/tmp/<payload-name>`)
*   `SCAN_INTERVAL`: Seconds between individual scan cycles (Default: 10)

## Integration

These payloads are designed to work standalone or as part of the **Red Team Toolkit v2.4**. When a reconnaissance payload identifies a target, the information is logged to `/tmp/`, allowing other payloads to ingest the BSSID or SSID for automated follow-up actions like handshake capture or evil twin deployment.

Detections also trigger system alerts using the `ALERT` command, ensuring they are captured in the Pager's global notification history.
