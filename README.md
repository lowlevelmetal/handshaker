# handshaker

**Wi-Fi 802.11 Handshake Sniffer and Deauth Tool**

---

## NAME

**handshaker** — Capture WPA handshakes, manage client lists, and optionally deauthenticate Wi-Fi clients

---

## SYNOPSIS

```shell
handshaker --interface <iface> [options]
````

---

## DESCRIPTION

**handshaker** is a Python-based tool for monitoring Wi-Fi networks, capturing WPA/WPA2 handshakes, and optionally performing client deauthentication attacks to trigger handshake collection.
It maintains a real-time list of Wi-Fi networks (APs) and their associated clients, updating a terminal UI.
You can filter by SSID or BSSID, capture handshake traffic, and optionally perform deauth at a configurable interval.
All 802.11 traffic can be optionally saved for later analysis.

The UI:

* **Top half:** Shows a scrollable list of detected APs and their connected clients.
* **Bottom half:** Shows a scrollable event log.

If a handshake (EAPOL packet) is captured for an AP, `[EAPOL]` is displayed next to that AP in the UI.

---

## OPTIONS

* `-i`, `--interface <interface>`
  *(Required)* Wireless interface to use for monitoring (must be in monitor mode).

* `-c`, `--channel <channel>`
  Channel to scan/capture on. If not specified, cycles through all available channels.

* `-s`, `--target-ssid <ssid>`
  Filter capture to a specific network SSID.

* `-b`, `--target-bssid <bssid>`
  Filter capture to a specific network BSSID (MAC address).

* `-t`, `--timeout <seconds>`
  Timeout (in seconds) after which clients are removed from the active list if no packets are seen.
  Default: 60

* `-d`, `--deauth`
  Enable deauthentication of detected clients (for handshake capture/testing).

* `--interval <seconds>`
  Interval (in seconds) between deauth bursts.
  Default: 10

* `--output-directory <dir>`
  Directory in which to store captured traffic files (e.g., handshakes).
  If not set, no cap files are written.

---

## USAGE & BEHAVIOR

* With only `--interface`, scans all channels and networks, displaying all detected APs and associated clients.
* When filtering with `--target-ssid` or `--target-bssid`, only packets from the specified network(s) are processed.
* Handshake packets (EAPOL) are detected and logged. If any handshake traffic is captured for an AP, `[EAPOL]` is shown next to that AP in the UI.
* Captured packets are saved as `<SSID>_capture.cap` in the output directory (if specified).
* When deauth is enabled, clients are periodically deauthenticated to trigger handshakes.
* Clients disappear from the UI after the specified timeout unless new packets are seen.

---

## UI CONTROLS

* **Up/Down**: Move selection in AP list
* **Enter**: When on an AP, prompts for output directory and enables deauth/handshake collection for that AP/channel.
* **PgUp/PgDn**: Scroll the event log
* **q**: Quit

---

## EXAMPLES

Scan all networks on all channels:

```shell
handshaker -i wlan0
```

Capture handshakes for a specific SSID, saving files to `./captures`:

```shell
handshaker -i wlan0 -s "MyWiFi" --output-directory ./captures
```

Perform deauth attacks every 5 seconds on a specific BSSID:

```shell
handshaker -i wlan0 -b 00:11:22:33:44:55 -d --interval 5
```

Monitor a single channel and set a custom timeout:

```shell
handshaker -i wlan0 -c 6 -t 120
```

---

## REQUIREMENTS

* **Root privileges** are typically required.
* Wireless interface **must support monitor mode**.
* **Python 3.7+**
* `scapy`
* `curses` (standard with Python)
* Linux with `iwconfig` for channel setting
* libpcap and permissions for raw packet capture

---

## NOTES

* The `[EAPOL]` marker is shown next to an AP as soon as any handshake packet is captured for that BSSID—matching what tools like airodump-ng or aircrack-ng do.
* This tool does not guarantee that a *full* 4-way handshake is present; it shows `[EAPOL]` as soon as aircrack-ng would show "handshake detected."
* For reliable operation, ensure your interface is in monitor mode and no network manager is interfering.

---

## LEGAL NOTICE

**For authorized network testing and research only.**
Deauthentication attacks and handshake capture may be illegal or disruptive on networks you do not own or have explicit permission to test.

---

## LICENSE

MIT

---

## AUTHOR

lowlevelmetal, 2025

---
