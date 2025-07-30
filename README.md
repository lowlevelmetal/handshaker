# handshaker(1) — Wi-Fi 802.11 Handshake Sniffer and Deauth Tool

**handshaker** — Capture WPA handshakes, manage client lists, and optionally deauthenticate Wi-Fi clients

---

## SYNOPSIS

```
handshaker --interface <iface> [options]
```

---

## DESCRIPTION

**handshaker** is a tool for monitoring Wi-Fi networks, capturing WPA/WPA2 handshakes, and optionally performing client deauthentication attacks for handshake collection and testing.

The tool maintains a list of Wi-Fi networks (APs) and their associated clients, updating the display in real time. It can filter by SSID or BSSID, capture 4-way handshakes, and optionally perform deauth attacks at a user-specified interval. All relevant 802.11 traffic can be saved for later analysis.

---

## OPTIONS

* **-i, --interface \<interface>**
  (Required) Wireless interface to use for monitoring (must be in monitor mode).

* **-c, --channel \<channel>**
  Channel to scan/capture on. If not specified, will cycle through all available channels.

* **-s, --target-ssid \<ssid>**
  Filter capture to a specific network SSID.

* **-b, --target-bssid \<bssid>**
  Filter capture to a specific network BSSID (MAC address).

* **-t, --timeout \<seconds>**
  Timeout (in seconds) after which clients are removed from the active list if no packets are seen.
  *Default:* 60

* **-d, --deauth**
  Enable deauthentication of detected clients (for handshake capture/testing).

* **--interval \<seconds>**
  Interval (in seconds) between deauth bursts.
  *Default:* 10

* **--output-directory \<dir>**
  Directory in which to store captured traffic files (e.g., handshakes).
  If not set, defaults to current working directory.

---

## BEHAVIOR

* With only `--interface`, scans all channels and networks, displaying all detected APs and associated clients.
* The top half of the UI shows a scrollable list of detected APs and their clients.
* The bottom half of the UI shows a scrollable log of events and actions.
* When filtering with `--target-ssid` or `--target-bssid`, only packets from the specified network(s) are processed.
* Handshake packets (EAPOL) are detected and logged. Captured packets are saved as `<SSID>_capture.cap` in the output directory.
* When deauth is enabled, clients are periodically deauthenticated to trigger handshakes.
* Clients disappear from the UI after the specified timeout unless new packets are seen from them.

---

## EXAMPLES

```sh
# Scan all networks on all channels
handshaker -i wlan0

# Capture handshakes for a specific SSID, saving files to ./captures
handshaker -i wlan0 -s "MyWiFi" --output-directory ./captures

# Perform deauth attacks every 5 seconds on a specific BSSID
handshaker -i wlan0 -b 00:11:22:33:44:55 -d --interval 5

# Monitor a single channel and set a custom timeout
handshaker -i wlan0 -c 6 -t 120
```

---

## REQUIREMENTS

* Root privileges are typically required.
* Wireless interface must support monitor mode.
* `libpcap`, `ncurses`, and other dependencies as per your build system.

---
