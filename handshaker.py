#!/usr/bin/env python3

import argparse
import threading
import curses
import os
import sys
import subprocess
import time
from datetime import datetime
from collections import deque
from dataclasses import dataclass, field
from scapy.all import *

ui = None 
stop_sniffer = False
stop_channel_cycle = False
channel_cycle_lock = threading.Lock()
channel = 0
networks = {} 

def is_unicast(mac):
    """Check if MAC address is unicast (not broadcast/multicast)."""
    if not mac:
        return False
    first_octet = int(mac.split(':')[0], 16)
    return (first_octet & 1) == 0

def packet_handler(pkt):
    global ui
    global networks

    # Identify APs (Beacon or Probe Response)
    if pkt.haslayer(Dot11Beacon) or pkt.haslayer(Dot11ProbeResp):
        bssid = pkt[Dot11].addr2
        ssid = None 
        ssid_raw = pkt[Dot11Elt].info
        if ssid_raw:
            ssid = pkt[Dot11Elt].info.decode(errors="ignore")
        if bssid not in networks and ssid is not None:
            networks[bssid] = {'ssid': ssid, 'clients': set()}
            ui.log(f"[+] New AP: {ssid} ({bssid})")
        if bssid in networks:
            if 'channels' in networks[bssid]:
                networks[bssid]['channels'].add(get_channel())
            else:
                networks[bssid]['channels'] = {get_channel()}
        if pkt.haslayer(RadioTap):
            pwr = pkt[RadioTap].dBm_AntSignal
            if bssid in networks:
                networks[bssid]['pwr'] = pwr
            

    # Identify data packets (potential clients)
    if pkt.haslayer(Dot11):
        addr1 = pkt[Dot11].addr1  # Destination
        addr2 = pkt[Dot11].addr2  # Source
        bssid = None

        # Try to identify BSSID (AP MAC)
        if pkt.type == 2:  # Data frame
            to_ds = pkt.FCfield & 0x1 != 0
            from_ds = pkt.FCfield & 0x2 != 0
            if not to_ds and not from_ds:  # STA <-> AP
                bssid = pkt[Dot11].addr3
            elif to_ds and not from_ds:  # STA -> DS
                bssid = pkt[Dot11].addr1
            elif not to_ds and from_ds:  # DS -> STA
                bssid = pkt[Dot11].addr2

        if bssid and bssid in networks:
            # addr1/addr2 may be a client MAC
            if is_unicast(addr1) and addr1 != bssid and addr1 not in networks[bssid]['clients']:
                networks[bssid]['clients'].add(addr1)
                ui.log(f"[+] Client {addr1} associated with {bssid} ({networks[bssid]['ssid']})")
            if is_unicast(addr2) and addr2 != bssid and addr2 not in networks[bssid]['clients']:
                networks[bssid]['clients'].add(addr2)
                ui.log(f"[+] Client {addr2} associated with {bssid} ({networks[bssid]['ssid']})")

def sniffer_thread(args):
    sniff(iface=args.interface, prn=packet_handler, store=0,
          stop_filter=lambda pkt: stop_sniffer)

def set_channel(chan, interface):
    global ui
    subprocess.run(['iw', 'dev', interface, 'set', 'channel', str(chan)])
    ui.log(f"Channel set to {chan}")

def get_channel():
    global channel
    global channel_cycle_lock
    with channel_cycle_lock:
        return channel

def channel_thread(interface):
    global channel
    global channel_cycle_lock
    channel = 1

    while True:
        with channel_cycle_lock:
            channel += 1
            if channel > 11:
                channel = 1
            if stop_channel_cycle:
                break
            set_channel(channel, interface)

        time.sleep(2)
        

def parse_args():
    parser = argparse.ArgumentParser(
        description='Capture WPA handshakes and manage Wi-Fi clients (with optional deauth).'
    )
    parser.add_argument('-i', '--interface', required=True, help='Wireless interface in monitor mode')
    parser.add_argument('-c', '--channel', type=int, help='Channel to scan')
    parser.add_argument('-s', '--target-ssid', help='Filter by SSID')
    parser.add_argument('-b', '--target-bssid', help='Filter by BSSID')
    parser.add_argument('-w', '--write-directory', help='Directory for .cap files (no output if not set)')
    parser.add_argument('-t', '--timeout', type=int, default=60, help='Client timeout (seconds)')
    parser.add_argument('-d', '--deauth', action='store_true', help='Enable deauthentication')
    parser.add_argument('--interval', type=int, default=10, help='Deauth burst interval (seconds)')
    return parser.parse_args()

def clamp(value, min_value, max_value):
    return max(min_value, min(value, max_value))

class NcursesUI:
    def __init__(self, args):
        self.args = args
        self.running = True
        self.log_offset = 0
        self.selected_ap = 0
        self.logs = deque(maxlen=250)
        self.log_lock = threading.Lock()

    def log(self, msg):
        ts = datetime.now().strftime('%H:%M:%S')
        fmsg = f"[{ts}] {msg}"
        with self.log_lock:
            self.logs.append(fmsg)
        
        if self.log_offset != 0:
            self.log_offset += 1

    def draw(self, stdscr):
        global networks

        stdscr.clear()
        maxy, maxx = stdscr.getmaxyx()
        panel_h = maxy//2 - 1

        # Determine if terminal is not large enough, if so try to exit gracefully.
        if maxy < 6 or maxx < 40:
            try:
                stdscr.addstr(0, 0, "Terminal too small", curses.A_REVERSE)
            except curses.error:
                pass
            stdscr.refresh()
            return

        # Print title
        title = "handshaker - Up/Dn=select AP  Enter=deauth  PgUp/PgDn=scroll log  space=go to log top  q=quit"
        stdscr.addnstr(0, 0, title[:maxx].ljust(maxx), maxx, curses.A_REVERSE)
        stdscr.addnstr(1, 0, f"Access Points".ljust(maxx), maxx, curses.A_BOLD)

        # Print access points
        max_ap_size = panel_h - 3
        down_scroll = max(0, self.selected_ap - max_ap_size)
        for i, (bssid, ap) in enumerate(networks.items()):
            if i - down_scroll > max_ap_size:
                break;
            if i < down_scroll:
                continue
            ssid = ap.get('ssid', '<hidden>').ljust(34)
            pwr = (str(ap.get('pwr', 'NoSignal')) + "dBm").ljust(12)
            channels = ",".join(str(chan) for chan in ap['channels']).ljust(12)
            line = f"{ssid} {pwr} [{bssid}] {channels}"
            stdscr.addnstr(2 + i - down_scroll, 0, line.replace('\x00', '').ljust(maxx), maxx, curses.A_REVERSE if i == self.selected_ap else 0)

        # Print log header
        total_logs = len(self.logs)
        total_log_str = f"Log Offset: {self.log_offset} | Total Log: {total_logs}"
        total_log_strlen = len(total_log_str)
        log_title_str = "Event Logs".ljust(maxx-total_log_strlen)+total_log_str
        log_pos = panel_h
        stdscr.hline(log_pos, 0, "-", maxx)
        log_pos += 1
        stdscr.addnstr(log_pos, 0, log_title_str, maxx, curses.A_BOLD)
        log_pos += 1

        # Print logs
        with self.log_lock:
            # Print logs only if necessary
            if total_logs > 0:
                # Max log size can only be remaining screen real estate
                max_log_size = maxy - log_pos - 1

                # Maximum scroll will always be zero if total_logs
                # can't fill/overflow screen.
                max_offset = max(0, total_logs - max_log_size)
                
                self.log_offset = min(max_offset, max(0, self.log_offset))
                end = total_logs - self.log_offset
                start = max(0, end - max_log_size)
                for idx, logitem in enumerate(list(self.logs)[start:end]):
                    logitem = logitem.replace('\x00', '')
                    try:
                        stdscr.addnstr(log_pos + idx, 0, logitem.ljust(maxx), maxx)
                    except Exception:
                        # Fallback in case of encoding issues
                        stdscr.addnstr(log_pos + idx, 0, logitem.encode('utf-8', errors='replace').decode('utf-8').ljust(maxx), maxx)

    
    def run(self, stdscr):
        curses.curs_set(0)
        stdscr.timeout(250)
        while self.running:
            self.draw(stdscr)
            ch = stdscr.getch()
            if ch == -1:
                continue
            elif ch in (ord('q'), ord('Q')):
                self.running = False
                break
            elif ch == curses.KEY_PPAGE:
                self.log_offset = min(500, self.log_offset + 1)
            elif ch == curses.KEY_NPAGE:
                self.log_offset = max(0, self.log_offset - 1) 
            elif ch in (curses.KEY_UP, ord('k')):
                self.selected_ap = max(0, self.selected_ap - 1) 
            elif ch in (curses.KEY_DOWN, ord('j')):
                self.selected_ap = min(self.selected_ap + 1, len(networks) - 1) 
            elif ch == ord(' '):
                self.log_offset = 0


def main():
    global stop_sniffer
    global stop_channel_cycle
    global ui
    global channel

    args = parse_args()

    euid = os.geteuid()
    if euid != 0:
        print('Root required')
        sys.exit(1)

    ui = NcursesUI(args)
    ui.log(f'Initializing handshaker on interface {args.interface}')
   
    # Start packet sniffer
    tsniffer = threading.Thread(target=sniffer_thread, args=(args,))
    tsniffer.start()

    if args.channel is None:
        tchancycle = threading.Thread(target=channel_thread, args=(args.interface,))
        tchancycle.start()
    else:
        channel = args.channel 
        set_channel(clamp(channel, 1, 11), args.interface)

    try:
        curses.wrapper(ui.run)
    except KeyboardInterrupt:
        pass
    finally:
        ui.log('Exiting...')

    stop_channel_cycle = True
    stop_sniffer = True
    tsniffer.join()
    tchancycle.join()

if __name__ == '__main__':
    main()
