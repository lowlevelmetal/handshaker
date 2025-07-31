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

stop_sniffer = False
stop_channel_cycle = False
log_lock = threading.Lock()
channel_cycle_lock = threading.Lock()
logs = deque(maxlen=500) 
networks = {} 

def log(msg):
    with log_lock:
        ts = datetime.now().strftime('%H:%M:%S')
        logs.append(f'[{ts}] {msg}')
def is_unicast(mac):
    """Check if MAC address is unicast (not broadcast/multicast)."""
    if not mac:
        return False
    first_octet = int(mac.split(':')[0], 16)
    return (first_octet & 1) == 0

def packet_handler(pkt):
    # Identify APs (Beacon or Probe Response)
    if pkt.haslayer(Dot11Beacon) or pkt.haslayer(Dot11ProbeResp):
        bssid = pkt[Dot11].addr2
        ssid = '<Hidden SSID>' 
        ssid_raw = pkt[Dot11Elt].info
        if ssid_raw:
            ssid = pkt[Dot11Elt].info.decode(errors="ignore")
        if bssid not in networks:
            networks[bssid] = {'ssid': ssid, 'clients': set()}
            log(f"[+] New AP: {ssid} ({bssid})")

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
                log(f"[+] Client {addr1} associated with {bssid} ({networks[bssid]['ssid']})")
            if is_unicast(addr2) and addr2 != bssid and addr2 not in networks[bssid]['clients']:
                networks[bssid]['clients'].add(addr2)
                log(f"[+] Client {addr2} associated with {bssid} ({networks[bssid]['ssid']})")

def sniffer_thread(args):
    sniff(iface=args.interface, prn=packet_handler, store=0,
          stop_filter=lambda pkt: stop_sniffer)

def set_channel(chan, interface):
    subprocess.run(['iw', 'dev', interface, 'set', 'channel', str(chan)])
    log(f"Channel set to {chan}")

def channel_thread(interface):
    i = 1

    while True:
        if i > 11:
            i = 1

        with channel_cycle_lock:
            if stop_channel_cycle:
                break
        
        set_channel(i, interface)

        time.sleep(2)
        i = i + 1

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

class NcursesUI:
    def __init__(self, args):
        self.args = args
        self.running = True
        self.log_offset = 0

    def draw(self, stdscr):
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
        title = "handshaker - Up/Dn=select AP  Enter=deauth  PgUp/PgDn=scroll log  q=quit"
        stdscr.addnstr(0, 0, title[:maxx].ljust(maxx), maxx, curses.A_REVERSE)

        # Print logs headers 
        log_pos = panel_h
        stdscr.hline(log_pos, 0, "-", maxx)
        log_pos += 1
        stdscr.addnstr(log_pos, 0, "Event Log".ljust(maxx), maxx, curses.A_BOLD)
        log_pos += 1
        
        # Print logs
        with log_lock:
            if len(logs) > 0:
                max_log_size = maxy - log_pos - 1
                for idx, logitem in enumerate(list(logs)[-max_log_size:]):
                    logitem = logitem.replace('\x00', '')
                    stdscr.addnstr(log_pos + idx, 0, logitem.ljust(maxx), maxx)

    
    def run(self, stdscr):
        curses.curs_set(0)
        stdscr.timeout(250)
        while self.running:
            self.draw(stdscr)
            ch = stdscr.getch()
            if ch == -1:
                continue
            if ch in (ord('q'), ord('Q')):
                self.running = False
                break


def main():
    global stop_sniffer
    global stop_channel_cycle

    args = parse_args()

    euid = os.geteuid()
    if euid != 0:
        print('Root required')
        sys.exit(1)

    log(f'Initializing handshaker on interface {args.interface}')
   
    # Start packet sniffer
    tsniffer = threading.Thread(target=sniffer_thread, args=(args,))
    tsniffer.start()

    tchancycle = threading.Thread(target=channel_thread, args=(args.interface,))
    tchancycle.start()

    # Create UI
    ui = NcursesUI(args)

    try:
        curses.wrapper(ui.run)
    except KeyboardInterrupt:
        pass
    finally:
        log('Exiting...')

    stop_channel_cycle = True
    stop_sniffer = True
    tsniffer.join()
    tchancycle.join()

if __name__ == '__main__':
    main()
