#!/usr/bin/env python3
"""
emdump - A tool that connects to an M-PWRD device and prints all received packets,
similar to tcpdump.
"""

import argparse
import sys
import time
import logging
from datetime import datetime

from pubsub import pub
from emcat.common import connect_device, setup_logging, send_heartbeat, int_to_mpwr_addr

def on_receive(packet, interface):
    """
    Callback executed when a packet is received.
    The packet is printed in a tcpdump-like format to stdout.
    """
    logging.info("*** FNORD!!!! ****")
    timestamp = datetime.now().strftime('%y-%m-%d %H:%M:%S')
    # Retrieve addresses
    source = packet.get("from", "unknown")
    destination = packet.get("to", "unknown")
    
    # If addresses are integers, convert them to M-PWRD format
    if isinstance(source, int):
        source = int_to_mpwr_addr(source)
    if isinstance(destination, int):
        destination = int_to_mpwr_addr(destination)
    
    decoded = packet.get("decoded", {})
    portnum = decoded.get("portnum", "N/A")
    payload = decoded.get("payload", "")
    print(f"[{timestamp}] {source} -> {destination} | PORT: {portnum} | PAYLOAD: {payload}")

def run_dump(serial_port=None, verbose=0):
    """
    Connects to the M-PWRD device and starts dump mode,
    printing all received packets to stdout.
    """
    interface = connect_device(serial_port, verbose)
    # Directly subscribe to the event as in cat.py
    pub.subscribe(on_receive, "meshtastic.receive")
    logging.info("Dump mode started. Waiting for incoming packets (Ctrl+C to exit).")
    
    # Main loop: periodically send heartbeats to keep the connection active (if supported)
    while True:
        try:
            send_heartbeat(interface)
            time.sleep(1)
        except Exception as e:
            logging.error(f"Error in main loop: {e}")
            break

def main():
    parser = argparse.ArgumentParser(
        description="emdump - Dumps all received packets from an M-PWRD device (similar to tcpdump)."
    )
    parser.add_argument("--serial", type=str, default=None,
                        help="Optional: Serial port for accessing the M-PWRD device. "
                             "If not provided, default detection is used.")
    parser.add_argument("-v", "--verbose", action="count", default=0,
                        help="Increase verbosity (e.g., -vv for debug output).")
    args = parser.parse_args()

    setup_logging(args.verbose)
    run_dump(args.serial, args.verbose)

if __name__ == "__main__":
    main()