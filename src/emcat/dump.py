#!/usr/bin/env python3
"""
emdump - Dumps all received packets from an M-PWRD device (like tcpdump) or
reads an input PCAP file and outputs the captured packets.
When using the -i/--in parameter, no device connection is made.
"""

import argparse
import sys
import time
import logging
import struct
from datetime import datetime

import dpkt  # External library for reading/writing PCAP files
from pubsub import pub
from emcat.common import connect_device, setup_logging, send_heartbeat, int_to_mpwr_addr

# Global PCAP writer variable (used when capturing live; not used in input mode)
PCAP_WRITER = None

def mpwr_addr_to_int(addr):
    """
    Converts a Meshtastick address (either an integer or a string in the form "!xxxxxxxx")
    into a 4-byte integer.
    """
    if isinstance(addr, int):
        return addr
    elif isinstance(addr, str) and addr.startswith("!"):
        try:
            return int(addr[1:], 16)
        except Exception:
            return 0
    return 0

def meshtastic_to_custom(packet):
    """
    Transforms a Meshtastick packet into a custom encapsulated binary format.
    
    Custom header:
      - 4 bytes: source address (unsigned int, network byte order)
      - 4 bytes: destination address (unsigned int, network byte order)
      - 2 bytes: port string length (unsigned short, network byte order)
      - n bytes: port string (UTF-8 encoded)
    Followed by the decoded payload.
    """
    src = packet.get("from", 0)
    dst = packet.get("to", 0)
    src_int = mpwr_addr_to_int(src)
    dst_int = mpwr_addr_to_int(dst)
    
    header = struct.pack("!II", src_int, dst_int)
    
    decoded = packet.get("decoded", {})
    port = decoded.get("portnum", "")
    port_bytes = port.encode('utf-8') if isinstance(port, str) else b""
    port_len = len(port_bytes)
    port_header = struct.pack("!H", port_len)  # 2 bytes for port length
    
    payload = decoded.get("payload", b"")
    if not isinstance(payload, bytes):
        payload = str(payload).encode('utf-8')
    
    return header + port_header + port_bytes + payload

def parse_custom_frame(frame_bytes):
    """
    Parses a custom encapsulated frame (as written by meshtastic_to_custom) into a dictionary.
    The custom header consists of:
      - 4 bytes: source address
      - 4 bytes: destination address
      - 2 bytes: port string length
      - n bytes: port string
    The remainder is the payload.
    
    Returns a dict similar to a live packet:
      { "from": src, "to": dst, "decoded": {"portnum": port, "payload": payload} }
    """
    if len(frame_bytes) < 10:
        return None
    src, dst = struct.unpack("!II", frame_bytes[:8])
    port_len = struct.unpack("!H", frame_bytes[8:10])[0]
    if len(frame_bytes) < 10 + port_len:
        return None
    port_bytes = frame_bytes[10:10+port_len]
    port = port_bytes.decode('utf-8', errors='replace')
    payload = frame_bytes[10+port_len:]
    return {
        "from": src,
        "to": dst,
        "decoded": {"portnum": port, "payload": payload}
    }

def on_receive_display(packet, interface):
    """
    Callback executed when a packet is received.
    Prints the packet in a tcpdump-like format to stdout.
    """
    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    # Retrieve addresses and convert them if necessary
    source = packet.get("from", "unknown")
    destination = packet.get("to", "unknown")
    if isinstance(source, int):
        source = int_to_mpwr_addr(source)
    if isinstance(destination, int):
        destination = int_to_mpwr_addr(destination)
    
    decoded = packet.get("decoded", {})
    portnum = decoded.get("portnum", "N/A")
    payload = decoded.get("payload", "")
    print(f"[{timestamp}] {source} -> {destination} | PORT: {portnum} | PAYLOAD: {payload}")

def on_receive_pcap(packet, interface):
    """
    Callback executed when a packet is received live.
    Transforms the Meshtastick packet into our custom format and writes it to the PCAP file.
    """
    global PCAP_WRITER
    if PCAP_WRITER is None:
        return
    try:
        custom_frame = meshtastic_to_custom(packet)
        ts = datetime.now().timestamp()
        PCAP_WRITER.writepkt(custom_frame, ts=ts)
    except Exception as e:
        logging.error(f"Error writing packet to PCAP: {e}")

def run_live_dump(serial_port=None, verbose=0):
    """
    Connects to the M-PWRD device and starts dump mode,
    printing all received packets to stdout and optionally writing them to a PCAP file.
    """
    interface = connect_device(serial_port, verbose)
    # Always register the display callback
    pub.subscribe(on_receive_display, "meshtastic.receive")
    logging.info("Display output callback registered.")
    
    # Register the PCAP callback only if PCAP_WRITER is set
    if PCAP_WRITER is not None:
        pub.subscribe(on_receive_pcap, "meshtastic.receive")
        logging.info("PCAP output callback registered.")
    
    logging.info("Live dump mode started. Waiting for incoming packets (Ctrl+C to exit).")
    
    while True:
        try:
            send_heartbeat(interface)
            time.sleep(1)
        except Exception as e:
            logging.error(f"Error in main loop: {e}")
            break

def process_pcap_file(pcap_filename):
    """
    Reads a PCAP file (with custom encapsulation) and prints each packet using on_receive_display.
    """
    try:
        with open(pcap_filename, "rb") as f:
            pcap = dpkt.pcap.Reader(f)
            for ts, buf in pcap:
                packet = parse_custom_frame(buf)
                if packet:
                    # For display purposes, we ignore the interface parameter (set to None)
                    on_receive_display(packet, None)
    except Exception as e:
        logging.error(f"Error processing PCAP file: {e}")

def main():
    global PCAP_WRITER
    parser = argparse.ArgumentParser(
        description="emdump - Dumps all received packets from an M-PWRD device or reads an input PCAP file."
    )
    parser.add_argument("--serial", type=str, default=None,
                        help="Optional: Serial port for accessing the M-PWRD device. Ignored if --in is provided.")
    parser.add_argument("-v", "--verbose", action="count", default=0,
                        help="Increase verbosity (e.g., -vv for debug output).")
    parser.add_argument("-o", "--out", type=str, default=None,
                        help="Optional: Path to output PCAP file to save packets (only in live mode).")
    parser.add_argument("-i", "--in", dest="infile", type=str, default=None,
                        help="Optional: Path to input PCAP file to read and display captured packets.")
    args = parser.parse_args()

    setup_logging(args.verbose)
    
    # If an output file is specified, set up the PCAP writer (for live capture mode)
    if args.out:
        try:
            pcap_file = open(args.out, "wb")
            # Use custom link type DLT_USER0 (147) for our custom encapsulation.
            PCAP_WRITER = dpkt.pcap.Writer(pcap_file, linktype=147)
        except Exception as e:
            logging.error(f"Failed to open output file: {e}")
            sys.exit(1)
    
    if args.infile:
        # Process the input PCAP file and display packets
        process_pcap_file(args.infile)
    else:
        # Run live capture (device connection mode)
        run_live_dump(args.serial, args.verbose)

if __name__ == "__main__":
    main()