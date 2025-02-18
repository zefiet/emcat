#!/usr/bin/env python3
"""
common.py - Shared functions for cat and dump applications.
"""

import sys
import signal
import logging
from pubsub import pub

# Try to import the M-PWRD serial interface (the package is still named meshtastic)
try:
    import meshtastic.serial_interface as ms
except ImportError as e:
    logging.error("Meshtastic library not found. Please install it with 'pip install meshtastic'.")
    sys.exit(1)

def setup_logging(verbose=0):
    """
    Configures logging based on the verbosity level.
    """
    logging.basicConfig(
        stream=sys.stderr,
        level=logging.INFO,  # Default level
        format='[%(levelname)s] %(message)s'
    )
    if verbose == 0:
        logging.getLogger().setLevel(logging.WARNING)
    elif verbose == 1:
        logging.getLogger().setLevel(logging.INFO)
    else:
        logging.getLogger().setLevel(logging.DEBUG)

def sigint_handler(sig, frame):
    """
    Signal handler for SIGINT (Ctrl+C) to exit cleanly.
    """
    logging.info("KeyboardInterrupt received. Exiting the program.")
    sys.exit(0)

signal.signal(signal.SIGINT, sigint_handler)

def send_heartbeat(interface):
    """
    Sends a heartbeat if the interface supports it (e.g., in serial mode).
    """
    if hasattr(interface, 'stream'):
        logging.info("Sending heartbeat...")
        interface.sendHeartbeat()
        logging.info("Heartbeat sent.")
    else:
        logging.warning("Skipping heartbeat because 'stream' attribute is missing (likely TCP mode).")

def connect_device(serial_port=None, verbose=0):
    """
    Establishes a connection to the M-PWRD device.
    If a serial port is provided, it is used; otherwise, default detection is used.
    After a successful connection, a heartbeat is sent if supported.
    """
    try:
        port_info = serial_port if serial_port else "default detection"
        logging.info(f"Attempting to connect to the M-PWRD device (Serial Port: {port_info})...")
        debug_output = sys.stdout if verbose >= 3 else None
        interface = ms.SerialInterface(devPath=serial_port, debugOut=debug_output)
        logging.info("Successfully connected to the M-PWRD device.")
        send_heartbeat(interface)
        return interface
    except Exception as e:
        logging.error(f"Failed to connect to the M-PWRD device: {e}")
        sys.exit(1)

# New functions to convert addresses

def int_to_mpwr_addr(addr_int: int) -> str:
    """
    Converts an integer address to the M-PWRD address format.
    Example: 3175869220 -> "!bd4beb24"
    """
    return "!" + format(addr_int, '08x')

def mpwr_addr_to_int(addr_str: str) -> int:
    """
    Converts an M-PWRD address (e.g., "!bd4beb24") to an integer.
    """
    if addr_str.startswith("!"):
        addr_str = addr_str[1:]
    return int(addr_str, 16)