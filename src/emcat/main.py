#!/usr/bin/env python3
"""
emcat - A netcat-inspired CLI tool that uses the Meshtastic library to connect
to a Meshtastic device via serial. It lets you send and receive messages directly
between Meshtastic devices and enables communication between hosts using Meshtastic networks.

Note: This is a proof-of-concept and is not recommended for production use—in fact,
you might not want to use it at all. Reviews and pull requests are welcome.
"""

import argparse
import sys

def connect_device(serial_port=None, verbose=False):
    """
    Establish a connection to the Meshtastic device using the Meshtastic library.
    If a serial port is provided, it is used; otherwise, the default behavior of
    the Meshtastic client is applied.
    """
    try:
        import meshtastic.serial_interface as ms
        port_info = serial_port if serial_port else "default detection"
        if verbose:
            print(f"[INFO] Attempting to connect to the Meshtastic device (Serial Port: {port_info})...")
        # Use the correct parameter 'devPath' to specify the serial port
        interface = ms.SerialInterface(devPath=serial_port, debugOut=verbose)
        if verbose:
            print("[INFO] Successfully connected to the Meshtastic device.")
        return interface
    except Exception as e:
        print(f"[ERROR] Failed to connect to the Meshtastic device: {e}")
        sys.exit(1)

def run_client(client_id, serial_port=None, verbose=False):
    """
    Client mode: Establishes a connection to the Meshtastic device and targets
    a specific Meshtastic client ID. Later, implement the logic to send messages
    to the specified client.
    """
    interface = connect_device(serial_port, verbose)
    if verbose:
        print(f"[INFO] Client mode started. Target Meshtastic Client ID: {client_id}")
    print("Client mode: Meshtastic connection established. Data transmission not yet implemented.")

def run_server(serial_port=None, verbose=False):
    """
    Server mode: Establishes a connection to the Meshtastic device.
    In the future, implement logic to handle incoming messages.
    """
    interface = connect_device(serial_port, verbose)
    if verbose:
        print("[INFO] Server mode started.")
    print("Server mode: Meshtastic connection established. Data transmission not yet implemented.")

def main():
    parser = argparse.ArgumentParser(
        description="emcat - a netcat-inspired CLI tool using the Meshtastic library to connect to a Meshtastic device via serial."
    )
    # In client mode, the first positional argument is the target Meshtastic Client ID.
    parser.add_argument("client_id", nargs="?", help="Target Meshtastic Client ID (only in client mode)")
    parser.add_argument("-l", "--listen", action="store_true",
                        help="Start in listen/server mode (client mode requires a client ID)")
    parser.add_argument("-v", "--verbose", action="store_true",
                        help="Increase output verbosity")
    parser.add_argument("--serial", type=str, default=None,
                        help="Optional: Serial port for accessing the Meshtastic device. If not provided, the default behavior is used.")
    args = parser.parse_args()

    if args.listen:
        run_server(args.serial, args.verbose)
    else:
        if not args.client_id:
            parser.error("In client mode, a target Meshtastic Client ID must be provided.")
        run_client(args.client_id, args.serial, args.verbose)

if __name__ == "__main__":
    main()