#!/usr/bin/env python3
"""
emcat - A netcat-inspired CLI tool that uses the Meshtastic library to connect
to a Meshtastic device via serial. It lets you send and receive messages directly
between Meshtastic devices and enables communication between hosts using Meshtastic networks.

Note: This is a proof-of-concept and is not recommended for production use—in fact,
you might not want to use it at all. Reviews and pull requests are welcome.
"""

import argparse
import re
import sys

# Import port number definitions from the Meshtastic package.
from meshtastic import portnums_pb2


def connect_device(serial_port=None, verbose=False):
    """
    Establish a connection to the Meshtastic device using the Meshtastic library.
    If a serial port is provided, it is used; otherwise, the default behavior of
    the Meshtastic client is applied.
    
    After a successful connection, the built-in sendHeartbeat() method is called
    to verify that the connection is stable.
    """
    try:
        import meshtastic.serial_interface as ms
        port_info = serial_port if serial_port else "default detection"
        if verbose:
            print(f"[INFO] Attempting to connect to the Meshtastic device (Serial Port: {port_info})...")
        # Pass sys.stdout as debug output if verbose is True
        debug_output = sys.stdout if verbose else None
        interface = ms.SerialInterface(devPath=serial_port, debugOut=debug_output)
        if verbose:
            print("[INFO] Successfully connected to the Meshtastic device.")
        
        # Use the built-in sendHeartbeat method to verify connection stability.
        try:
            if verbose:
                print("[INFO] Sending heartbeat using sendHeartbeat()...")
            interface.sendHeartbeat()
            if verbose:
                print("[INFO] Heartbeat sent successfully.")
        except Exception as heartbeat_error:
            print(f"[ERROR] Failed to send heartbeat: {heartbeat_error}")
            sys.exit(1)
        
        return interface
    except Exception as e:
        print(f"[ERROR] Failed to connect to the Meshtastic device: {e}")
        sys.exit(1)


def run_client(client_id, serial_port=None, verbose=False):
    """
    Client mode: Establishes a connection to the Meshtastic device and targets
    a specific Meshtastic client ID. It verifies that the client ID is correctly
    formatted (8 hexadecimal digits) and then checks whether the node is known
    in the network using the interface.nodes dictionary.
    
    If there is piped input from stdin, the content is sent as a data payload
    to the target client using sendData. If the payload is too big, it is
    split into chunks and each chunk is sent separately.
    """
    # Verify that client_id is in the correct 8-digit hexadecimal format
    if not re.fullmatch(r"[0-9a-fA-F]{8}", client_id):
        print(f"[ERROR] Provided client ID '{client_id}' is not in the correct format (8 hexadecimal digits).")
        sys.exit(1)

    interface = connect_device(serial_port, verbose)
    
    # Use interface.nodes to get the known nodes (do not use showNodes, which prints a table)
    nodes = interface.nodes

    # Normalize node keys by removing any leading "!" and converting to lowercase for comparison.
    def normalize_node_key(key):
        return key.lstrip("!").lower()
    known_nodes = {normalize_node_key(node_id) for node_id in nodes.keys()}
    
    if client_id.lower() not in known_nodes:
        print(f"[ERROR] Client ID '{client_id}' not found among known nodes: {list(known_nodes)}")
        sys.exit(1)
    
    if verbose:
        print(f"[INFO] Client mode started. Target Meshtastic Client ID: {client_id}")
    
    # Check if there's piped input from stdin
    if not sys.stdin.isatty():
        text = sys.stdin.read().strip()
        if text:
            if verbose:
                print(f"[INFO] Sending data to client {client_id}: {text}")
            # Prepend "!" to the client_id if not already present
            destination = client_id if client_id.startswith("!") else "!" + client_id.lower()
            
            # Convert text to bytes (UTF-8 encoded)
            data = text.encode("utf-8")
            # Define maximum payload size (in bytes); adjust as necessary
            CHUNK_SIZE = 180
            if len(data) > CHUNK_SIZE:
                if verbose:
                    print("[INFO] Payload too big, splitting into chunks.")
                num_chunks = (len(data) + CHUNK_SIZE - 1) // CHUNK_SIZE
                for i in range(0, len(data), CHUNK_SIZE):
                    chunk = data[i:i+CHUNK_SIZE]
                    if verbose:
                        print(f"[INFO] Sending chunk {i//CHUNK_SIZE + 1}/{num_chunks}: {chunk}")
                    interface.sendData(chunk,
                                       destinationId=destination,
                                       portNum=portnums_pb2.PortNum.TEXT_MESSAGE_APP)
                print("Data sent in chunks.")
            else:
                interface.sendData(data,
                                   destinationId=destination,
                                   portNum=portnums_pb2.PortNum.TEXT_MESSAGE_APP)
                print("Data sent.")
        else:
            print("[WARNING] No text provided via stdin.")
        return
    
    # Interactive mode could be implemented here if needed.
    print("Client mode: Meshtastic connection established. Awaiting input (interactive mode not implemented).")


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