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
import threading
import time

# Global default configuration
DEFAULT_DELAY = 1         # Delay between sending chunks in seconds (default: 1 second)
DEFAULT_TIMEOUT = 30      # Timeout for waiting for an ACK in seconds (default: 30 seconds)
DEFAULT_CHUNK_SIZE = 180  # Maximum payload size per chunk in bytes (default: 180 bytes)

# Import port number definitions from the Meshtastic package.
from meshtastic import portnums_pb2


def connect_device(serial_port=None, verbose=0):
    """
    Establish a connection to the Meshtastic device using the Meshtastic library.
    If a serial port is provided, it is used; otherwise, the default behavior of
    the Meshtastic client is applied.

    After a successful connection, the built-in sendHeartbeat() method is called
    to verify that the connection is stable.

    The interface outputs debug information only if verbose level >= 2.
    """
    try:
        import meshtastic.serial_interface as ms
        port_info = serial_port if serial_port else "default detection"
        if verbose >= 1:
            print(f"[INFO] Attempting to connect to the Meshtastic device (Serial Port: {port_info})...")
        # Only pass sys.stdout as debug output if verbose level is at least 2
        debug_output = sys.stdout if verbose >= 2 else None
        interface = ms.SerialInterface(devPath=serial_port, debugOut=debug_output)
        if verbose >= 1:
            print("[INFO] Successfully connected to the Meshtastic device.")
        
        # Use the built-in sendHeartbeat method to verify connection stability.
        try:
            if verbose >= 1:
                print("[INFO] Sending heartbeat using sendHeartbeat()...")
            interface.sendHeartbeat()
            if verbose >= 1:
                print("[INFO] Heartbeat sent successfully.")
        except Exception as heartbeat_error:
            print(f"[ERROR] Failed to send heartbeat: {heartbeat_error}")
            sys.exit(1)
        
        return interface
    except Exception as e:
        print(f"[ERROR] Failed to connect to the Meshtastic device: {e}")
        sys.exit(1)


def send_chunk(interface, chunk, destination, timeout=DEFAULT_TIMEOUT, verbose=0):
    """
    Send a single chunk and wait for its ACK.
    Before each send attempt, a heartbeat is sent to "reset" the connection state.
    The chunk is resent until an ACK is received.
    """
    ack_event = threading.Event()

    def callback(response):
        if verbose >= 1:
            print(f"[DEBUG] ACK callback triggered with response: {response}")
        ack_event.set()

    while not ack_event.is_set():
        # Send a heartbeat before each send attempt.
        try:
            if verbose >= 1:
                print("[INFO] Sending heartbeat before sending chunk...")
            interface.sendHeartbeat()
        except Exception as e:
            if verbose >= 1:
                print(f"[WARNING] Exception during sending heartbeat: {e}")
        if verbose >= 1:
            print(f"[INFO] Sending chunk: {chunk}")
        try:
            interface.sendData(
                chunk,
                destinationId=destination,
                portNum=portnums_pb2.PortNum.TEXT_MESSAGE_APP,
                wantAck=True,
                onResponse=callback,
                onResponseAckPermitted=True
            )
        except Exception as e:
            print(f"[ERROR] Exception during sending chunk: {e}")
            time.sleep(1)
            continue
        # Wait for ACK with the specified timeout
        if not ack_event.wait(timeout):
            print(f"[WARNING] No ACK received, resending chunk...")
        else:
            if verbose >= 1:
                print("[INFO] ACK received for chunk.")
    return True


def run_client(client_id, serial_port=None, verbose=0, delay=DEFAULT_DELAY, timeout=DEFAULT_TIMEOUT, chunksize=DEFAULT_CHUNK_SIZE):
    """
    Client mode: Establishes a connection to the Meshtastic device and targets
    a specific Meshtastic client ID. It verifies that the client ID is correctly
    formatted (8 hexadecimal digits) and then checks whether the node is known
    in the network using the interface.nodes dictionary.
    
    If there is piped input from stdin, the content is sent as a data payload
    to the target client using sendData() with wantAck=True. The payload is split
    into chunks (even if only one chunk is needed) and each chunk is sent sequentially.
    Each chunk is only advanced after an ACK is received; if no ACK is received, the
    chunk is resent.
    """
    # Verify that client_id is in the correct 8-digit hexadecimal format.
    if not re.fullmatch(r"[0-9a-fA-F]{8}", client_id):
        print(f"[ERROR] Provided client ID '{client_id}' is not in the correct format (8 hexadecimal digits).")
        sys.exit(1)

    interface = connect_device(serial_port, verbose)
    
    # Use interface.nodes to get the known nodes.
    nodes = interface.nodes

    # Normalize node keys by removing any leading "!" and converting to lowercase.
    def normalize_node_key(key):
        return key.lstrip("!").lower()
    known_nodes = {normalize_node_key(node_id) for node_id in nodes.keys()}
    
    if client_id.lower() not in known_nodes:
        print(f"[ERROR] Client ID '{client_id}' not found among known nodes: {list(known_nodes)}")
        sys.exit(1)
    
    if verbose >= 1:
        print(f"[INFO] Client mode started. Target Meshtastic Client ID: {client_id}")
    
    # Check if there's piped input from stdin.
    if not sys.stdin.isatty():
        text = sys.stdin.read().strip()
        if text:
            if verbose >= 1:
                print(f"[INFO] Sending data to client {client_id}: {text}")
            # Prepend "!" to the client_id if not already present.
            destination = client_id if client_id.startswith("!") else "!" + client_id.lower()
            
            # Convert text to bytes (UTF-8 encoded).
            data = text.encode("utf-8")
            # Split data into chunks of size 'chunksize'.
            chunks = [data[i:i+chunksize] for i in range(0, len(data), chunksize)]
            total_chunks = len(chunks)
            for index, chunk in enumerate(chunks, start=1):
                if verbose >= 1:
                    print(f"[INFO] Sending chunk {index}/{total_chunks}")
                send_chunk(interface, chunk, destination, timeout=timeout, verbose=verbose)
                # Wait only if there is another chunk to send.
                if index < total_chunks:
                    if verbose >= 1:
                        print(f"[INFO] Waiting {delay} second(s) before sending next chunk...")
                    time.sleep(delay)
            print("Data sent in chunks.")
        else:
            print("[WARNING] No text provided via stdin.")
        return
    
    # Interactive mode could be implemented here if needed.
    print("Client mode: Meshtastic connection established. Awaiting input (interactive mode not implemented).")


def run_server(serial_port=None, verbose=0):
    """
    Server mode: Establishes a connection to the Meshtastic device.
    In the future, implement logic to handle incoming messages.
    """
    interface = connect_device(serial_port, verbose)
    if verbose >= 1:
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
    # Verbosity as count: -v for minimal, -vv for interface debug output.
    parser.add_argument("-v", "--verbose", action="count", default=0,
                        help="Increase output verbosity (use -vv for interface debug output)")
    parser.add_argument("--serial", type=str, default=None,
                        help="Optional: Serial port for accessing the Meshtastic device. If not provided, the default behavior is used.")
    # Parameters for delay, timeout, and chunk size.
    parser.add_argument("-d", "--delay", type=int, default=DEFAULT_DELAY,
                        help=f"Delay between sending chunks in seconds (default: {DEFAULT_DELAY})")
    parser.add_argument("-t", "--timeout", type=int, default=DEFAULT_TIMEOUT,
                        help=f"Timeout for waiting for an ACK in seconds (default: {DEFAULT_TIMEOUT})")
    parser.add_argument("-c", "--chunksize", type=int, default=DEFAULT_CHUNK_SIZE,
                        help=f"Chunk size for splitting the payload in bytes (default: {DEFAULT_CHUNK_SIZE})")
    args = parser.parse_args()

    if args.listen:
        run_server(args.serial, args.verbose)
    else:
        if not args.client_id:
            parser.error("In client mode, a target Meshtastic Client ID must be provided.")
        run_client(args.client_id, args.serial, args.verbose, delay=args.delay, timeout=args.timeout, chunksize=args.chunksize)


if __name__ == "__main__":
    main()