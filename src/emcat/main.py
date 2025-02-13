#!/usr/bin/env python3
"""
emcat - A netcat-inspired CLI tool that uses the Meshtastic library to connect
to a Meshtastic device via serial. It allows you to send and receive messages directly
between Meshtastic devices and enables communication between hosts using Meshtastic networks.

Note: This is a proof-of-concept and is not recommended for production use—in fact,
you might not want to use it at all. Reviews and pull requests are welcome.
"""

import argparse
import re
import sys
import threading
import time
import signal
from datetime import datetime

# Import pubsub for event handling
from pubsub import pub

# Register a signal handler for SIGINT (Ctrl+C) to catch KeyboardInterrupts cleanly
def sigint_handler(sig, frame):
    print("\n[INFO] KeyboardInterrupt received. Exiting the program.")
    sys.exit(0)

signal.signal(signal.SIGINT, sigint_handler)

# Global default configuration
DEFAULT_DELAY = 0         # Delay between sending chunks in seconds (default: 1 second)
DEFAULT_TIMEOUT = 10      # Timeout for waiting for an ACK in seconds (default: 30 seconds)
DEFAULT_CHUNK_SIZE = 180  # Maximum payload size per chunk in bytes (default: 180 bytes)
DEFAULT_PORT = 256        # Default port number for sending data


# Import port number definitions from the Meshtastic package.
from meshtastic import portnums_pb2


def connect_device(serial_port=None, verbose=0):
    """
    Establish a connection to the Meshtastic device using the Meshtastic library.
    If a serial port is provided, it is used; otherwise, the default behavior of the
    Meshtastic client is applied.

    After a successful connection, sendHeartbeat() is used to verify the connection.
    """
    try:
        import meshtastic.serial_interface as ms
        port_info = serial_port if serial_port else "default detection"
        if verbose >= 1:
            print(f"[INFO] Attempting to connect to the Meshtastic device (Serial Port: {port_info})...")
        debug_output = sys.stdout if verbose >= 2 else None
        interface = ms.SerialInterface(devPath=serial_port, debugOut=debug_output)
        if verbose >= 1:
            print("[INFO] Successfully connected to the Meshtastic device.")
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
    A heartbeat is sent before each attempt, and the chunk is resent until an ACK is received.
    """
    ack_event = threading.Event()

    def callback(response):
        if verbose >= 1:
            print("[DEBUG] ACK callback triggered")
        decoded = response.get("decoded", {})
        routing = decoded.get("routing", {})
        error_reason = routing.get("errorReason", "NONE")
        if error_reason != "NONE":
            if verbose >= 1:
                print(f"[DEBUG] Delivery error occurred: {error_reason}")
        else:
            if verbose >= 1:
                print("[DEBUG] Message delivered successfully (ACK received).")
        ack_event.set()

    while not ack_event.is_set():
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
                #portNum=portnums_pb2.PortNum.TEXT_MESSAGE_APP,
                portNum=DEFAULT_PORT,
                wantAck=True,
                onResponse=callback,
                onResponseAckPermitted=True
            )
        except Exception as e:
            print(f"[ERROR] Exception during sending chunk: {e}")
            time.sleep(1)
            continue
        if not ack_event.wait(timeout):
            print("[WARNING] No ACK received, resending chunk...")
        else:            
            if verbose >= 1:
                print("[INFO] ACK received for chunk.")
    ack_event.clear()
    return True


def run_client(client_id, serial_port=None, verbose=0, delay=DEFAULT_DELAY,
               timeout=DEFAULT_TIMEOUT, chunksize=DEFAULT_CHUNK_SIZE):
    """
    Client mode: Connect to the Meshtastic device and target a specific client ID.
    If input is piped via stdin, send the content as a data payload in chunks.
    """
    if not re.fullmatch(r"[0-9a-fA-F]{8}", client_id):
        print(f"[ERROR] Provided client ID '{client_id}' is not in the correct format (8 hexadecimal digits).")
        sys.exit(1)
    interface = connect_device(serial_port, verbose)
    nodes = interface.nodes

    def normalize_node_key(key):
        return key.lstrip("!").lower()
    known_nodes = {normalize_node_key(node_id) for node_id in nodes.keys()}
    if client_id.lower() not in known_nodes:
        print(f"[ERROR] Client ID '{client_id}' not found among known nodes: {list(known_nodes)}")
        sys.exit(1)
    if verbose >= 1:
        print(f"[INFO] Client mode started. Target Meshtastic Client ID: {client_id}")
    if not sys.stdin.isatty():
        text = sys.stdin.read().strip()
        if text:
            if verbose >= 1:
                print(f"[INFO] Sending data to client {client_id}: {text}")
            destination = client_id if client_id.startswith("!") else "!" + client_id.lower()
            data = text.encode("utf-8")
            chunks = [data[i:i+chunksize] for i in range(0, len(data), chunksize)]
            total_chunks = len(chunks)
            for index, chunk in enumerate(chunks, start=1):
                if verbose >= 1:
                    print(f"[INFO] Sending chunk {index}/{total_chunks}")
                send_chunk(interface, chunk, destination, timeout=timeout, verbose=verbose)
                if index < total_chunks:
                    if verbose >= 1:
                        print(f"[INFO] Waiting {delay} second(s) before sending next chunk...")
                    time.sleep(delay)
            print("Data sent in chunks.")
        else:
            print("[WARNING] No text provided via stdin.")
        return
    print("Client mode: Meshtastic connection established. Awaiting input (interactive mode not implemented).")


def run_server(serial_port=None, verbose=0):
    """
    Server mode: Connect to the Meshtastic device and listen for incoming packets using pubsub.
    When a packet is received, print its raw content.
    If the serial port disconnects, catch the event and exit gracefully.
    """
    
    if verbose >= 1:
        print("[INFO] Server mode started.")

    def onConnection(interface, topic=pub.AUTO_TOPIC):
        if verbose >= 1:
            print("[INFO] Meshtastic device connected.")
            
        pub.subscribe(on_receive, "meshtastic.receive")        
        pub.subscribe(on_receive_data,  "meshtastic.receive.data")

    def on_receive(packet, interface):
        if verbose >= 1:
            timestamp = datetime.now().strftime("%y-%m-%d %H:%M:%S")
            channel_str = f" | CH: {packet['channel']}" if 'channel' in packet else ""
            prio_str = f" | PRIO: {packet['priority']}" if 'priority' in packet else ""
            port_str = f" | PORT: {packet['decoded']['portnum']}" if 'portnum' in packet['decoded'] else ""
            payload_str = f" | PAYLOAD: {packet['decoded']['payload']}" if 'payload' in packet['decoded'] else ""
            print(f"[{timestamp}] !{format(packet['from'], '08x')} > !{format(packet['to'], '08x')}{channel_str}{prio_str}{port_str}{payload_str}")

    def on_receive_data(packet, interface):
        from pprint import pprint
        
        try:
            packet.show()
        except AttributeError:
            pprint(packet)

    def on_disconnect(interface, topic=pub.AUTO_TOPIC):
        print("[INFO] Meshtastic device disconnected. Exiting gracefully.")
        sys.exit(0)
        
    # Subscribe to the receive and disconnect topics using pubsub.
    #pub.subscribe(on_receive, "meshtastic.receive")
    pub.subscribe(on_disconnect, "meshtastic.connection.lost")
    pub.subscribe(onConnection, "meshtastic.connection.established")

    interface = connect_device(serial_port, verbose)

    print("Server mode: Listening for incoming Meshtastic packets...")
    
    # Keep the server loop running indefinitely.
    while True:
        try:
            interface.sendHeartbeat()
            time.sleep(1)
        except Exception as e:
            print(f"[ERROR] Exception in server loop: {e}")
            sys.exit(1)


def main():
    parser = argparse.ArgumentParser(
        description="emcat - a netcat-inspired CLI tool using the Meshtastic library to connect to a Meshtastic device via serial."
    )
    parser.add_argument("client_id", nargs="?", help="Target Meshtastic Client ID (only in client mode)")
    parser.add_argument("-l", "--listen", action="store_true",
                        help="Start in listen/server mode (client mode requires a client ID)")
    parser.add_argument("-v", "--verbose", action="count", default=0,
                        help="Increase output verbosity (use -vv for interface debug output)")
    parser.add_argument("--serial", type=str, default=None,
                        help="Optional: Serial port for accessing the Meshtastic device. If not provided, default detection is used.")
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
        run_client(args.client_id, args.serial, args.verbose, delay=args.delay,
                   timeout=args.timeout, chunksize=args.chunksize)


if __name__ == "__main__":
    main()