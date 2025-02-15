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
DEFAULT_DELAY = 0         # Delay between sending chunks in seconds (default: 0 seconds)
DEFAULT_TIMEOUT = 10      # Timeout for waiting for an ACK in seconds (default: 10 seconds)
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
        debug_output = sys.stdout if verbose >= 3 else None
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
            print(f"[INFO] Sending chunk data: {chunk}")
        try:
            interface.sendData(
                chunk,
                destinationId=destination,
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
    Client mode: Connect to the Meshtastic device and send data to a specific client.
    Before sending the first data chunk, a header message is sent containing protocol info.
    """
    # Validate client_id format (must be 8 hexadecimal digits)
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
                
            # Ensure destination client ID is formatted correctly
            destination = client_id if client_id.startswith("!") else "!" + client_id.lower()
            data = text.encode("utf-8")
            chunks = [data[i:i+chunksize] for i in range(0, len(data), chunksize)]
            total_chunks = len(chunks)
            
            # Build header message:
            # Byte sequence of "[ɛm kæt]" followed by 0x90 and total_chunks,
            # then 0x90 and chunksize.
            header = "[ɛm kæt]".encode("utf-8") + b'\x90' + bytes([total_chunks]) + b'\x90' + bytes([chunksize])
            if verbose >= 1:
                print(f"[INFO] Sending header message: {header}")
            send_chunk(interface, header, destination, timeout=timeout, verbose=verbose)
            if verbose >= 1:
                print(f"[INFO] Waiting {delay} second(s) before sending first chunk...")
            time.sleep(delay)
            
            # Now send the data chunks with per-chunk headers
            for chunk_number, chunk in enumerate(chunks):
                # Build per-chunk header:
                # - Static "ɛm" as UTF-8 encoded bytes,
                # - 0x90 as delimiter,
                # - current chunk number (starting at 0) as a single byte,
                # - 0x90 as delimiter.
                chunk_header = "ɛm".encode("utf-8") + b'\x90' + bytes([chunk_number]) + b'\x90'
                full_chunk = chunk_header + chunk
                if verbose >= 1:
                    print(f"[INFO] Sending chunk {chunk_number + 1}/{total_chunks} (chunk number: {chunk_number})")
                send_chunk(interface, full_chunk, destination, timeout=timeout, verbose=verbose)
                if chunk_number < total_chunks - 1:
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
    Only packets on the DEFAULT_PORT are processed.
    Whenever a header packet is received (even during an active session),
    a new session is initiated. If a session already exists, a warning is issued.
    Upon initialization, a buffer of (total_chunks * chunk_length) bytes is allocated.
    """
    if verbose >= 1:
        print("[INFO] Server mode started.")

    # Session state variables
    session_initialized = False
    session_client_id = None
    session_total_chunks = 0
    session_chunk_length = 0
    session_buffer = None  # Buffer for session data
    session_next_expected_chunk = 0  # Counter for expected chunk number

    def onConnection(interface, topic=pub.AUTO_TOPIC):
        if verbose >= 1:
            print("[INFO] Meshtastic device connected.")
        pub.subscribe(on_receive, "meshtastic.receive")
        # Uncomment below if additional data packet subscription is needed:
        # pub.subscribe(on_receive_data, "meshtastic.receive.data")

    def on_receive(packet, interface):
        nonlocal session_initialized, session_client_id, session_total_chunks, session_chunk_length, session_buffer, session_next_expected_chunk

        # Debug: print the entire packet if verbose level is 2 or higher
        if verbose >= 2:
            print(f"[DEBUG] Received packet: {packet}")

        # Attempt to extract the port number from the packet
        try:
            portnum = packet['decoded'].get('portnum', None)
        except (AttributeError, KeyError):
            if verbose >= 2:
                print(f"[DEBUG] Packet missing 'portnum': {packet}")
            return

        # Convert the expected port number (256) to its enum name, e.g., "PRIVATE_APP"
        expected_port = portnums_pb2.PortNum.Name(DEFAULT_PORT)
        if portnum != expected_port:
            if verbose >= 2:
                print(f"[DEBUG] Ignoring packet with port {portnum} (expected {expected_port}).")
            return

        # Retrieve the payload from the packet
        payload = packet['decoded'].get('payload', None)
        header_signature = "[ɛm kæt]".encode("utf-8")

        # If payload exists, convert it to bytes
        if payload is not None:
            payload_bytes = payload.encode("utf-8") if isinstance(payload, str) else payload

            # Check if the packet is a header packet
            if payload_bytes.startswith(header_signature):
                if session_initialized:
                    if verbose >= 1:
                        print("[WARNING] Received header packet while session active; aborting current session and reinitializing.")
                # Process header packet regardless of session state:
                expected_header_length = len(header_signature) + 4
                if len(payload_bytes) < expected_header_length:
                    if verbose >= 1:
                        print("[WARNING] Incomplete header received; ignoring header parsing.")
                else:
                    if (payload_bytes[len(header_signature)] == 0x90 and
                        payload_bytes[len(header_signature) + 2] == 0x90):
                        total_chunks = payload_bytes[len(header_signature) + 1]
                        chunk_length = payload_bytes[len(header_signature) + 3]
                        session_client_id = packet['from']
                        session_total_chunks = total_chunks
                        session_chunk_length = chunk_length
                        session_buffer = bytearray(total_chunks * chunk_length)
                        session_next_expected_chunk = 0
                        session_initialized = True
                        if verbose >= 1:
                            print(f"[INFO] Session initiated from client {format(session_client_id, '08x')}. "
                                  f"Expecting {total_chunks} chunks with chunk length {chunk_length}. "
                                  f"Allocated buffer of {total_chunks * chunk_length} bytes.")
                # Since header packets are used solely for session initialization, return now.
                return

        # If we reach here, the packet is not a header packet.
        # If no session is active, ignore the packet.
        if not session_initialized:
            if verbose >= 2:
                print("[DEBUG] No active session; ignoring non-header packet.")
            return

        # Process session packets only from the active session's client.
        if packet['from'] != session_client_id:
            if verbose >= 2:
                print(f"[DEBUG] Ignoring packet from client {format(packet['from'], '08x')}; "
                      f"session active from client {format(session_client_id, '08x')}.")
            return

        # Define our per-chunk header marker.
        # Format: "ɛm" (UTF-8) + 0x90 + <chunk_number> + 0x90.
        marker = "ɛm".encode("utf-8")
        expected_chunk_header_length = len(marker) + 3

        if (len(payload_bytes) >= expected_chunk_header_length and
            payload_bytes.startswith(marker) and
            payload_bytes[len(marker)] == 0x90 and
            payload_bytes[len(marker) + 2] == 0x90):

            # Extract the chunk number (one byte after the first delimiter)
            chunk_number = payload_bytes[len(marker) + 1]

            if chunk_number > session_next_expected_chunk:
                if verbose >= 1:
                    print(f"[WARNING] Received chunk number {chunk_number} but expected {session_next_expected_chunk}. Missing chunks?")
            elif chunk_number < session_next_expected_chunk:
                if verbose >= 1:
                    print(f"[INFO] Received chunk number {chunk_number} but expected {session_next_expected_chunk}. Ignoring duplicate/out-of-order packet.")
            else:
                # Expected chunk received; extract chunk data (payload after header)
                chunk_data = payload_bytes[expected_chunk_header_length:]
                offset = chunk_number * session_chunk_length
                session_buffer[offset:offset+len(chunk_data)] = chunk_data
                if verbose >= 1:
                    print(f"[INFO] Successfully received chunk {chunk_number}. Stored at offset {offset} in buffer.")
                session_next_expected_chunk += 1
        else:
            if verbose >= 1:
                print(f"[INFO] Session packet received from client {format(packet['from'], '08x')} with no header marker.")

        if verbose >= 2:
            timestamp = datetime.now().strftime("%y-%m-%d %H:%M:%S")
            channel_str = f" | CH: {packet['channel']}" if 'channel' in packet else ""
            prio_str = f" | PRIO: {packet['priority']}" if 'priority' in packet else ""
            payload_str = f" | PAYLOAD: {payload}"
            print(f"[DEBUG] [{timestamp}] !{format(packet['from'], '08x')} > !{format(packet['to'], '08x')}"
                  f"{channel_str}{prio_str} | PORT: {portnum}{payload_str}")

    # Subscribe to connection established and lost topics
    pub.subscribe(onConnection, "meshtastic.connection.established")
    pub.subscribe(lambda interface, topic=pub.AUTO_TOPIC: (print("[INFO] Meshtastic device disconnected. Exiting gracefully."), sys.exit(0)),
                  "meshtastic.connection.lost")

    # Connect to the device
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