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
import logging
from datetime import datetime

# Configure logging to output to stderr.
logging.basicConfig(
    stream=sys.stderr,
    level=logging.INFO,  # Default level; will be adjusted based on -v flags
    format='[%(levelname)s] %(message)s'
)

# Import pubsub for event handling
from pubsub import pub

# Register a signal handler for SIGINT (Ctrl+C) to catch KeyboardInterrupts cleanly
def sigint_handler(sig, frame):
    logging.info("KeyboardInterrupt received. Exiting the program.")
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
        logging.info(f"Attempting to connect to the Meshtastic device (Serial Port: {port_info})...")
        debug_output = sys.stdout if verbose >= 3 else None
        interface = ms.SerialInterface(devPath=serial_port, debugOut=debug_output)
        logging.info("Successfully connected to the Meshtastic device.")
        try:
            logging.info("Sending heartbeat using sendHeartbeat()...")
            interface.sendHeartbeat()
            logging.info("Heartbeat sent successfully.")
        except Exception as heartbeat_error:
            logging.error(f"Failed to send heartbeat: {heartbeat_error}")
            sys.exit(1)
        return interface
    except Exception as e:
        logging.error(f"Failed to connect to the Meshtastic device: {e}")
        sys.exit(1)


def send_chunk(interface, chunk, destination, timeout=DEFAULT_TIMEOUT, verbose=0):
    """
    Send a single chunk and wait for its ACK.
    A heartbeat is sent before each attempt, and the chunk is resent until an ACK is received.
    """
    ack_event = threading.Event()

    def callback(response):
        logging.debug("ACK callback triggered")
        decoded = response.get("decoded", {})
        routing = decoded.get("routing", {})
        error_reason = routing.get("errorReason", "NONE")
        if error_reason != "NONE":
            logging.debug(f"Delivery error occurred: {error_reason}")
        else:
            logging.debug("Message delivered successfully (ACK received).")
        ack_event.set()

    while not ack_event.is_set():
        try:
            logging.info("Sending heartbeat before sending chunk...")
            interface.sendHeartbeat()
        except Exception as e:
            logging.info(f"Exception during sending heartbeat: {e}")
        logging.info(f"Sending chunk data: {chunk}")
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
            logging.error(f"Exception during sending chunk: {e}")
            time.sleep(1)
            continue
        if not ack_event.wait(timeout):
            logging.warning("No ACK received, resending chunk...")
        else:
            logging.info("ACK received for chunk.")
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
        logging.error(f"Provided client ID '{client_id}' is not in the correct format (8 hexadecimal digits).")
        sys.exit(1)
        
    interface = connect_device(serial_port, verbose)
    nodes = interface.nodes

    def normalize_node_key(key):
        return key.lstrip("!").lower()

    known_nodes = {normalize_node_key(node_id) for node_id in nodes.keys()}
    if client_id.lower() not in known_nodes:
        logging.error(f"Client ID '{client_id}' not found among known nodes: {list(known_nodes)}")
        sys.exit(1)
        
    logging.info(f"Client mode started. Target Meshtastic Client ID: {client_id}")
        
    if not sys.stdin.isatty():
        text = sys.stdin.read().strip()
        if text:
            logging.info(f"Sending data to client {client_id}: {text}")
                
            # Ensure destination client ID is formatted correctly
            destination = client_id if client_id.startswith("!") else "!" + client_id.lower()
            data = text.encode("utf-8")
            chunks = [data[i:i+chunksize] for i in range(0, len(data), chunksize)]
            total_chunks = len(chunks)
            
            # Build header message:
            # Byte sequence of "[ɛm kæt]" followed by 0x90 and total_chunks,
            # then 0x90 and chunksize.
            header = "[ɛm kæt]".encode("utf-8") + b'\x90' + bytes([total_chunks]) + b'\x90' + bytes([chunksize])
            logging.info(f"Sending header message: {header}")
            send_chunk(interface, header, destination, timeout=timeout, verbose=verbose)
            logging.info(f"Waiting {delay} second(s) before sending first chunk...")
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
                logging.info(f"Sending chunk {chunk_number + 1}/{total_chunks} (chunk number: {chunk_number})")
                send_chunk(interface, full_chunk, destination, timeout=timeout, verbose=verbose)
                if chunk_number < total_chunks - 1:
                    logging.info(f"Waiting {delay} second(s) before sending next chunk...")
                    time.sleep(delay)
            logging.info("Data sent in chunks.")
        else:
            logging.warning("No text provided via stdin.")
        return
        
    logging.info("Client mode: Meshtastic connection established. Awaiting input (interactive mode not implemented).")


def run_server(serial_port=None, verbose=0):
    """
    Server mode: Connect to the Meshtastic device and listen for incoming packets using pubsub.
    Whenever a header packet is received, a new session is initiated.
    This version uses a shutdown event to gracefully terminate the main loop when all data is received.
    """
    logging.info("Server mode started.")

    # Event to signal that the server should shut down gracefully.
    shutdown_event = threading.Event()

    # Session state variables
    session_initialized = False
    session_client_id = None
    session_total_chunks = 0
    session_chunk_length = 0
    session_buffer = None  # Buffer for session data
    session_next_expected_chunk = 0  # Counter for expected chunk number

    def onConnection(interface, topic=pub.AUTO_TOPIC):
        logging.info("Meshtastic device connected.")
        pub.subscribe(on_receive, "meshtastic.receive")

    def on_receive(packet, interface):
        nonlocal session_initialized, session_client_id, session_total_chunks, session_chunk_length, session_buffer, session_next_expected_chunk

        logging.debug(f"Received packet: {packet}")

        # Attempt to extract the port number from the packet
        try:
            portnum = packet['decoded'].get('portnum', None)
        except (AttributeError, KeyError):
            logging.debug(f"Packet missing 'portnum': {packet}")
            return

        # Convert the expected port number (256) to its enum name, e.g., "PRIVATE_APP"
        expected_port = portnums_pb2.PortNum.Name(DEFAULT_PORT)
        if portnum != expected_port:
            logging.debug(f"Ignoring packet with port {portnum} (expected {expected_port}).")
            return

        # Retrieve the payload from the packet
        payload = packet['decoded'].get('payload', None)
        header_signature = "[ɛm kæt]".encode("utf-8")

        if payload is not None:
            payload_bytes = payload.encode("utf-8") if isinstance(payload, str) else payload

            # Check if the packet is a header packet
            if payload_bytes.startswith(header_signature):
                if session_initialized:
                    logging.warning("Received header packet while session active; aborting current session and reinitializing.")
                expected_header_length = len(header_signature) + 4
                if len(payload_bytes) < expected_header_length:
                    logging.warning("Incomplete header received; ignoring header parsing.")
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
                        logging.info(
                            f"Session initiated from client {format(session_client_id, '08x')}. "
                            f"Expecting {total_chunks} chunks with chunk length {chunk_length}. "
                            f"Allocated buffer of {total_chunks * chunk_length} bytes."
                        )
                # Header packets are used solely for session initialization.
                return

        # If no session is active, ignore non-header packets.
        if not session_initialized:
            logging.debug("No active session; ignoring non-header packet.")
            return

        # Process session packets only from the active session's client.
        if packet['from'] != session_client_id:
            logging.debug(
                f"Ignoring packet from client {format(packet['from'], '08x')}; "
                f"session active from client {format(session_client_id, '08x')}."
            )
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
                logging.warning(f"Received chunk number {chunk_number} but expected {session_next_expected_chunk}. Missing chunks?")
            elif chunk_number < session_next_expected_chunk:
                logging.info(f"Received chunk number {chunk_number} but expected {session_next_expected_chunk}. Ignoring duplicate/out-of-order packet.")
            else:
                # Expected chunk received; extract chunk data (payload after header)
                chunk_data = payload_bytes[expected_chunk_header_length:]
                offset = chunk_number * session_chunk_length
                session_buffer[offset:offset+len(chunk_data)] = chunk_data
                logging.info(f"Successfully received chunk {chunk_number}. Stored at offset {offset} in buffer.")
                session_next_expected_chunk += 1

                # When all chunks have been received, write the complete data and signal shutdown.
                if session_next_expected_chunk == session_total_chunks:
                    logging.info("All data received.")
                    sys.stdout.buffer.write(session_buffer)
                    sys.stdout.buffer.flush()
                    shutdown_event.set()  # Signal to exit the main loop gracefully
        else:
            logging.info(f"Session packet received from client {format(packet['from'], '08x')} with no header marker.")

        logging.debug(
            f"[{datetime.now().strftime('%y-%m-%d %H:%M:%S')}] "
            f"!{format(packet['from'], '08x')} > !{format(packet['to'], '08x')} | "
            f"PORT: {portnum} | PAYLOAD: {payload}"
        )

    # Subscribe to connection established and lost topics
    pub.subscribe(onConnection, "meshtastic.connection.established")
    pub.subscribe(
        lambda interface, topic=pub.AUTO_TOPIC: (
            logging.info("Meshtastic device disconnected. Exiting gracefully."),
            shutdown_event.set()
        ),
        "meshtastic.connection.lost"
    )

    # Connect to the device
    interface = connect_device(serial_port, verbose)
    logging.info("Server mode: Listening for incoming Meshtastic packets...")

    # Main loop: run until the shutdown_event is set.
    while not shutdown_event.is_set():
        try:
            interface.sendHeartbeat()
            time.sleep(1)
        except Exception as e:
            logging.error(f"Exception in server loop: {e}")
            shutdown_event.set()

    logging.info("Exiting server mode gracefully.")


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

    # Adjust logging level based on verbose flag.
    if args.verbose == 0:
        logging.getLogger().setLevel(logging.WARNING)
    elif args.verbose == 1:
        logging.getLogger().setLevel(logging.INFO)
    else:
        logging.getLogger().setLevel(logging.DEBUG)

    if args.listen:
        run_server(args.serial, args.verbose)
    else:
        if not args.client_id:
            parser.error("In client mode, a target Meshtastic Client ID must be provided.")
        run_client(args.client_id, args.serial, args.verbose, delay=args.delay,
                   timeout=args.timeout, chunksize=args.chunksize)


if __name__ == "__main__":
    main()