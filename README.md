# [ɛm kæt]

![ɛm kæt](doc/emcat-logo-small.png)

`emcat` and `emdump` are netcat-inspired CLI tools that enable data transmission and packet capture over M-PWRD networks. Unlike simple message-based tools, `emcat` facilitates full-duplex streaming of arbitrary data, allowing efficient transfer of files or data streams between devices.

> **Note:** These tools are **proof-of-concept** and are not recommended for production use — in fact, you might not want to use them at all. Reviews and pull requests are welcome!

---

## Tools Overview

### emcat

`emcat` is designed for raw data transmission over M-PWRD networks. It operates similarly to `netcat`, enabling the transfer of continuous data streams rather than individual messages. This allows sending files or streaming input from one device to another seamlessly.

#### **Example Usage**

**Receiving a Data Stream (Listener Mode)**  
To receive incoming data and save it to a file:

```zsh
emcat -l > received_data.bin
```

**Sending a File**  
To send a file to a specific target device:

```zsh
cat file_to_send.bin | emcat 00affe00
```

These examples illustrate how `emcat` enables direct data transmission between devices using M-PWRD networks.

---

### **The emcat Protocol**

Since M-PWRD networks operate with limited packet sizes, `emcat` employs a chunked transmission protocol. Data is split into multiple **chunks**, each with a custom header to ensure correct reassembly at the receiving end.

#### **Header Structure**
Each transmitted chunk consists of:

- **Header Packets** (Sent at the beginning of a transmission)
  ```
  [ɛm kæt] | 0x90 | <Total Chunks> | 0x90 | <Chunk Size>
  ```
  - `[ɛm kæt]` → UTF-8 identifier for `emcat`
  - `0x90` → Separator byte
  - `<Total Chunks>` → Number of chunks (1 byte)
  - `0x90` → Separator byte
  - `<Chunk Size>` → Bytes per chunk (1 byte)

- **Data Chunks** (Sent after the header packet)
  ```
  ɛm | 0x90 | <Chunk Number> | 0x90 | <Payload>
  ```
  - `ɛm` → UTF-8 marker for chunk
  - `0x90` → Separator byte
  - `<Chunk Number>` → Sequence number of the chunk (1 byte)
  - `0x90` → Separator byte
  - `<Payload>` → Actual data (up to `<Chunk Size>` bytes)

---

#### **Transmission Process**

1. **Connection & Initialization**  
   The sender establishes a connection to an M-PWRD device and identifies the target device.

2. **Sending the Header Packet**  
   The sender first transmits a **header packet** containing metadata about the transmission, including the total number of chunks and the chunk size.

3. **Chunked Data Transmission**  
   The file or data stream is split into **chunks** based on the predefined chunk size. Each chunk is **sent individually** and **ACKed** by the receiver.

4. **Handling Lost or Out-of-Order Chunks**  
   If an **ACK is not received**, the sender **resends the chunk** until it is acknowledged or a timeout occurs.

5. **Reassembly at the Receiver**  
   The receiver reconstructs the file by:
   - Reading the header packet to determine how many chunks to expect.
   - Receiving and storing chunks based on their sequence number.
   - Writing the complete data to stdout once all chunks are received.

This protocol ensures that:
- **Large files can be transmitted over multiple packets.**
- **The receiver can detect missing or out-of-order chunks.**
- **Multiple concurrent streams can coexist without interference.**

---

### emdump

`emdump` is a companion tool for capturing and analyzing packets in an M-PWRD network. It can operate in two modes:

1. **Live Capture Mode:** Connects to an M-PWRD device and displays incoming packets in a tcpdump-like format. Optionally, it can save the live capture to a PCAP file with a custom encapsulation format for later analysis.
2. **Offline Analysis Mode:** Reads a PCAP file (with the custom M-PWRD encapsulation) and outputs the captured packets, allowing you to review previously saved captures.

#### **Example Usage**

**Live Capture Mode**

To capture live packets from an M-PWRD device and display them on the console:

```zsh
emdump
```

To also save the captured packets to a PCAP file:

```zsh
emdump -o capture.pcap
```

**Offline Analysis Mode**

To read and display packets from an existing PCAP file:

```zsh
emdump -i capture.pcap
```

In offline mode, `emdump` does not attempt to connect to a device; it only processes the provided PCAP file.

---

## Installation

Before proceeding, ensure that you have [GitHub CLI (`gh`)](https://cli.github.com/manual/installation) and [pipx](https://pipxproject.github.io/pipx/installation/) installed on your system.

Clone the repository and install the tools using pipx for an isolated and hassle-free setup:

```zsh
gh repo clone zefiet/emcat
pipx install .
```

This will clone the project from GitHub and install `emcat` and `emdump` in a virtual environment, ensuring that their dependencies are managed independently.

---

## Verbose Level

Both tools are designed to provide just the right amount of insight into their operations without overwhelming you with unnecessary details. By default, only **WARNING** and **ERROR** messages are sent to standard error (stderr).

- **`-v`**: Displays **INFO** messages along with warnings and errors.
- **`-vv`**: Displays **DEBUG** messages in addition to **INFO**, **WARNING**, and **ERROR** messages.
- **`-vvv`**: Provides maximum verbosity, including M-PWRD-specific debugging output.

---

## PCAP Files and Custom Encapsulation

`emdump` saves live captures in a PCAP file using a custom encapsulation format. The custom format consists of:
- **4 bytes:** Source address (unsigned int, network byte order)
- **4 bytes:** Destination address (unsigned int, network byte order)
- **2 bytes:** Port string length (unsigned short, network byte order)
- **n bytes:** Port string (UTF-8 encoded)
- **Remaining bytes:** Decoded payload

This encapsulation allows the preservation of the original port information without faking an Ethernet header.

---

## Contributing

Contributions, reviews, and pull requests are welcome! If you encounter issues or have suggestions for improvement, please open an issue on GitHub.

---

## Disclaimer

These tools are provided as-is for experimental and educational purposes. Use them at your own risk and be aware that they are not intended for production environments.

Happy networking!
