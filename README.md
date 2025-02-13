# [ɛm kæt]

`emcat` is a netcat-inspired CLI tool that uses Meshtastic for serial communication.
It lets you send and receive messages directly between Meshtastic devices.
It enables communication between hosts using Meshtastic networks.

**Note:** This is a **proof-of-concept** and is not recommended for production use — in fact, you might not want to use it at all. 

Reviews and pull requests are welcome :)

## Example Usage

Start an `emcat` listnener to receive data

```
emcat -l
```

Send data to receiver

```
cat data.txt | emcat 00affe00
```