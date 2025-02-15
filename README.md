# [ɛm kæt]

`emcat` is a netcat-inspired CLI tool that uses Meshtastic for serial communication.
It lets you send and receive messages directly between Meshtastic devices.
It enables communication between hosts using Meshtastic networks.

**Note:** This is a **proof-of-concept** and is not recommended for production use — in fact, you might not want to use it at all.

Reviews and pull requests are welcome :)

## Example Usage

### Starting an `emcat` Listener

[![asciicast](https://asciinema.org/a/B967gxiFQ7QUIdxePHIZDNo2B.svg)](https://asciinema.org/a/B967gxiFQ7QUIdxePHIZDNo2B)

To begin receiving data, start an `emcat` listener which redirects all incoming messages to a file:

```zsh
emcat -l > example.txt
```

### Sending Data to a Receiver

[![asciicast](https://asciinema.org/a/N8yNveya8QGlXTOkU3vwEH9VH.svg)](https://asciinema.org/a/N8yNveya8QGlXTOkU3vwEH9VH)

To send data, pipe the contents of a file into `emcat` along with the target device identifier:

```zsh
cat doc/example.txt | emcat 00affe00
```

These examples illustrate how you can easily set up a basic communication channel between devices using `emcat`.

## Install

Before proceeding, ensure that you have [GitHub CLI (`gh`)](https://cli.github.com/manual/installation) and [pipx](https://pipxproject.github.io/pipx/installation/) installed on your system.

Clone the repository and install `emcat` using pipx for an isolated and hassle-free setup:

```zsh
gh repo clone zefiet/emcat
pipx install .
```

This will clone the project from GitHub and install `emcat` in a virtual environment, ensuring that its dependencies are managed independently.

## Usage

### Verbose Level

`emcat` is designed to provide just the right amount of insight into its operations without overwhelming you with unnecessary details. By default, only **WARNING** and **ERROR** messages are sent to standard error (stderr), ensuring that critical issues are highlighted promptly while routine operations remain unobtrusive.

#### `-v`

With the `-v` option, **INFO** messages are displayed alongside warnings and errors. This level is ideal for everyday monitoring, offering a clear snapshot of the tool’s regular activities and key events.

#### `-vv`

The `-vv` flag increases verbosity by including **DEBUG** messages. This detailed output is particularly useful for troubleshooting, as it provides deeper insights into `emcat`’s internal processes and state transitions.

#### `-vvv`

Using the `-vvv` setting delivers maximum transparency. In this mode, you receive **INFO**, **DEBUG**, and additional Meshtastic-specific messages—ideal for advanced diagnostics and comprehensive monitoring of your Meshtastic network.
