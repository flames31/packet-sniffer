# 🔍 Packet Sniffer

A lightweight packet sniffer in Go that captures and displays live network traffic in your terminal.

## Features

- Real-time packet capture
- Protocol detection (TCP, UDP, ICMP)
- Live traffic statistics
- Clean terminal dashboard

## Installation

```bash
# Install dependencies
sudo apt-get install libpcap-dev  # For Linux users (macOS already has libpcap)

# Clone and setup
git clone https://github.com/flames31/packet-sniffer.git
cd packet-sniffer

go mod init packet-sniffer
go get github.com/google/gopacket
go get github.com/rivo/tview
```

## Usage

```bash
# List network interfaces
sudo go run main.go --list

# Start capturing
sudo go run main.go --iface eth0 (or en0 for macOS)
```

**Note:** Requires root/sudo privileges.

## Testing

```bash
# Generate ICMP traffic
ping google.com

# Generate TCP traffic
curl https://google.com
```

## Requirements

- Go 1.19+
- libpcap
- Root privileges

## License

MIT
