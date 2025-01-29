# ExShark

[![Hex.pm](https://img.shields.io/hexpm/v/exshark.svg)](https://hex.pm/packages/exshark)
[![Documentation](https://img.shields.io/badge/docs-hexpm-blue.svg)](https://hexdocs.pm/exshark)
[![Build Status](https://github.com/ryankshah/exshark/workflows/CI/badge.svg)](https://github.com/ryankshah/exshark/actions)
[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

ExShark is an Elixir wrapper for tshark (Wireshark's command-line interface) that enables packet capture and analysis using Wireshark's powerful dissectors.

## Features

- 🚀 Live packet capture with streaming support
- 📦 PCAP file analysis
- 🔍 Lazy packet loading for memory efficiency
- ⚡ Async packet processing
- 🛠 Full access to Wireshark dissectors
- 📊 Rich packet information including raw data access
- 🧪 Comprehensive test suite

## Installation

1. Ensure you have Wireshark/tshark installed on your system:

```bash
# Ubuntu/Debian
sudo apt-get install tshark

# macOS
brew install wireshark
```

2. Add `exshark` to your dependencies in `mix.exs`:

```elixir
def deps do
  [
    {:exshark, "~> 0.1.0"},
    {:jason, "~> 1.2"}
  ]
end
```

3. Install dependencies:

```bash
mix deps.get
```

## Quick Start

### Analyzing a PCAP File

```elixir
# Read all packets from a PCAP file
packets = ExShark.read_file("capture.pcap")

# Access packet information
first_packet = Enum.at(packets, 0)
IO.puts "Protocol: #{first_packet.highest_layer}"
IO.puts "Source IP: #{first_packet[ip: :src]}"
```

### Live Capture

```elixir
# Start a live capture
ExShark.capture(interface: "eth0", filter: "tcp port 80")
|> Stream.each(fn packet ->
  IO.puts "Captured: #{packet.highest_layer}"
end)
|> Stream.run()
```

### Lazy Loading

```elixir
# Start a lazy capture
{:ok, capture} = ExShark.LazyCapture.start_link("large_capture.pcap")

# Load specific packets on demand
packet = ExShark.LazyCapture.get_packet(capture, 1000)
IO.puts "Packet #{packet.frame_info.number}: #{packet.highest_layer}"
```

### Async Processing

```elixir
callback = fn packet ->
  IO.puts "Processing packet #{packet.frame_info.number}"
  {:ok, nil}
end

TShark.AsyncCapture.apply_on_packets("capture.pcap", callback, timeout: 5000)
```

## Advanced Usage

### Raw Data Access

```elixir
# Access raw packet data
packet = TShark.read_file("capture.pcap") |> Enum.at(0)
layer = TShark.Packet.get_layer(packet, :tcp)
raw_layer = %{layer | raw_mode: true}
raw_data = TShark.Layer.get_field(raw_layer, :payload)
```

### Protocol Field Access

```elixir
# Multiple ways to access protocol fields
packet[ip: :src]                    # Access protocol field
packet.frame_info.protocols         # Access frame info
TShark.Packet.get_layer(packet, :http)  # Get entire protocol layer
```

## Documentation

Full documentation can be found at [https://hexdocs.pm/tshark_ex](https://hexdocs.pm/tshark_ex).

## Development

### Prerequisites

- Elixir 1.14 or later
- Erlang/OTP 25 or later
- tshark/Wireshark

### Running Tests

#### Run all tests
```bash
mix test
```

#### Run with coverage
```bash
mix coveralls
```

#### Run specific test file
```bash
mix test test/exshark/async_capture_test.exs
```

### Contributing

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add some amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Acknowledgments

- Inspired by the Python [pyshark](https://github.com/KimiNewt/pyshark) library
- Built on top of the excellent [Wireshark](https://www.wireshark.org/) project

## Support

If you have any questions or run into issues, please [open an issue](https://github.com/yourusername/tshark_ex/issues/new) on GitHub.