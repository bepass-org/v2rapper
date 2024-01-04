
# V2rapper - TCP Proxy

This program is a custom TCP proxy that forwards traffic between a local and remote address. I developed it to monitor v2ray server connections.\
\
It includes features like country-based IP filtering, speed monitoring/throttling, keyword based routing and connection management.

## Features

- **Keyword based TCP Forwarding**: Forwards traffic between a local and remote server based on the incoming connection's header.
- **Speed Monitoring**: Monitors upload and download speeds, displaying them in real-time, and you can set a limit to drop old connections.
- **Connection Management**: Handles new connections, ensuring smooth operation under various conditions.
- **IP Filtering**: Supports country-based whitelisting or blacklisting of IPs using CIDR blocks.

## Usage

Run the program with the following command:

```
go run main.go [options]
```

### Options

- `-bind` or `-b`: Address to bind the TCP server to (default `:8080`).
- `-local` or `-l`: IP:Port to forward to if the connection matches a path (default `127.0.0.1:8081`).
- `-remote` or `-r`: IP:Port to forward to if the connection does not match any paths.
- `-country-whitelist` or `-cw`: List of country codes to whitelist (can be specified multiple times).
- `-country-blacklist` or `-cb`: List of country codes to blacklist (can be specified multiple times).
- `-upload-speed` or `-us`: Maximum upload speed (e.g., 10MB, 10Mb, 10KB).
- `-download-speed` or `-ds`: Maximum download speed (e.g., 10MB, 10Mb, 10KB).
- `-path` or `-p`: The string to check in the incoming connection to determine routing (can be specified multiple times).

### Examples

For example, you run a v2ray vless ws server on 127.0.0.1:8080 and your path is /ws and you want all probes and \
other connections to be forwarded to example.com:80. You can run the following command:
```
go run main.go -b :8080 -l 127.0.0.1:8081 -p "/ws" -r example.com:80
```
same as above but you want to whitelist Iran and China and drop all other connections:
```
go run main.go -b :8080 -l 127.0.0.1:8081 -p "/ws" -r example.com:80 -cw ir -cw ch
```
same as first example, but you want to accept all incoming connections except from US and UK and limit upload and download speed to 10MB:
```
go run main.go -b :8080 -l 127.0.0.1:8081 -p "/ws" -r example.com:80 -cb us -cb uk -us 10MB -ds 10MB
```

## Installation

Just clone the repository and run the program with the command above in a tmux session or as a service.

## Contributing

If you have any suggestions, feel free to open an issue or a pull request. Any contributions you make are greatly appreciated.

## License

This project is open-source and available under the [MIT License](LICENSE).
