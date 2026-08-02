# HoneyBash

HoneyBash is a multi-protocol honeypot framework written in Python. It provides simulated services across common network protocols to capture connection attempts, credentials, queries, and payload data for threat intelligence and security research.

## Features

- Supports 14 network protocols in a single framework.
- Modular architecture with individual server components.
- Structured logging of authentication attempts, connection events, and protocol payloads.
- Local SQLite storage backend with optional PostgreSQL support.
- Configurable service banners and custom port bindings.
- Ephemeral TLS certificate generation for HTTPS honeypot testing.

## Supported Protocols

| Protocol | Service Name | Default Port | Description |
| :--- | :--- | :--- | :--- |
| DHCP | `dhcp` | 67 / UDP | Emulates DHCP lease request handling |
| DNS | `dns` | 53 / UDP & TCP | Logs domain name resolution queries |
| FTP | `ftp` | 21 / TCP | Emulates FTP server login and command execution |
| HTTP Proxy | `httpproxy` | 8080 / TCP | Captures proxy requests and headers |
| HTTP | `http` | 80 / TCP | Serves decoy login and landing pages |
| HTTPS | `https` | 443 / TCP | TLS-encrypted HTTP honeypot with dynamic certificates |
| MySQL | `mysql` | 3306 / TCP | Simulates MySQL database authentication |
| PostgreSQL | `postgres` | 5432 / TCP | Simulates PostgreSQL wire protocol handshakes |
| RDP | `rdp` | 3389 / TCP | Captures Remote Desktop Protocol initiation attempts |
| Redis | `redis` | 6379 / TCP | Logs Redis command executions and auth requests |
| SMB | `smb` | 445 / TCP | Emulates Server Message Block connection requests |
| SMTP | `smtp` | 25 / TCP | Captures email transaction attempts and AUTH data |
| SSH | `ssh` | 22 / TCP | Captures SSH login credentials and terminal input |
| Telnet | `telnet` | 23 / TCP | Emulates Telnet login prompts and shell interactions |

## Requirements

- Python 3.9 or higher
- Administrative / Root privileges (required when binding to low-numbered ports under 1024)

## Installation

1. Clone the repository:
   ```bash
   git clone https://github.com/Yuthish231/HoneyBash.git
   cd HoneyBash
   ```

2. Create and activate a virtual environment (optional but recommended):
   ```bash
   python -m venv venv
   source venv/bin/activate  # On Linux/macOS
   # or
   venv\Scripts\activate     # On Windows
   ```

3. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

4. Alternatively, install the package in editable mode:
   ```bash
   pip install -e .
   ```

## Usage

### Command Line Interface

HoneyBash can be executed using the package manager CLI:

```bash
python -m HoneyBash [options]
```

Or if installed via `pip install -e .`:

```bash
honeybash [options]
```

### Running Specific Honeypots

To run individual honeypots directly:

```bash
python honeypots/ssh_server.py --port 2222
python honeypots/http_server.py --port 8080
```

### Configuration

Honeypot services accept custom parameters such as binding IP address, port numbers, decoy usernames, passwords, and storage options through command-line arguments or configuration files.

## Project Structure

```text
HoneyBash/
├── cli/              # Command line manager and CLI banners
├── config/           # Configuration loader and setting utilities
├── core/             # Base honeypot server definitions
├── data/             # HTML templates for HTTP honeypots
├── honeypots/        # Protocol-specific honeypot implementations
├── logging/          # Event logger and serialization handlers
├── network/          # Network sniffer module
├── storage/          # Storage backends (SQLite and PostgreSQL)
└── utils/            # General utilities and certificate generation
```

## Logging and Analytics

All captured events (connections, authentication attempts, raw commands) are serialized into JSON records and written to structured logs and local SQLite database files for subsequent analysis.

## Security Disclaimer

HoneyBash is intended solely for security research, threat monitoring, and educational purposes. Ensure you have proper authorization before deploying honeypots on networks you do not own or control.
