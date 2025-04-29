# Scanux

A system security and performance scanner that helps monitor and analyze system health, security, and performance metrics.

## System Requirements

Before installing scanux, ensure you have the following system dependencies installed:

- nmap (Network Mapper)
  - Ubuntu/Debian: `sudo apt-get install nmap`
  - CentOS/RHEL: `sudo yum install nmap`
  - macOS: `brew install nmap`

## Features

- System metrics monitoring (CPU, memory, disk usage)
- Security scanning
- Performance analysis
- Network monitoring
- Multiple output formats (text, JSON, YAML)

## Installation

1. Install system dependencies (see above)
2. Install scanux:
   ```bash
   pip install scanux
   ```

## Usage

```bash
# Run a full system scan
scanux

# Show only issues
scanux --issues-only

# Output in JSON format
scanux --json

# Output in YAML format
scanux --yaml

# Run specific modules
scanux --modules system security
```

## Requirements

- Python 3.8 or higher
- psutil
- python-nmap
- netifaces
- rich
- pyyaml

## License

MIT 