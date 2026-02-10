# Port Scanner

Custom TCP port scanner with multi-threaded scanning, banner grabbing, and multiple output formats.

## Usage

```bash
python3 -m port_scanner --target 172.20.0.1 --ports 1-10000
python3 -m port_scanner --target 172.20.0.0/24 --ports 1-65535 --threads 200
python3 -m port_scanner --target webapp --ports 1-10000 --output json --outfile results.json
```

## Features
- TCP connect scanning with open/closed/filtered detection
- Banner grabbing and service fingerprinting
- Multi-threading (configurable, default 100 threads)
- CIDR subnet scanning
- JSON and CSV export
- Real-time progress and open port display

## Dependencies
Python 3.8+ (standard library only)