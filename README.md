# PRINS - Performance and Security Analysis of 5G Roaming

A comprehensive simulation framework for analyzing performance and security aspects of 5G roaming interfaces, implementing various communication modes including PRINS (PRotocol for N32 INterconnect Security).
It was developed for the IEEE CNS 2025 Paper titled "Performance Evaluation of 5G Roaming Security based on PRINS". The link to IEEE eXplore will follow once it is available.

## Overview

This repository contains a Python-based simulation framework that models the N32 roaming interface in 5G networks, focusing on different security and performance modes. The framework implements various components of the roaming architecture including SEPPs (Security Edge Protection Proxies) and IPX (IP Exchange) providers.

## Architecture

The simulation framework consists of four main components:

- **vSEPP** (Visiting SEPP): Handles outgoing communication and payload encryption
- **vIPX** (Visiting IPX): Intermediate proxy for traffic modification and forwarding
- **hIPX** (Home IPX): Home network proxy for traffic processing
- **hSEPP** (Home SEPP): Receives and validates incoming communication

## Supported Communication Modes

1. **base**: Basic unencrypted communication
2. **e2e**: End-to-end TLS encryption
3. **h2h**: Hop-by-hop TLS encryption
4. **prins**: PRINS protocol with JWS (JSON Web Signature) modifications
5. **prins_tcp**: PRINS over TCP without TLS

## Key Features

- **Multi-process Architecture**: Each component runs in its own process for isolation
- **CPU Core Pinning**: Intelligent CPU core assignment for performance optimization
- **Dynamic Port Management**: Automatic port cleanup and allocation
- **Flexible Configuration**: JSON-based configuration for different network scenarios
- **Performance Monitoring**: Built-in timing and performance measurement
- **Network Capture**: Optional tshark integration for packet analysis
- **Retry Mechanisms**: Robust error handling and retry logic

## Installation

### Prerequisites

- Python 3.7+
- Required Python packages:
  ```bash
  pip install cryptography psutil python-jose
  ```
- System tools:
  ```bash
  sudo apt-get install tshark netstat lsof
  ```
- Clone the repository:
   ```bash
   git clone https://github.com/tum-lkn/prins.git
   ```


## Usage

### Basic Simulation

Run a single simulation:
```bash
python3 main.py <mode> <message_type>
```

Example:
```bash
python3 main.py prins large_even
```

### Batch Testing

Use the runner for comprehensive testing:
```bash
python3 runner.py
```

The runner supports:
- Multiple modes and message types
- CPU core pinning for performance isolation
- Automatic retry mechanisms
- Optional network packet capture

### Configuration

Configure components using JSON files in the `configs/` directory:
- `vsepp_config.json`: vSEPP configuration
- `vipx_config.json`: vIPX configuration
- `hipx_config.json`: hIPX configuration
- `hsepp_config.json`: hSEPP configuration

## Performance Optimization

### CPU Core Pinning

The framework automatically assigns components to dedicated CPU cores:
- **Core 0**: Runner process
- **Core 1**: Main orchestration process
- **Core 2+**: Individual components (vSEPP, vIPX, hIPX, hSEPP)

This ensures performance isolation and reduces interference between components.

### Memory Management

- Uses multiprocessing with shared memory for inter-process communication
- Implements proper cleanup mechanisms for processes and sockets
- Supports both cold and warm start scenarios

## Message Types

The framework supports various message sizes and structures:
- `small_*`: Small payload messages (117 Byte)
- `middle_*`: Medium payload messages (442 Byte) 
- `large_*`: Large payload messages (718 Byte)
- `*_aad`: Messages with large unencrypted AAD payload
- `*_ciphertext`: Messages with large encrypted payload
- `*_even`: Messages with balanced AAD and ciphertext

## Security Features

### PRINS Protocol Implementation

- **JWS Integration**: JSON Web Signature for message integrity
- **Key Management**: Cryptographic key handling and validation
- **Modification Tracking**: Secure logging of message modifications
- **IPX Authorization**: Fine-grained control over which IPX can modify messages

### TLS Support

- **End-to-End**: Full encryption between endpoints
- **Hop-by-Hop**: Encryption between each component pair
- **Certificate Management**: Automated certificate handling

## Monitoring and Analysis

### Network Analysis

- Message processing latency
- Optional tshark packet capture
- Traffic flow analysis
- Protocol-level debugging

## Development

### Project Structure

```
prins/
├── runner.py            # Runner script for test-run execution
├── main.py              # Main orchestration
├── vSEPP.py             # Visited SEPP implementation
├── hSEPP.py             # Home SEPP implementation
├── IPX.py               # IPX provider implementation
├── helper_functions.py  # Utility functions
├── configs/             # Configuration files
├── msgs/                # Test messages
├── results/             # Delay measurement results
└── captures/            # Wireshark captures
```

### Adding New Modes

1. Implement mode logic in relevant component files
2. Add configuration parameters
3. Update the main orchestration logic
4. Test with various message types

## Contact

oliver.zeidler@tum.de

## Acknowledgments

This work is part of research into 5G roaming security and performance optimization, with a focus on the N32-f interface and the PRINS protocol.