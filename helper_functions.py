import socket
import ssl
import threading
import sys
import json
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.hashes import SHA256
import logging
import base64

logging.basicConfig(level=logging.ERROR, format='[%(levelname)s] %(message)s')
logger = logging.getLogger("shared logger")

### Base64 URL Safe Encoding and Decoding Functions
# These functions are essential for securely transmitting structured data over the network in a format that is both compact and safe for URLs.
def base64url_encode(data):
    return base64.urlsafe_b64encode(data).rstrip(b'=').decode('utf-8')

def base64url_decode(data):
    padding = '=' * (4 - (len(data) % 4)) if len(data) % 4 != 0 else ''
    return base64.urlsafe_b64decode(data + padding)

def base64url_encode_json(data):
    return base64url_encode(json.dumps(data).encode('utf-8'))

def base64url_decode_json(data):
    return json.loads(base64url_decode(data).decode('utf-8'))

def create_server_socket(host, port):
    """Create a TCP server socket with specified host and port."""
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_socket.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    server_socket.settimeout(0.2)
    server_socket.bind((host, port))
    server_socket.listen(5)
    return server_socket

# shutdown_all_sockets is a helper function that takes a list of sockets and attempts to shut them down gracefully.
def shutdown_all_sockets(sockets):
    """Helper function to shut down and close a list of sockets."""
    for sock in sockets:
        if sock:
            try:
                sock.shutdown(socket.SHUT_RDWR)
                sock.close()
            except OSError:
                pass

def create_context(certfile, keyfile, cafile, purpose):
    """Create an SSL context for secure communication."""
    context = ssl.create_default_context(purpose)
    context.load_cert_chain(certfile=certfile, keyfile=keyfile)
    context.load_verify_locations(cafile=cafile)
    # context.check_hostname = False        # in the case of mininet, it currently only works with this
    # context.verify_mode = ssl.CERT_NONE  # in the case of mininet, it currently only works with this
    context.verify_mode = ssl.CERT_REQUIRED
    return context

def derive_shared_key_from_shared_secret(shared_secret=b"shared_secret_for_csepp_psepp"):
    """Derive a shared symmetric key from a shared secret using HKDF."""
    return HKDF(
        algorithm=SHA256(),
        length=32,
        salt=None,
        info=b"5G-PRINS",
    ).derive(shared_secret)

def get_config(config_file):
    """Read and parse the JSON configuration file."""
    try:
        with open(config_file, 'r') as file:
            config = json.load(file)
            return config
    except FileNotFoundError:
        logger.error(f"Configuration file {config_file} not found.")
        sys.exit(1)
    except json.JSONDecodeError:
        logger.error(f"Error decoding JSON from configuration file {config_file}.")
        sys.exit(1)
