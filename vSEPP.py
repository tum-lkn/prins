import socket
import ssl
import time
import json
from jose import jwe
import helper_functions as hf
from helper_functions import logger

__all__ = ["vSEPP"]

class vSEPP:
    """visited SEPP (vSEPP) class for handling secure communication over the N32 roaming interface. (sending)"""

    def __init__(self, config=None, config_path=None, shared_dict=None, control_dict=None): 
        """Initialize the vSEPP instance with configuration and shared resources."""
        self.shared_dict = shared_dict
        self.control_dict = control_dict

        if config_path is not None:
            config = hf.get_config(config_path)

        self.config = config
        self.host = config["ip"]
        self.port = config["port"]
        self.next_host = config["next_ip"]
        self.next_port = config["next_port"]
        self.dst_host = config["dst_ip"]
        self.dst_port = config["dst_port"]
        self.certfile = config["certfile"]
        self.keyfile = config["keyfile"]
        self.cafile = config["cafile"]
        self.prins_shared_key = hf.derive_shared_key_from_shared_secret()
        self.start = []
        self.name = config["name"]
        self.mode = config["mode"]
        self.sock = None  # Persistent socket
        self.ssock = None  # Secure socket

    def start_server(self):
        """Start the server to listen for incoming connections and handle payloads."""
        server_socket = hf.create_server_socket(self.host, self.port)
        logger.info(f"[{self.name}] Server listening on {self.host}:{self.port}")
        if hasattr(self, 'control_dict'):
            self.control_dict['vsepp_ready'] = True
        conn = None

        while not (hasattr(self, 'control_dict') and 
                    self.control_dict is not None and 
                    self.control_dict.get('shutdown', False)):
            try:
                # start = time.perf_counter()
                conn, addr = server_socket.accept()
                logger.info(f"[{self.name}] Connection from NF at {addr} established.")
                data = conn.recv(4096)
                if data:
                    logger.info(f"[{self.name}] Received payload from NF: {data.decode()}")
                    self.send_payload(data.decode())
                # end = time.perf_counter()
                # logger.error(f"[{self.name}] Time taken to receive payload: {end - start:.4f} seconds")
            except ssl.SSLError as e:
                logger.info(f"[{self.name}] TLS handshake failed: {e}")
            except socket.timeout:
                if (hasattr(self, 'control_dict') and 
                            self.control_dict is not None and 
                            self.control_dict.get('shutdown', False)):
                    logger.info(f"[{self.name}] Simulation finished. Closing {self.name}.")
                    break
                continue
            except Exception as e:
                logger.info(f"[{self.name}] Unexpected error: {e}")
                break
            finally:
                if conn:
                    hf.shutdown_all_sockets([conn])
                    conn = None
        # hf.shutdown_all_sockets([conn])
        # hf.shutdown_all_sockets([server_socket])
        self.close_persistent_socket()

    def create_persistent_socket(self):
        """Create and maintain a persistent socket connection."""
        # start = time.perf_counter()
        if self.sock is not None and self.ssock is not None:
            logger.info(f"[{self.name}] Socket already exists. Reusing it.")
            return
        logger.info(f"[{self.name}] Creating persistent socket connection to {self.next_host}:{self.next_port}")
        
        while not (hasattr(self, 'control_dict') and 
                    self.control_dict is not None and 
                    self.control_dict.get('shutdown', False)):
            try:
                self.sock = socket.create_connection((self.next_host, self.next_port))
                if self.mode in ["h2h", "prins", "prins_details"]:
                    context = hf.create_context(self.certfile, self.keyfile, self.cafile, ssl.Purpose.SERVER_AUTH)
                    logger.info(f"[{self.name}] Creating TLS connection to {self.next_host}:{self.next_port}")
                    self.ssock = context.wrap_socket(self.sock, server_hostname=self.next_host)
                elif self.mode in ["base", "prins_tcp"]:
                    logger.info(f"[{self.name}] Creating TCP connection to {self.next_host}:{self.next_port}")
                    self.ssock = self.sock
                else: # e2e
                    context = hf.create_context(self.certfile, self.keyfile, self.cafile, ssl.Purpose.SERVER_AUTH)
                    logger.info(f"[{self.name}] Creating TLS connection to {self.dst_host}:{self.dst_port}")
                    self.ssock = context.wrap_socket(self.sock, server_hostname=self.dst_host)
                logger.info(f"[{self.name}] Persistent connection established.")
                break
            except ssl.SSLError as e:
                logger.error(f"[{self.name}] SSL Error wrapping socket: {e}")
                raise
            except Exception as e:
                logger.error(f"[{self.name}] Error wrapping socket: {e}")
                raise
        # end = time.perf_counter()
        # logger.error(f"[{self.name}] Time taken to create persistent socket: {end - start:.4f} seconds")

    def close_persistent_socket(self):
        """Close the persistent socket connection."""
        if (hasattr(self, 'control_dict') and 
                    self.control_dict is not None and 
                    self.control_dict.get('shutdown', True)):  # Only close sockets if the simulation is stopping
            if self.ssock:
                hf.shutdown_all_sockets([self.ssock])
                self.ssock = None
            if self.sock:
                hf.shutdown_all_sockets([self.sock])
                self.sock = None
            logger.info(f"[{self.name}] Persistent socket closed.")

    def send_payload(self, payload):
        """Send payload using the persistent socket."""
        if hasattr(self, 'shared_dict') and self.shared_dict is not None:
            start_time = time.perf_counter()
            
            # Record based on whether this is cold or warm start
            if not self.shared_dict.get('cold_complete', False):
                self.shared_dict['vsepp_start_cold'] = start_time
                logger.info(f"[{self.name}] Recorded cold start start time: {start_time}")
            elif self.control_dict.get('perform_warm', False):
                self.shared_dict['vsepp_start_warm'] = start_time
                logger.info(f"[{self.name}] Recorded warm start start time: {start_time}")
        # self.start.append(time.perf_counter())
        # logger.info(f"[{self.name}] Start time: {self.start[-1]}")
        ### here is the old place:
        if self.sock is None:
            self.create_persistent_socket()
        
        try:
            if self.mode in ["prins", "prins_details", "prins_tcp"]:
                payload = self.prins_get_payload(payload)
            elif self.mode in ["h2h", "base", "e2e"]:
                payload = json.loads(payload)
                payload = {"ciphertext": hf.base64url_encode_json(payload["ciphertext"]), "aad": hf.base64url_encode_json(payload["aad"])}
                payload = json.dumps(payload)
                # payload = hf.base64url_encode_json(payload)
            logger.info(f"[{self.name}] Sending payload: {payload}")
            self.ssock.sendall(payload.encode())
            logger.info(f"[{self.name}] Payload sent successfully.")
        except (socket.error, ssl.SSLError) as e:
            logger.info(f"[{self.name}] Error sending payload: {e}. Reconnecting...")
            # self.close_persistent_socket()
            # self.create_persistent_socket()
            self.send_payload(payload)  # Retry sending the payload
        except Exception as e:
            logger.info(f"[{self.name}] Unexpected error: {e}")
        # end = time.perf_counter()
        # logger.error(f"[{self.name}] Time taken to send payload: {end - self.start[-1]:.4f} seconds")
    
    def prins_get_payload(self, payload="Hello from vSEPP!"):
        """Encrypt the payload using PRINS mode and return the formatted payload."""
        ### PRINS mode ###
        # start = time.perf_counter()
        payload = json.loads(payload)
        unencrypted_ciphertext = payload["ciphertext"]
        logger.info(f"[{self.name}] Payload to encrypt: {unencrypted_ciphertext}")
        encrypted_ciphertext = jwe.encrypt(json.dumps(unencrypted_ciphertext), self.prins_shared_key)
        logger.info(f"[{self.name}] Encrypted Payload: {encrypted_ciphertext}")

        # if "aad" not in payload: # TODO: check if this is needed
        # in the end, the NF will never send aad and the vSEPP has to define it based on some measures
        # -> the split between ciphertext and aad is done at the SEPP (but in this simulation not yet -> simplification)

        if payload["aad"] is None:
            send_payload = {
                "reformattedData": {
                    "ciphertext": hf.base64url_encode(encrypted_ciphertext),
                    "aad": None
                }
            }
            return json.dumps(send_payload)

        send_payload = self.reformat_payload(encrypted_ciphertext, payload["aad"],addModificationsBlock=True)

        logger.info(f"[{self.name}] Encrypted Payload: {send_payload}")
        # end = time.perf_counter()
        # logger.info(f"[{self.name}] Time taken to encrypt prins payload: {end - start:.4f} seconds")
        return send_payload
    
    def reformat_payload(self, ciphertext, unencrypted_payload,addModificationsBlock=False):
        """Reformat the payload for PRINS mode."""
        ### PRINS mode ###
        contextId = self.getcontextId()
        messageId = self.getmessageId()
        authorizedIpxId = self.getauthorizedIpxId()
        metadata = {
            "n32fContextId": contextId,
            "messageId": messageId,
            "authorizedIpxId": authorizedIpxId
        }
        aad = {
            "metaData": metadata,
            "payload": unencrypted_payload,
        }
        logger.info(f"[{self.name}] AAD: {aad}")
        if addModificationsBlock:
            payload = {
                "reformattedData": {
                    "ciphertext": hf.base64url_encode(ciphertext),
                    "aad": hf.base64url_encode_json(aad)
                },
                "modificationsBlock": [None]
            }
        else:
            payload = {
                "reformattedData": {
                    "ciphertext": ciphertext,
                    "aad": aad
                }
            }
        return json.dumps(payload)
    
    def getcontextId(self):
        """Generate a context ID for the payload."""
        return "0600AD1855BD6007"  # Placeholder for context ID generation
    def getmessageId(self):
        """Generate a message ID for the payload."""
        return "060ad1855bd6007" # Placeholder for message ID generation
    def getauthorizedIpxId(self):
        """Get the authorized IPX ID from the configuration."""
        if isinstance(self.config["authorizedIpxId"], list):
            return self.config["authorizedIpxId"][0]
        if isinstance(self.config["authorizedIpxId"], str):
            return [self.config["authorizedIpxId"]]
        else:
            logger.info(f"[{self.name}] Error: authorizedIpxId is not a list or string")
            return None

if __name__ == "__main__":
    vsepp_config = hf.get_config("configs/mininet/vsepp_config.json")
    vsepp = vSEPP(vsepp_config)
    vsepp.start_server()
    logger.info(f"[{vsepp.name}] Server is ready.")