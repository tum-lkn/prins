import socket
import ssl
import sys
import threading
import time
import json
from jose import jws
from cryptography.hazmat.primitives import serialization
import helper_functions as hf
from helper_functions import logger

__all__ = ["IPX"]

class IPX:  # either vIPX or hIPX
    """ IP eXchange Provider (IPX) class for handling secure communication over the N32 roaming interface. Both vIPX and hIPX are implemented in this class. """

    def __init__(self, config=None, config_path=None, control_dict=None):
        """Initialize the IPX instance with configuration and shared resources."""
        self.control_dict = control_dict
        if config_path is not None:
            config = hf.get_config(config_path)

        self.config = config
        self.fqdn = config["fqdn"]
        self.host = config["ip"]
        self.port = config["port"]
        self.next_host = config["next_ip"]
        self.next_port = config["next_port"]
        self.certfile = config["certfile"]
        self.keyfile = config["keyfile"]
        self.cafile = config["cafile"]
        self.name = config["name"]
        self.mode = config["mode"]
        self.recv_sock = None  # Persistent receiving socket
        self.recv_ssock = None  # Secure receiving socket
        self.recv_conn = None  # Connection for receiving
        self.fwd_sock = None  # Persistent forwarding socket
        self.fwd_ssock = None  # Secure forwarding socket
        if self.mode in ["prins", "prins_details", "prins_tcp"]:
            # Load private key for IPX
            with open(config["IPX_private_key"], "rb") as key_file:
                self.private_key_ipx = serialization.load_pem_private_key(key_file.read(), password=None)
            # Load public key for IPX
            with open(config["IPX_public_key"], "rb") as key_file:
                self.public_key_ipx = serialization.load_pem_public_key(key_file.read())

    def create_recv_socket(self):
        """Create and maintain a persistent receiving socket."""
        # start = time.perf_counter()
        if self.recv_sock is not None:
            logger.info(f"[{self.name}] Receiving socket already exists. Reusing it.")
            if self.mode in ["e2e","prins","prins_details"] and self.recv_ssock is not None:
                logger.info(f"[{self.name}] Secure receiving socket already exists. Reusing it.")
                return
            return
        
        self.recv_sock = hf.create_server_socket(self.host, self.port)
        if self.mode in ["h2h","prins","prins_details"]:
            context = hf.create_context(self.certfile, self.keyfile, self.cafile, ssl.Purpose.CLIENT_AUTH)
            self.recv_ssock = context.wrap_socket(self.recv_sock, server_side=True)
        elif self.mode in ["base", "e2e","prins_tcp"]:
            self.recv_ssock = self.recv_sock
        logger.info(f"[{self.name}] Persistent receiving socket established on {self.host}:{self.port}.")
        # end = time.perf_counter()
        # logger.error(f"[{self.name}] Time taken to create receiving socket: {end - start:.4f} seconds")

    def create_fwd_socket(self):
        """Create and maintain a persistent forwarding socket."""
        # start = time.perf_counter()
        if self.fwd_sock is not None:
            logger.info(f"[{self.name}] Forwarding socket already exists. Reusing it.")
            if self.mode in ["h2h","prins","prins_details"] and self.fwd_ssock is not None:
                logger.info(f"[{self.name}] Secure forwarding socket already exists. Reusing it.")
                return
            return
        
        while not (hasattr(self, 'control_dict') and 
                    self.control_dict is not None and 
                    self.control_dict.get('shutdown', False)):
            try:
                self.fwd_sock = socket.create_connection((self.next_host, self.next_port))
                if self.mode in ["h2h","prins","prins_details"]:
                    context = hf.create_context(self.certfile, self.keyfile, self.cafile, ssl.Purpose.SERVER_AUTH)
                    self.fwd_ssock = context.wrap_socket(self.fwd_sock, server_hostname=self.next_host)
                    logger.info(f"[{self.name}] Persistent secure forwarding socket established to {self.next_host}:{self.next_port}.")
                elif self.mode in ["base", "e2e","prins_tcp"]:
                    self.fwd_ssock = self.fwd_sock
                    logger.info(f"[{self.name}] Persistent forwarding socket established to {self.next_host}:{self.next_port}.")
                break
            except (socket.error, ssl.SSLError) as e:
                logger.info(f"[{self.name}] Error creating forwarding socket: {e}. Retrying...")
                time.sleep(0.1)
        # end = time.perf_counter()
        # logger.error(f"[{self.name}] Time taken to create forwarding socket: {end - start:.4f} seconds")

    def close_sockets(self):
        """Close all persistent sockets."""
        if (hasattr(self, 'control_dict') and 
                    self.control_dict is not None and 
                    self.control_dict.get('shutdown', True)):
            if self.recv_ssock:
                hf.shutdown_all_sockets([self.recv_ssock])
                self.recv_ssock = None
            if self.recv_sock:
                hf.shutdown_all_sockets([self.recv_sock])
                self.recv_sock = None
            if self.fwd_ssock:
                hf.shutdown_all_sockets([self.fwd_ssock])
                self.fwd_ssock = None
            if self.fwd_sock:
                hf.shutdown_all_sockets([self.fwd_sock])
                self.fwd_sock = None
            logger.info(f"[{self.name}] All persistent sockets closed.")

    def forward(self, data):
        """Forward data using the persistent forwarding socket. Used in PRINS modes."""
        # start = time.perf_counter()
        if self.fwd_ssock is None or self.fwd_sock is None:
            logger.info(f"[{self.name}] Forwarding socket does not exist. Creating it.")
            self.create_fwd_socket()

        try:
            data = self.add_jws(data)
            logger.info(f"[{self.name}] Forwarding data to {self.next_host}:{self.next_port}.")
            self.fwd_ssock.sendall(data)
        except (socket.error, ssl.SSLError) as e:
            logger.info(f"[{self.name}] Error forwarding data: {e}. Reconnecting...")
            self.close_sockets()
            self.create_fwd_socket()
            self.forward(data)  # Retry forwarding the data
        # end = time.perf_counter()
        # logger.error(f"[{self.name}] PRINS Data forwarded in {end - start:.4f} seconds.")

    def _start_server(self):
        """Start the server for PRINS modes, base, and for h2h TLS (all except e2e)."""
        if self.recv_sock is None or self.recv_ssock is None:
            self.create_recv_socket()
        logger.info(f"[{self.name}] Server listening on {self.host}:{self.port}")
        if self.name == "hIPX":
            # hipx_ready_event.set()  # Signal that the server is ready
            if hasattr(self, 'control_dict'):
                self.control_dict['hipx_ready'] = True
        else:  # vIPX
            # vipx_ready_event.set()
            if hasattr(self, 'control_dict'):
                self.control_dict['vipx_ready'] = True
        
        # Accept initial connection
        while True:
            try:
                self.recv_conn, addr = self.recv_ssock.accept()
                logger.info(f"[{self.name}] Initial connection from {addr}")
                break
            except socket.timeout:
                time.sleep(0.1)
                continue
        
        try:
            while not (hasattr(self, 'control_dict') and 
                        self.control_dict is not None and 
                        self.control_dict.get('shutdown', False)):
                try:
                    # start = time.perf_counter()
                    data = self.recv_conn.recv(4096)
                    if not data:
                        if (hasattr(self, 'control_dict') and 
                            self.control_dict is not None and 
                            self.control_dict.get('shutdown', False)):
                            logger.info(f"[{self.name}] Simulation finished. Closing {self.name}. (no data)")
                            break
                        # logger.info(f"[{self.name}] Connection closed by peer. Waiting for new connection...")
                        self.recv_conn, addr = self.recv_ssock.accept()
                        logger.info(f"[{self.name}] New connection from {addr}")
                        continue
                    
                    logger.info(f"[{self.name}] Received: {data}")
                    if self.mode in ["prins", "prins_details", "prins_tcp"]:
                        self.forward(data)
                    else:  # h2h, base, etc.
                        if self.fwd_ssock is None:
                            self.create_fwd_socket()
                        logger.info(f"[{self.name}] Forwarding data to {self.next_host}:{self.next_port}.")
                        self.fwd_ssock.sendall(data)
                    # self.forward(data)
                    logger.info(f"[{self.name}] Data forwarded to {self.next_host}:{self.next_port}")
                    # end = time.perf_counter()
                    # logger.error(f"[{self.name}] Time taken to receive and forward: {end - start:.4f} seconds")
                except ssl.SSLError as e:
                    logger.info(f"[{self.name}] TLS handshake failed: {e}")
                except socket.timeout:
                    if (hasattr(self, 'control_dict') and 
                                self.control_dict is not None and 
                                self.control_dict.get('shutdown', True)): 
                        logger.info(f"[{self.name}] Simulation finished. Closing {self.name}.")
                        break
                    continue
                except Exception as e:
                    logger.info(f"[{self.name}] Unexpected error: {e}")
                    # self.recv_conn, addr = self.recv_ssock.accept()
                    # logger.info(f"[{self.name}] Reconnected from {addr}")
        finally:
            if self.recv_conn:
                hf.shutdown_all_sockets([self.recv_conn])
                self.recv_conn = None
            self.close_sockets()

    def handle_connection(self, type):
        """Handle bidirectional connection in e2e TLS mode."""
        if type == "recv":
            source = self.recv_conn
            destination = self.fwd_ssock
        elif type == "fwd":
            source = self.fwd_ssock
            destination = self.recv_conn
            
        # Continue processing messages until shutdown is requested
        while not (hasattr(self, 'control_dict') and 
                self.control_dict is not None and 
                self.control_dict.get('shutdown', False)):
            try:
                # start = time.perf_counter()
                if source is None or destination is None:
                    logger.info(f"[{self.name}] Source or destination socket is None. Exiting thread.")
                    return
                data = source.recv(4096)
                if not data:
                    return
                logger.info(f"[{self.name} {type}] Received data: {data}")
                destination.sendall(data)
                logger.info(f"[{self.name} {type}] Forwarded data to {self.next_host}:{self.next_port}")
                # end = time.perf_counter()
                # logger.error(f"[{self.name}] Time taken to receive and forward: {end - start:.4f} seconds")
            except (OSError, ConnectionResetError) as e:
                if (hasattr(self, 'control_dict') and 
                            self.control_dict is not None and 
                            self.control_dict.get('shutdown', True)): 
                    logger.info(f"[{self.name}] Simulation finished. Closing {self.name}.")
                    return
                logger.info(f"[{self.name}] Connection error: {e}")
                return
            except TimeoutError:
                if (hasattr(self, 'control_dict') and 
                            self.control_dict is not None and 
                            self.control_dict.get('shutdown', True)): 
                    logger.info(f"[{self.name}] Simulation finished. Closing {self.name}.")
                    return
                time.sleep(0.1)
                continue
            except Exception as e:
                logger.info(f"[{self.name}] Unexpected error: {e}")
                return

    def start_server(self):
        """Start the server based on the mode."""
        if self.mode in ["prins", "prins_details", "prins_tcp", "base", "h2h"]:
            self._start_server()
        elif self.mode in ["e2e"]:
            self.start_server_with_forwarding()
    
    def start_server_with_forwarding(self):
        """Start the server in e2e TLS mode with forwarding using persistent sockets."""
        # Create persistent receiving and forwarding sockets
        if self.recv_sock is None or self.recv_ssock is None:
            self.create_recv_socket()

        logger.info(f"[{self.name}] Server listening on {self.host}:{self.port}, forwarding to {self.next_host}:{self.next_port}")
        if self.name == "hIPX":
            # hipx_ready_event.set()  # Signal that the server is ready
            if hasattr(self, 'control_dict'):
                self.control_dict['hipx_ready'] = True
        else:  # vIPX
            # vipx_ready_event.set()
            if hasattr(self, 'control_dict'):
                self.control_dict['vipx_ready'] = True

        while True:
            try:
                self.recv_conn, addr = self.recv_ssock.accept()
                logger.info(f"[{self.name}] Connection from {addr}")
                if self.fwd_sock is None or self.fwd_ssock is None:
                    self.create_fwd_socket()
                if self.recv_conn and self.fwd_ssock:
                    logger.info(f"[{self.name}] Connection established. Starting bidirectional communication.")
                break
            except TimeoutError:
                if (hasattr(self, 'control_dict') and 
                            self.control_dict is not None and 
                            self.control_dict.get('shutdown', False)): 
                    logger.info(f"[{self.name}] Simulation finished. Closing {self.name}.")
                    break
                continue
            except Exception as e:
                logger.info(f"[{self.name}] Error accepting connection: {e}")
                break
        
        try: 
            while not (hasattr(self, 'control_dict') and 
                        self.control_dict is not None and 
                        self.control_dict.get('shutdown', False)):
                try:
                    # start = time.perf_counter()
                    if self.mode in ["h2h","base"]:
                        self.handle_connection("recv")
                    else: # e2e
                        # Start threads for bidirectional communication
                        recv_to_fwd_thread = threading.Thread(target=self.handle_connection, args=("recv",))
                        fwd_to_recv_thread = threading.Thread(target=self.handle_connection, args=("fwd",))

                        recv_to_fwd_thread.start()
                        fwd_to_recv_thread.start()

                        # Wait for threads to finish
                        try:
                            recv_to_fwd_thread.join()
                            fwd_to_recv_thread.join()
                        except KeyboardInterrupt:
                            logger.info(f"[{self.name}] KeyboardInterrupt received. Stopping server.")
                            if hasattr(self, 'control_dict'):
                                self.control_dict.set('shutdown', True)
                    
                    # end = time.perf_counter()
                    # logger.error(f"[{self.name}] Time taken e2e server: {end - start:.4f} seconds")
                except ssl.SSLError as e:
                    logger.info(f"[{self.name}] TLS handshake failed: {e}")
                except socket.timeout:
                    if (hasattr(self, 'control_dict') and 
                                self.control_dict is not None and 
                                self.control_dict.get('shutdown', True)):
                        logger.info(f"[{self.name}] Simulation finished. Closing {self.name}.")
                        break
                    continue
                except Exception as e:
                    logger.info(f"[{self.name}] Unexpected error: {e}")
                    break
        finally:
            if self.recv_conn:
                hf.shutdown_all_sockets([self.recv_conn])
                self.recv_conn = None
        # Close all persistent sockets when the server stops
        self.close_sockets()

    def define_modifications(self, aad):
        """Define modifications to be added to the packet's payload."""
        # TODO: add logic to define modifications (which parts of aad to modify)
        # For now, we just add a new field to aad (good idea, but no)
        # For now we just copy the complete aad field and add it again as the new modification field
        # operations = aad
        # modifications = {"signature": f"Added by {self.name}", "modifications": aad}
        logger.info(f"[{self.name}] Modifications to add: {aad}")
        payload = {"operations": aad, "identity": self.fqdn} # TODO: change FQDN to URI if necessary
        return payload

    def add_jws(self, payload):
        payload = json.loads(payload.decode())
        reformattedData = payload["reformattedData"]
        if "modificationsBlock" in payload:
            modificationsBlock = payload["modificationsBlock"][0]
        else:
            logger.info(f"[{self.name}] No ModificationsBlock, so no IPX is allowed to do changes. Packet is forwarded without changes.")
            # logger.info(f"[{self.name}] modificationsBlock: {modificationsBlock}")
            return json.dumps(payload).encode() 

        aad = hf.base64url_decode_json(reformattedData["aad"])

        allowed = self.check_for_allowance(aad["metaData"])
        if not allowed:
            logger.info(f"[{self.name}] This IPX is not allowed to do changes. Packet is forwarded without changes.")
            return json.dumps(payload).encode() 
        else:
            # if next IPX is allowed to do changes, we add the IPX ID to the aad
            if self.config["next_allowed_ipx"]:
                aad["metaData"]["authorizedIpxId"] = self.config["next_allowed_ipx"]
                # else leave the field as is

        modifications = self.define_modifications(aad["payload"])
        # logger.info(f"[{self.name}] Private key: {self.private_key_ipx}")
        jws_ipx = jws.sign(modifications, self.private_key_ipx, algorithm="ES256")
        # testing
        pt1 = jws_ipx.split(".")[0]
        pt2 = jws_ipx.split(".")[1]
        pt3 = jws_ipx.split(".")[2]
        logger.info(f"[{self.name}] JWS parts. Header: {hf.base64url_decode_json(pt1)}, Modifications payload: {hf.base64url_decode_json(pt2)}, Signature: {pt3}")
        # testing

        if modificationsBlock: 
            # if there is already an entry by vIPX, this adds an entry as an hIPX
            send_ipx = json.dumps({
                "reformattedData": {
                    "ciphertext": reformattedData["ciphertext"], 
                    "aad": hf.base64url_encode_json(aad)
                    }, 
                "modificationsBlock": [
                    modificationsBlock, 
                    jws_ipx
                    ]
                })
        else:
            # if there is no entry yet, add the first one
            send_ipx = json.dumps({
                "reformattedData": {
                    "ciphertext": reformattedData["ciphertext"], 
                    "aad": hf.base64url_encode_json(aad)
                    }, 
                "modificationsBlock": [
                    jws_ipx
                    ]
                })
        logger.info(f"[{self.name}] JWS to send: {send_ipx}")
        return send_ipx.encode()
    
    def check_for_allowance(self, metaData):
        if metaData["authorizedIpxId"] == self.fqdn:
            logger.info(f"[{self.name}] IPX is allowed to do changes.")
            return True
        else:
            logger.info(f"[{self.name}] IPX is not allowed to do changes.")
            return False

if __name__ == "__main__":
    name = sys.argv[1] if len(sys.argv) > 1 else "vIPX"
    if name == "vIPX" or name == "vipx" or name == "v":
        vipx_config = hf.get_config("configs/mininet/vipx_config.json")
        vipx = IPX(vipx_config)
        vipx.start_server()
        logger.info(f"[{vipx.name}] Server is ready.")
    # Initialize hIPX
    if name == "hIPX" or name == "hipx" or name == "h":
        hipx_config = hf.get_config("configs/mininet/hipx_config.json")
        hipx = IPX(hipx_config)
        hipx.start_server()
        logger.info(f"[{hipx.name}] Server is ready.")