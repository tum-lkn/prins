import socket
import ssl
import time
import json
from jose import jwe, jws
from cryptography.hazmat.primitives import serialization
import helper_functions as hf
from helper_functions import logger

__all__ = ["hSEPP"]

class hSEPP:
    """ home SEPP (hSEPP) handling secure communication over the N32 roaming interface. (receiving; validating) """

    def __init__(self, config=None, config_path=None, shared_dict=None, control_dict=None):
        """Initialize the hSEPP instance with configuration and shared resources."""
        self.shared_dict = shared_dict
        self.control_dict = control_dict

        if config_path is not None:
            config = hf.get_config(config_path)

        self.config = config
        self.host = config["ip"]
        self.port = config["port"]
        self.certfile = config["certfile"]
        self.keyfile = config["keyfile"]
        self.cafile = config["cafile"]
        self.prins_shared_key = hf.derive_shared_key_from_shared_secret()
        self.end = []
        self.name = config["name"]
        self.mode = config["mode"]
        self.key_list = []
        self.sock = None  # Persistent socket
        self.ssock = None  # Secure socket

        if self.mode in ["prins", "prins_details", "prins_tcp"]:
            # pre-load all the keys for the authorized IPXs
            # saves ~2ms per packet
            for i in range(len(config["authorizedIpxList"])):
                logger.info(f"[{self.name}][__init__] Authorized IPX ID: {config['authorizedIpxList'][i].get('ipxId')}")
                logger.info(f"[{self.name}][__init__] Authorized IPX key: {config['authorizedIpxList'][i].get('publicKey')}")
                with open(config["authorizedIpxList"][i]["publicKey"], "rb") as key_file:
                    self.key_list.append(serialization.load_pem_public_key(key_file.read()))

    def create_persistent_socket(self):
        """Create and maintain a persistent socket connection."""
        # start = time.perf_counter()
        if self.sock is not None and self.ssock is not None:
            logger.info(f"[{self.name}] Socket already exists. Reusing it.")
            return
        
        while not (hasattr(self, 'control_dict') and 
                    self.control_dict is not None and 
                    self.control_dict.get('shutdown', False)):
            try:
                self.sock = hf.create_server_socket(self.host, self.port)
                if self.mode in ["e2e", "h2h", "prins", "prins_details"]:
                    context = hf.create_context(self.certfile, self.keyfile, self.cafile, ssl.Purpose.CLIENT_AUTH)
                    logger.info(f"[{self.name}] Creating persistent secure socket connection to {self.host}:{self.port}")
                    self.ssock = context.wrap_socket(self.sock, server_side=True)
                elif self.mode in ["base", "prins_tcp"]:
                    logger.info(f"[{self.name}] Creating persistent socket connection to {self.host}:{self.port}")
                    self.ssock = self.sock
                logger.info(f"[{self.name}] Persistent socket established on {self.host}:{self.port}.")
                break
            except (socket.error, ssl.SSLError) as e:
                logger.info(f"[{self.name}] Error creating persistent socket: {e}. Retrying...")
                time.sleep(0.1)
        # end = time.perf_counter()
        # logger.error(f"[{self.name}] Time taken to create persistent socket: {end - start:.4f} seconds")

    def close_persistent_socket(self):
        """Close the persistent socket connection."""
        # Only close sockets if the simulation is stopping
        if (hasattr(self, 'control_dict') and 
                    self.control_dict is not None and 
                    self.control_dict.get('shutdown', True)):
            if self.ssock:
                hf.shutdown_all_sockets([self.ssock])
                self.ssock = None
            if self.sock:
                hf.shutdown_all_sockets([self.sock])
                self.sock = None
            logger.info(f"[{self.name}] Persistent socket closed.")

    def start_server(self):
        """Start the server using the persistent socket."""
        self.create_persistent_socket()
        
        if hasattr(self, 'control_dict'):
            self.control_dict['hsepp_ready'] = True

        conn = None
        # Accept a connection from the persistent socket
        while True:
            try:
                conn, addr = self.ssock.accept()
                logger.info(f"[{self.name}] Connection from {addr}")
                if conn:
                    break
            except TimeoutError:
                if (hasattr(self, 'control_dict') and 
                            self.control_dict is not None and 
                            self.control_dict.get('shutdown', False)):
                    logger.info(f"[{self.name}] Simulation finished. Closing {self.name}.")
                    return
                continue
            except Exception as e:
                logger.info(f"[{self.name}] Error accepting connection: {e}")
                return

        try:
            while not (hasattr(self, 'control_dict') and 
                        self.control_dict is not None and 
                        self.control_dict.get('shutdown', False)):
                try:
                    # start = time.perf_counter()
                    # Receive data from the client
                    data = conn.recv(4096)
                    if data:
                        logger.info(f"[{self.name}] Received data: {data}")
                        if self.mode in ["base", "e2e", "h2h"]:
                            data = json.loads(data.decode())
                            ciphertext = hf.base64url_decode_json(data["ciphertext"])
                            aad = hf.base64url_decode_json(data["aad"])
                            data = json.dumps({"ciphertext": ciphertext, "aad": aad})
                            # data = hf.base64url_decode_json(data.decode())
                        elif self.mode in ["prins", "prins_details", "prins_tcp"]:
                            data = self.handle_incoming_prins(data)

                        if data is None:
                            logger.info(f"[{self.name}] Data decryption failed. Dropping packet.")
                            continue

                        if hasattr(self, 'shared_dict') and self.shared_dict is not None:
                            end_time = time.perf_counter()
                            
                            # Record based on whether this is cold or warm start
                            if not self.shared_dict.get('cold_complete', False):
                                self.shared_dict['hsepp_end_cold'] = end_time
                                self.shared_dict['cold_complete'] = True
                                logger.info(f"[{self.name}] Recorded cold start end time: {end_time}")
                            elif self.control_dict.get('perform_warm', False):
                                self.shared_dict['hsepp_end_warm'] = end_time
                                self.shared_dict['warm_complete'] = True
                                logger.info(f"[{self.name}] Recorded warm start end time: {end_time}")

                    # end = time.perf_counter()
                    # logger.error(f"[{self.name}] Time taken to process data: {end - start:.4f} seconds")
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
        finally:
            if conn:
                hf.shutdown_all_sockets([conn])
        # hf.shutdown_all_sockets([conn])
        self.close_persistent_socket()

    def handle_incoming_prins(self, payload):
        """Handle incoming PRINS payloads."""
        # start = time.perf_counter()
        payload = json.loads(payload.decode())
        reformattedData = payload["reformattedData"]
        logger.info(f"[{self.name}][handle_incoming_prins] Received Payload: {payload}")
        ciphertext = hf.base64url_decode(reformattedData["ciphertext"])
        # Decrypt ciphertext at hSEPP
        decrypted_ciphertext = jwe.decrypt(ciphertext, self.prins_shared_key).decode()
        logger.info(f"[{self.name}][handle_incoming_prins] Decrypted ciphertext: {decrypted_ciphertext}")

        if reformattedData["aad"] is None:
            logger.info(f"[{self.name}][handle_incoming_prins] No AAD found. Returning only decrypted vSEPP payload.")
            json_payload = {"ciphertext": decrypted_ciphertext, "aad": None} # placeholder for this simulation scenario
            logger.info(f"[{self.name}][handle_incoming_prins] Final Decrypted Payload at {self.name}: {json_payload}")
            return json_payload
        aad = hf.base64url_decode_json(reformattedData["aad"])

        if "modificationsBlock" not in payload:
            logger.info(f"[{self.name}][handle_incoming_prins] No modificationsBlock found. Returning original vSEPP payload.")
            json_payload = {"ciphertext": decrypted_ciphertext, "aad": aad}
            logger.info(f"[{self.name}][handle_incoming_prins] Final Decrypted Payload at {self.name}: {json_payload}")
            return json_payload
        
        # modificationsBlock is present
        aad = self.handle_modifications(aad["payload"], payload["modificationsBlock"])
        logger.info(f"[{self.name}][handle_incoming_prins] Modified Payload: {aad}")
        json_payload = {"ciphertext": decrypted_ciphertext, "aad": aad}
        logger.info(f"[{self.name}][handle_incoming_prins] Final Decrypted Payload at {self.name}: {json_payload}")
        # end = time.perf_counter()
        # logger.error(f"[{self.name}][handle_incoming_prins] Time taken to process data: {end - start:.4f} seconds")
        return json_payload
    
    def handle_modifications(self, aad, modificationsBlock):
        """ Handles modifications for a variable number of IPXs where IPX identities and keys are handled automatically. """
        logger.info(f"[{self.name}][handle_modifications] Modifications Block: {modificationsBlock}")
        logger.info(f"[{self.name}][handle_modifications] AAD: {aad}")
        for i in range(len(modificationsBlock)):
            authorizedIpxId = json.loads(hf.base64url_decode(modificationsBlock[i].split(".")[1]))["identity"]
            alg = json.loads(hf.base64url_decode(modificationsBlock[i].split(".")[0]))["alg"]
            # TODO: to support different algorithms, the key has to be different
            logger.info(f"[{self.name}][handle_modifications] Algorithm: {alg}")
            for j, d in enumerate(self.config["authorizedIpxList"]):
                # logger.info(f"[{self.name}][handle_modifications] Authorized IPX ID: {d.get('ipxId')} == {authorizedIpxId}")
                if d.get("ipxId") == authorizedIpxId:
                    logger.info(f"[{self.name}][handle_modifications] Authorized IPX ID: {authorizedIpxId}")
                    public_key = self.key_list[j]
                    verified_metadata = self.verify_jws(modificationsBlock[i], public_key, alg)
                    logger.info(f"[{self.name}][handle_modifications] Verified Metadata: {verified_metadata}")
                    aad = self.apply_modifications(aad, verified_metadata)
                    break
        return aad
                    # break
    
    def verify_jws(self, signature, public_key, alg):
        """ verify and check signature of one IPX. """
        # TODO: also check different algorithms (then also the keys have to be different) (ES256, ES384, ES512, HS256, HS384, HS512)
        try:
            verified_metadata = jws.verify(signature, public_key, algorithms=alg)
            verified_metadata = json.loads(verified_metadata.decode())
            logger.info(f"[{self.name}][verify_jws] Verified Metadata: {verified_metadata}")
            return verified_metadata["operations"]
        except jws.JWSError as e:
            logger.error(f"[{self.name}][verify_jws] JWS signature verification failed: {e}")
            return None
        except Exception as e:
            logger.error(f"[{self.name}][verify_jws] JWS verification failed: {e}")
            return None
        
    def apply_modifications(self, payload, modifications):
        """ Apply modifications to the payload based on the modifications dictionary. """
        # payload is original aad (json)
        # ipx_modifications is a dictionary with the modifications (coming from a json) from one IPX
        if modifications is None:
            logger.info(f"[{self.name}][apply_modifications] No modifications found. Returning original payload.")
            return payload
        logger.info(f"[{self.name}][apply_modifications] Applying modifications: {modifications}")
        for key, value in modifications.items():
            if payload[key].__class__ == list and modifications[key][0].__class__ == dict: # works for all 3 large msgs, but may be not for all other cases
                for key2, value2 in modifications[key][0].items():
                    if payload[key][0][key2].__class__ == list and modifications[key][0][key2][0].__class__ == dict:
                        for key3, value3 in modifications[key][0][key2][0].items():
                            payload[key][0][key2][0][key3] = value3
                            logger.info(f"[{self.name}][apply_modifications] Modification List: {key}|{key2}|{key3} -> {value3}")
                            # logger.info(f"[{self.name}] Modification List: {key}|{key2} -> {value}")
                    elif payload[key][0][key2].__class__ == list and modifications[key][0][key2][0].__class__ == str:
                        for i in range(len(modifications[key][0][key2])):
                            payload[key][0][key2][i] = value2[i]
                            logger.info(f"[{self.name}][apply_modifications] Modification List: {key}|{key2}[{i}] -> {value2[i]}")
                    else:
                        payload[key][0][key2] = value2
                        logger.info(f"[{self.name}][apply_modifications] Modification List: {key}|{key2} -> {value2}")
            elif payload[key].__class__ == list and modifications[key][0].__class__ == str:
                for i in range(len(modifications[key])):
                    payload[key][i] = value[i]
                    logger.info(f"[{self.name}][apply_modifications] Modification List: {key}[{i}] -> {value[i]}")
            else:
                payload[key] = value
                logger.info(f"[{self.name}][apply_modifications] Modification: {key} -> {value}")
        return payload

def main():

    hsepp_config = hf.get_config("configs/mininet/hsepp_config.json")
    hsepp = hSEPP(hsepp_config)
    hsepp.start_server()
    logger.info(f"[{hsepp.name}] Server is ready.")

if __name__ == "__main__":
    main()
