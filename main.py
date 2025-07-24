import os
import subprocess
import time
import socket
import sys
import multiprocessing
import json
import psutil
import helper_functions as hf
from helper_functions import logger
from vSEPP import vSEPP
from IPX import IPX
from hSEPP import hSEPP

# Create results directory if it doesn't exist
os.makedirs("results", exist_ok=True)

def run_component(component_type, mode, shared_dict, control_dict, core_map=None):
    """Run a single component with support for both cold and warm starts"""
    try:
        if core_map:
            process = psutil.Process()
            core_id = core_map.get(component_type, 0)
        
            # Set process to run on only the specified core
            process.cpu_affinity([core_id])
            logger.info(f"[{component_type}] Pinned to CPU core {core_id}")
        
        # Run the specific component
        if component_type == "vsepp":
            vsepp = vSEPP(
                config_path=f"configs/{mode}/vsepp_config.json",
                shared_dict=shared_dict,
                control_dict=control_dict
            )
            vsepp.start_server()
            
        elif component_type == "vipx":
            vipx = IPX(config_path=f"configs/{mode}/vipx_config.json",
                control_dict=control_dict)
            vipx.start_server()
            
        elif component_type == "hipx":
            hipx = IPX(config_path=f"configs/{mode}/hipx_config.json",
                control_dict=control_dict)
            hipx.start_server()
            
        elif component_type == "hsepp":
            hsepp = hSEPP(
                config_path=f"configs/{mode}/hsepp_config.json",
                shared_dict=shared_dict,
                control_dict=control_dict
            )
            hsepp.start_server()
            
        # Monitor for shutdown signal
        while not control_dict.get('shutdown', False):
            time.sleep(0.1)
            
    except Exception as e:
        print(f"Error in {component_type}: {e}")
        
def start_func(msg):
    vsepp_host = '127.0.0.2'
    vsepp_port = 65431
    message_file = f'msgs/{str(msg)}.json'
    with open(message_file, 'rb') as f:
        data = f.read()
    # Connect to vsepp
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    client_socket.connect((vsepp_host, vsepp_port))
    client_socket.send(data)
    client_socket.close()

def main(mode, msg, coremap=None, num_warm_starts=1):
    """Run complete simulation with sequential cold and warm starts in same processes"""    
    # Shared memory for results and control
    manager = multiprocessing.Manager()
    shared_results = manager.dict()
    control_signals = manager.dict()
    
    try:
        # Start each component in its own process
        processes = []
        for component in ["vsepp", "vipx", "hipx", "hsepp"]:
            p = multiprocessing.Process(
                target=run_component,
                args=(component, mode, shared_results, control_signals, coremap)
            )
            p.daemon = True
            p.start()
            processes.append(p)
        
        # Wait for servers to initialize
        wait_start = time.time()
        while time.time() - wait_start < 10:  # 10-second max wait
            if (shared_results.get('vsepp_ready', False) and 
                shared_results.get('vipx_ready', False) and 
                shared_results.get('hipx_ready', False) and 
                shared_results.get('hsepp_ready', False)):
                break
            time.sleep(0.05)  # Short sleep for polling
        
        # Perform cold start
        logger.info(f"[Main] Running cold start for {mode} mode with message type {msg}...")
        start_func(msg)
        
        # Wait for cold start to complete
        wait_start = time.time()
        while (time.time() - wait_start < 10 and 
            not shared_results.get('cold_complete', False)):
            time.sleep(0.1)
        
        if not shared_results.get('cold_complete', False):
            logger.error("[Main] Cold start measurement failed - timeout")
        else:
            cold_elapsed_ms = (shared_results['hsepp_end_cold'] - 
                             shared_results['vsepp_start_cold']) * 1000
            logger.info(f"[Main] Cold start completed in {cold_elapsed_ms:.2f}ms")
        
        # Warm starts - modified to run multiple times
        warm_elapsed_times = []
        
        for i in range(num_warm_starts):
            # Clear previous warm start data
            if 'warm_complete' in shared_results:
                del shared_results['warm_complete']
            if 'vsepp_start_warm' in shared_results:
                del shared_results['vsepp_start_warm'] 
            if 'hsepp_end_warm' in shared_results:
                del shared_results['hsepp_end_warm']

            # Pause briefly before warm start
            time.sleep(0.2)
            
            # Signal components to perform warm start
            control_signals['perform_warm'] = True
            
            # Perform warm start with the same processes
            logger.info(f"[Main] Running warm start for {mode} mode with message type {msg}...")
            start_func(msg)
            
            # Wait for warm start to complete
            wait_start = time.time()
            while (time.time() - wait_start < 10 and 
                not shared_results.get('warm_complete', False)):
                time.sleep(0.1)
                    
            # Calculate warm start time
            if shared_results.get('vsepp_start_warm') and shared_results.get('hsepp_end_warm'):
                warm_elapsed_ms = (shared_results['hsepp_end_warm'] - 
                                shared_results['vsepp_start_warm']) * 1000
                warm_elapsed_times.append(warm_elapsed_ms)
                logger.info(f"[Main] Warm start #{i+1} time: {warm_elapsed_ms:.2f}ms")
            else:
                logger.error(f"[Main] Warm start #{i+1} measurement failed")
        
        # Signal all processes to shut down
        control_signals['shutdown'] = True
        
        # Wait for processes to terminate
        for p in processes:
            p.join(timeout=2)
            if p.is_alive():
                p.terminate()
        
        # Save all results
        if len(warm_elapsed_times) > 0:
            # Save cold start time
            with open(f'results/{mode}_{msg}_cold.txt', 'a') as f:
                f.write(f'{cold_elapsed_ms}\n')
            
            # Save all warm start times
            with open(f'results/{mode}_{msg}_warm.txt', 'a') as f:
                for time_ms in warm_elapsed_times:
                    f.write(f'{time_ms}\n')
                
        else:
            logger.info("[Main] Measurement failed - missing timing data")
    except KeyboardInterrupt:
        logger.error("[Main] Interrupted, shutting down...")
    except Exception as e:
        logger.error(f"[Main] Error: {e}")
    finally:
        # Ensure clean shutdown of all processes
        control_signals['shutdown'] = True
        for p in processes:
            p.join(timeout=2)
            if p.is_alive():
                p.terminate()
                p.join(timeout=1)
                if p.is_alive():
                    p.kill()

if __name__ == "__main__":

    mode = sys.argv[1]
    if mode not in ["base", "e2e", "h2h", "prins", "prins_details", "prins_tcp"]:
        logger.error("Invalid mode. Choose from: base, e2e, h2h, prins, prins_tcp.")
        sys.exit(1)

    msg = sys.argv[2]
    if msg not in ["large_aad", "large_ciphertext", "large_even", "middle_aad", "middle_ciphertext", "middle_even", "small_aad", "small_ciphertext", "small_even"]:
        logger.error("Invalid message type. Choose from: large_aad, large_ciphertext, large_even, middle_aad, middle_ciphertext, middle_even, small_aad, small_ciphertext, small_even.")
        sys.exit(1)

    try:
        num_warm_starts = int(sys.argv[3])
        logger.info(f"Running with {num_warm_starts} warm starts.")
    except:
        logger.error("Invalid warm start count. Using default (1).")
        num_warm_starts = 1

    core_map = sys.argv[4] if len(sys.argv) > 4 else None
    core_map = json.loads(core_map) if core_map else None
    if core_map:
        main(mode, msg, coremap=core_map, num_warm_starts=num_warm_starts)
    else: 
        main(mode, msg, num_warm_starts=num_warm_starts)
