import os
import subprocess
import time
import socket
import sys
import threading
import json
import psutil

# Ensure the captures directory exists
os.makedirs("captures", exist_ok=True)

def is_pid_running(pid):
    """Check if a process with the given PID is still running."""
    try:
        os.kill(pid, 0)  # Send signal 0 to check if the process exists
    except OSError:
        return False  # Process does not exist
    return True  # Process is running

def kill_process_tree(pid):
    """Kills a process and all its child processes."""
    try:
        import psutil
        parent = psutil.Process(pid)
        children = parent.children(recursive=True)
        
        for child in children:
            try:
                child.terminate()
            except:
                pass
                
        # Give them a moment to terminate
        gone, still_alive = psutil.wait_procs(children, timeout=3)
        
        # Force kill any that remain
        for p in still_alive:
            try:
                p.kill()
            except:
                pass
                
        # Finally kill the parent if it's still running
        if parent.is_running():
            parent.terminate()
            parent.wait(3)
            if parent.is_running():
                parent.kill()
    except:
        # Fallback to os.kill
        import os
        import signal
        try:
            os.killpg(os.getpgid(pid), signal.SIGTERM)
        except:
            try:
                os.kill(pid, signal.SIGTERM)
            except:
                pass

def force_kill_processes_using_ports(ports):
    """Force kill any process using the specified ports."""
    
    # Try psutil method first
    try:
        for port in ports:
            for proc in psutil.process_iter():
                try:
                    # Changed from connections() to net_connections()
                    connections = proc.net_connections(kind='inet')
                    for conn in connections:
                        if hasattr(conn, 'laddr') and conn.laddr.port == port:
                            print(f"[Runner] Killing process {proc.pid} ({proc.name()}) using port {port}")
                            try:
                                proc.terminate()
                                proc.wait(3)
                            except:
                                try:
                                    proc.kill()
                                except:
                                    pass
                except:
                    continue
    except:
        # Fallback to netstat on Linux
        for port in ports:
            try:
                # Get processes using the port with netstat
                cmd = f"netstat -tuln | grep :{port}"
                if subprocess.call(cmd, shell=True, stdout=subprocess.DEVNULL) == 0:
                    # Find and kill the process
                    cmd = f"lsof -i :{port} | tail -n +2 | awk '{{print $2}}'"
                    pids = subprocess.check_output(cmd, shell=True).decode().split()
                    for pid in pids:
                        try:
                            pid = int(pid.strip())
                            print(f"[Runner] Killing process {pid} using port {port}")
                            subprocess.call(f"kill -9 {pid}", shell=True)
                        except:
                            pass
            except:
                pass

def stream_output(stream):
    """Reads and prints the stream output line by line in a separate thread."""
    for line in iter(stream.readline, ''):
        sys.stdout.write(line)
    stream.close()

def is_port_free(port):
    """Check if a port is free."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.settimeout(1)
        result = sock.connect_ex(('127.0.0.1', port))
        return result != 0  # Returns True if the port is free
    
def wait_for_ports_to_be_free(ports, timeout=30):
    """Wait until all specified ports are free or timeout is reached."""
    start_time = time.time()
    while time.time() - start_time < timeout:
        if all(is_port_free(port) for port in ports):
            return True
        time.sleep(1)
    return False  # Timeout reached

def get_dynamic_core_map(components, start_core=2):
    """Assign each component to a unique core, starting from start_core."""
    num_cores = os.cpu_count()
    if num_cores is None or num_cores < (start_core + len(components)):
        print(f"[Runner] Warning: Not enough CPU cores ({num_cores}) for all components ({components}) starting from core {start_core}.")
        # Assign as many as possible, then reuse cores after start_core
        assigned_cores = [start_core + (i % max(1, num_cores - start_core)) for i in range(len(components))]
    else:
        assigned_cores = list(range(start_core, start_core + len(components)))
    return dict(zip(components, assigned_cores))

def run_script_non_blocking(mode, msg, num_warm_starts=None, core_map=None):
    """Runs a Python script in a fully non-blocking manner and streams its output. main.py is pinned to core 1 and passes core_map for components."""
    cmd = ["taskset", "-c", "1", "python3", "main.py", mode, msg]
    if num_warm_starts:
        cmd.append(str(num_warm_starts))
    if core_map:
        cmd.append(json.dumps(core_map))

    process = subprocess.Popen(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        bufsize=1,  # Line-buffered output
        universal_newlines=True
    )

    # Create and start separate threads for stdout and stderr streaming
    stdout_thread = threading.Thread(target=stream_output, args=(process.stdout,))
    stderr_thread = threading.Thread(target=stream_output, args=(process.stderr,))

    stdout_thread.daemon = True
    stderr_thread.daemon = True

    stdout_thread.start()
    stderr_thread.start()

    return process


def run(mode, msg, timeout=60, num_warm_starts=None, core_map=None, capture_with_tshark=False):
    """Run the simulation with the specified mode and message, handling port management and optional tshark capture."""
    # Ports to check
    required_ports = [65431, 65432, 65433, 65435]

    # First make sure no stray processes are holding the ports
    force_kill_processes_using_ports(required_ports)

    # Wait for ports to be free
    if not wait_for_ports_to_be_free(required_ports):
        print("[Runner] Timeout waiting for ports to be free. Killing any processes using these ports...")
        # Try one more time with more aggressive killing
        force_kill_processes_using_ports(required_ports)
        if not wait_for_ports_to_be_free(required_ports, timeout=5):
            print("[Runner] Still couldn't free ports. Skipping this run.")
            return

    # Prepare tshark capture if enabled
    tshark_process = None
    capture_file = None
    if capture_with_tshark:
        capture_file = f"captures/capture_{mode}_{msg}.pcap"
        tshark_process = subprocess.Popen(
            ["tshark", "-i", "lo", "-w", capture_file],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE
        )
        print(f"[Runner] Started tshark capture for mode={mode}, msg={msg}.")
        time.sleep(1)  # Give tshark some time to start

    try:
        # Run Simulation
        process = run_script_non_blocking(mode, msg, num_warm_starts=num_warm_starts, core_map=core_map)
        
        parent_pid = process.pid

        start_time = time.time()
        while process.poll() is None:
            if time.time() - start_time > timeout:
                # First try graceful termination
                print(f"[Runner] Process {parent_pid} timed out, terminating...")
                process.terminate()
                time.sleep(0.5)  # Give it time to clean up
                
                # Kill all child processes
                kill_process_tree(parent_pid)
                
                # Double-check and force kill any processes still using our ports
                force_kill_processes_using_ports(required_ports)
                
                raise Exception("Process timed out")
            time.sleep(0.5)
    finally:
        # Ensure we clean up everything
        if process.poll() is None:
            kill_process_tree(process.pid)
        # Stop tshark capture if it was started
        if tshark_process:
            time.sleep(1)  # Give tshark some time to finish writing
            tshark_process.terminate()
            tshark_process.wait()
            print(f"[Runner] Stopped tshark capture for mode={mode}, msg={msg}. Saved to {capture_file}")


def main(repeat, modes, messages, num_warm_starts=None, retries=3, core_map=None, capture_with_tshark=False):
    """Main function to run the simulations with the specified parameters."""
    start = time.perf_counter()
    if capture_with_tshark:
        repeat = 1  # Only run once if capturing with tshark
        print(f"[Runner] Starting runs with capture_with_tshark={capture_with_tshark}, only one run will be executed.")
    all_msgs = messages.copy()
    reduced_msgs = ["large_even", "middle_even","small_even"]
    for i in range(repeat):
        for mode in modes:
            if mode in ["base", "e2e", "h2h"]: # only run these modes with the even messages, as they are the only ones that are not affected by the message split
                messages = reduced_msgs
            else:
                messages = all_msgs
            for msg in messages:
                for attempt in range(retries):
                    try:
                        print(f"[Runner] Attempt {attempt + 1} for run {i+1}: mode={mode}, msg={msg}")
                        # Only capture the first run for each combination
                        capture = capture_with_tshark and i == 0 and attempt == 0
                        run(mode, msg, 30, num_warm_starts=num_warm_starts, core_map=core_map, capture_with_tshark=capture)
                        break  # Exit retry loop if the run succeeds
                    except Exception as e:
                        print(f"[Runner] Run {i+1}, attempt {attempt + 1} failed: {e}")
                        if attempt == retries - 1:
                            print(f"[Runner] Skipping run {i+1} after {retries} failed attempts.")
    end = time.perf_counter()
    print(f"[Runner] All runs completed in {end - start:.2f} seconds.")


if __name__ == '__main__':
    repetitions = 2 # 8 days of simulations -> 2000 repetitions
    modes = ['base', 'e2e', 'h2h', 'prins', 'prins_tcp']
    messages = ["large_aad", "large_ciphertext", "large_even", "middle_aad", "middle_ciphertext", "middle_even", "small_aad", "small_ciphertext", "small_even"]
    components = ["vsepp", "vipx", "hipx", "hsepp"]
    core_map = get_dynamic_core_map(components)
    num_warm_starts = 1
    main(repetitions, modes, messages, num_warm_starts=num_warm_starts, retries=3, core_map=core_map)
    # Uncomment the following line to run with tshark capture
    # main(repetitions, modes, messages, retries=3, capture_with_tshark=True)
