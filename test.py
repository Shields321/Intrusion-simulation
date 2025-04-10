import time
import subprocess
import paramiko
import virtualbox
import threading

class VMManager:
    def __init__(self):
        self.vbox = virtualbox.VirtualBox()
        self.vm_ips = {}

    def list_vms(self):
        """List all VM names."""
        return [m.name for m in self.vbox.machines]

    def start_vm(self, vm_name):
        """Start a VM and return its session."""
        machine = self.vbox.find_machine(vm_name)
        session = virtualbox.Session()  # Create a new session for each VM
        print(f"[*] Starting VM '{vm_name}'...")
        progress = machine.launch_vm_process(session, "gui", [])
        progress.wait_for_completion()
        print(f"[+] VM '{vm_name}' has started.")
        return machine, session  # Return both machine and session

    def get_vm_ip(self, vm_name):
        """Get the IP of a running VM using subprocess."""
        command = f"VBoxManage guestproperty get {vm_name} /VirtualBox/GuestInfo/Net/0/V4/IP"
        print(f"[*] Running command to get IP for '{vm_name}': {command}")
        
        try:
            result = subprocess.check_output(command, shell=True, stderr=subprocess.PIPE).decode().strip()
            if result.startswith("Value:"):
                ip = result.split(":")[1].strip()
                print(f"[+] Found IP for {vm_name}: {ip}")
                return ip
            else:
                print(f"[-] IP not found for {vm_name}.")
                return "IP not found"
        except subprocess.CalledProcessError as e:
            print(f"[-] Error retrieving IP for {vm_name}: {e}")
            return "Error"

    def ssh_execute_command(self, ip, username, password, command):
        """SSH into the VM and execute the command."""
        print(f"[*] Connecting to {ip} via SSH...")
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())  # Automatically add host keys
        try:
            ssh.connect(ip, username=username, password=password)
            print(f"[+] Connected to {ip}. Running command...")
            stdin, stdout, stderr = ssh.exec_command(command)
            output = stdout.read().decode()
            errors = stderr.read().decode()
            ssh.close()
            return output, errors
        except Exception as e:
            print(f"[-] SSH connection failed: {e}")
            return None, str(e)

    def poll_for_ip(self, vm_name, retries=10, delay=5):
        """Poll for the IP address of the VM until it is available."""
        for _ in range(retries):
            ip = self.get_vm_ip(vm_name)
            if ip != "IP not found" and ip != "Error":
                return ip
            time.sleep(delay)
        return None

    def start_vms_and_get_ips(self, vm_names):
        """Start multiple VMs concurrently, get their IPs, and return them."""
        threads = []
        
        # Start a thread for each VM to start and get its IP
        for vm_name in vm_names:
            thread = threading.Thread(target=self.start_vm_and_get_ip, args=(vm_name,))
            threads.append(thread)
            thread.start()

        # Wait for all threads to complete
        for thread in threads:
            thread.join()

        return self.vm_ips

    def start_vm_and_get_ip(self, vm_name):
        """Helper function to start a VM and retrieve its IP."""
        machine, session = self.start_vm(vm_name)
        
        # Wait a few seconds to ensure the VM has booted
        time.sleep(120)  # Adjust this if needed depending on VM boot time

        ip = self.poll_for_ip(vm_name)
        if ip:
            print(f"[*] IP for '{vm_name}': {ip}")
            self.vm_ips[vm_name] = ip
        else:
            print(f"[-] Failed to get IP for '{vm_name}'")

        # Unlock the session after use to prevent the "busy" error
        session.unlock_machine()

    def stop_vm(self, vm_name):
        """Stop the VM."""
        print(f"[*] Stopping VM '{vm_name}'...")

        # Find the VM and create a session
        machine = self.vbox.find_machine(vm_name)
        session = virtualbox.Session()
        
        try:
            # Attempt a graceful shutdown
            session.console.power_button()
            print(f"[*] Power button signal sent to VM '{vm_name}', waiting for shutdown...")
            time.sleep(10)  # Wait for the VM to shut down gracefully (adjust time as necessary)
            print(f"[+] VM '{vm_name}' has stopped.")
        
        except Exception as e:
            print(f"[-] Error stopping VM '{vm_name}': {e}")
