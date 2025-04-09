import time
import subprocess
import paramiko
import virtualbox

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

    def start_vms_and_get_ips(self, vm_names):
        """Start VMs, get their IPs, and return them."""
        for vm_name in vm_names:
            machine, session = self.start_vm(vm_name)
            # Wait a few seconds to ensure the VM has booted
            time.sleep(10)  # Adjust this if needed depending on VM boot time
            ip = self.get_vm_ip(vm_name)
            print(f"[*] IP for '{vm_name}': {ip}")
            self.vm_ips[vm_name] = ip
            # Unlock the session after use to prevent the "busy" error
            session.unlock_machine()
        return self.vm_ips
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
        


# Usage example
if __name__ == "__main__":
    vm_manager = VMManager()
    
    # List all VM names
    print("Available VMs:", vm_manager.list_vms())
    
    # Start VMs and get their IPs
    vm_names = ["kali-linux-2024.3-virtualbox-amd64", "ubuntuDesktop"]
    vm_ips = vm_manager.start_vms_and_get_ips(vm_names)
    
    print("[*] All VMs started and IPs collected.")
    print(vm_ips)

    # SSH into VMs and run a command
    kali_ip = vm_ips.get("kali-linux-2024.3-virtualbox-amd64")
    ubuntu_ip = vm_ips.get("ubuntuDesktop")
    
    print(f"Waiting for 20 seconds before running commands...")
    time.sleep(20)  # Wait a bit before running commands

    if kali_ip and ubuntu_ip:
        confirm = input(f"Do you want to launch the hping3 attack from Kali ({kali_ip}) to Ubuntu ({ubuntu_ip})? (yes/no): ").strip().lower()
        
        if confirm == "yes":
            # Modify command to send 1000 packets and then stop
            attack_command = f"echo kali | sudo -S hping3 -S -c 100 -p 80 {ubuntu_ip}"
            print(f"[*] Running hping3 flood from Kali to {ubuntu_ip}...")
            output, error = vm_manager.ssh_execute_command(kali_ip, "kali", "kali", attack_command)
            print(f"[*] Attack Output: {output}")
            if error:
                print(f"[!] Attack Error: {error}")
        else:
            print("[*] Attack aborted by user.")
    else:
        print("[!] Could not get IPs for both Kali and Ubuntu.")

    # Uncomment code is becuase the functionality to run the ssh server on the ubuntu vm has not been found out yet
    """
    if ubuntu_ip:
        print(f"[*] Running 'uptime' on Ubuntu VM...")
        output, error = vm_manager.ssh_execute_command(ubuntu_ip, "shields", "1234", "uptime")
        print(f"[*] Output: {output}")
        if error:
            print(f"[*] Error: {error}")
    """