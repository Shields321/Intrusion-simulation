import os
import signal
import threading
import time
import tkinter as tk
import subprocess
from tkinter import messagebox
from tkinter import ttk
from Manager import VMManager  # Replace with the actual VMManager import

"""
Right now this is the main entry point for the application.
some problems that have come up are:
    when an attack starts running it can not be stopped manually the user would have to wait for that attack to finish before they can do 
    anything else. 
    when the user want to stop using the vms the vms do not close they stay on

"""

class VMGUI:
    def __init__(self, master, vm_manager):
        self.master = master
        self.master.title("IDPS Virtual Machine Manager")
        self.master.geometry("500x500")  # Set window size
        self.master.resizable(False, False)  # Disable resizing
        self.vm_manager = vm_manager
        self.selected_vms = []
        self.attack_type = tk.StringVar()
        self.attack_running = False
        self.attack_thread = None
        self.monitor_thread = None
        self.attack_pid = None  # Track the process ID of the attack
        self.main_menu()

    def main_menu(self):
        """Main Menu: Start VMs, Launch Attack, Exit"""
        for widget in self.master.winfo_children():
            widget.destroy()

        ttk.Label(self.master, text="IDPS Simulation GUI", font=("Arial", 18, "bold")).pack(pady=20)

        ttk.Button(self.master, text="Start VMs", command=self.select_vms_page, width=30).pack(pady=10)
        ttk.Button(self.master, text="Launch Attack", command=self.attack_selection_page, width=30).pack(pady=10)
        ttk.Button(self.master, text="Stop VMs", command=self.stop_vms, width=30).pack(pady=10)
        ttk.Button(self.master, text="Exit", command=self.master.quit, width=30).pack(pady=20)

    def select_vms_page(self):
        """Page to select VMs to start"""
        for widget in self.master.winfo_children():
            widget.destroy()

        ttk.Label(self.master, text="Select VMs to Start", font=("Arial", 14)).pack(pady=20)

        self.vm_vars = {}
        for vm in self.vm_manager.list_vms():
            var = tk.BooleanVar()
            self.vm_vars[vm] = var
            ttk.Checkbutton(self.master, text=vm, variable=var).pack(anchor='w')

        ttk.Button(self.master, text="Start Selected VMs", command=self.start_selected_vms, width=30).pack(pady=10)
        ttk.Button(self.master, text="Back", command=self.main_menu, width=30).pack(pady=5)

    def start_selected_vms(self):
        """Start the selected VMs"""
        selected = [vm for vm, var in self.vm_vars.items() if var.get()]
        if not selected:
            messagebox.showwarning("No Selection", "Please select at least one VM.")
            return

        # Run the VM start in a separate thread
        threading.Thread(target=self._start_selected_vms, args=(selected,), daemon=True).start()

    def _start_selected_vms(self, selected):
        """Start the selected VMs in a background thread"""
        ip_map = self.vm_manager.start_vms_and_get_ips(selected)
        self._show_message("VMs Started", f"Started VMs:\n{ip_map}")
        self.main_menu()

    def stop_vms(self):
        """Stop all running VMs"""
        ip_map = self.vm_manager.vm_ips
        if not ip_map:
            messagebox.showwarning("No VMs Running", "There are no VMs currently running.")
            return

        # Run the VM stop in a separate thread
        threading.Thread(target=self._stop_vms, daemon=True).start()

    def _stop_vms(self):
        """Stop all running VMs in a background thread"""
        ip_map = self.vm_manager.vm_ips
        for vm_name, ip in ip_map.items():            
            subprocess.run(["VBoxManage", "controlvm", vm_name, "acpipowerbutton"])            
            print(f"[*] Stopped VM '{vm_name}' with IP: {ip}")

        self._show_message("VMs Stopped", "All VMs have been stopped.")
        self.main_menu()

    def attack_selection_page(self):
        """Page to select an attack type"""
        for widget in self.master.winfo_children():
            widget.destroy()

        ttk.Label(self.master, text="Select Attack Type", font=("Arial", 14)).pack(pady=20)

        attacks = ["Spoof Packet", "Dos", "Payload"]
        for atk in attacks:
            ttk.Radiobutton(self.master, text=atk, value=atk, variable=self.attack_type).pack(anchor='w')

        ttk.Button(self.master, text="Launch Attack", command=self.launch_attack, width=30).pack(pady=10)
        ttk.Button(self.master, text="Stop Attack", command=self.stop_attack, width=30).pack(pady=10)
        ttk.Button(self.master, text="Back", command=self.main_menu, width=30).pack(pady=5)

    def launch_attack(self):
        """Launch the selected attack"""
        if self.attack_running:
            messagebox.showwarning("Attack Running", "An attack is already running. Please wait for it to finish.")
            return

        atk = self.attack_type.get()
        if not atk:
            messagebox.showwarning("No Attack Selected", "Please select an attack type.")
            return

        ip_map = self.vm_manager.vm_ips
        kali_ip = ip_map.get("kali-linux-2024.3-virtualbox-amd64")
        ubuntu_ip = ip_map.get("ubuntuDesktop")

        if kali_ip and ubuntu_ip:
            # Reset attack variables before starting a new one
            self.attack_pid = None
            self.attack_running = False

            # Run the attack in a separate thread
            threading.Thread(target=self._launch_attack, args=(atk, kali_ip, ubuntu_ip), daemon=True).start()
        else:
            messagebox.showerror("VM IP Error", "Kali or Ubuntu IP not available.")
            self.main_menu()

    def _launch_attack(self, atk, kali_ip, ubuntu_ip):
        """Run the attack in a background thread"""
        self.attack_running = True
        threading.Thread(target=self._monitor_attack, args=(), daemon=True).start()
        port = 80
        packet_count = 1000
        payload_size = 1024*4
        fake_ip = "10.10.10.4"
        fake_ip2 = "10.11.12.4"
        fake_ip3 = "11.12.13.4"
        if atk == "payload":
            cmd = f"echo kali | sudo -S hping3 -S -p {port} -a {fake_ip3}  -d {payload_size} -E payload.txt {ubuntu_ip} -c 3"
        elif atk == "Dos":
            cmd = f"echo kali | sudo -S hping3 -S -p {port} -a {fake_ip} -i {packet_count} {ubuntu_ip}"
        elif atk == "spoof packet":
            cmd = f"echo kali | sudo -S hping3 -S -p {port} -a {fake_ip2} {ubuntu_ip} --ttl 200 -c 10"
        else:
            messagebox.showerror("Unknown Attack", "Invalid attack selected.")
            self.attack_running = False
            return
        
        # Execute the attack and get the PID
        print(f"[*] Running {atk} from Kali ({kali_ip}) to Ubuntu ({ubuntu_ip})...")
        output, error = self.vm_manager.ssh_execute_command(kali_ip, "kali", "kali", cmd)

        # Capture the PID for monitoring
        self.attack_pid = self._extract_pid(output)

        self._show_message("Attack Result", f"Output: {output}\nError: {error}")
        self.attack_running = False
        self.main_menu()

    def _extract_pid(self, output):
        """Extract the PID of the attack from the command output"""
        # For example, if the output contains a PID (adjust for your command's output)
        # This is a placeholder, adapt as necessary
        for line in output.splitlines():
            if "PID" in line:
                return int(line.split(":")[1].strip())
        return None

    def _monitor_attack(self):
        """Monitor the running attack in a background thread"""
        while self.attack_running:
            # Monitor the attack (e.g., check the attack process status)
            if self.attack_pid and self._check_attack_status():
                print(f"[*] Attack in progress with PID: {self.attack_pid}")
            time.sleep(2)

    def _check_attack_status(self):
        """Check the status of the attack process"""
        # If we had the PID, we would check if it's still running
        if self.attack_pid:
            try:
                os.kill(self.attack_pid, 0)  # Try to send signal 0 to check if the process is still running
                return True
            except ProcessLookupError:
                return False
        return False

    def stop_attack(self):
        """Stop the running attack"""
        if not self.attack_running:
            messagebox.showwarning("No Attack Running", "No attack is currently running.")
            return
        cmd = "echo kali | ctrl+c"
        kali_ip = self.vm_manager.vm_ips.get("kali-linux-2024.3-virtualbox-amd64")
        self.vm_manager.ssh_execute_command(kali_ip, "kali", "kali", cmd)

    def _show_message(self, title, message):
        """Show a message box with the given title and message"""
        self.master.after(0, messagebox.showinfo, title, message)


if __name__ == '__main__':
    root = tk.Tk()
    gui = VMGUI(root, VMManager())
    root.mainloop()
