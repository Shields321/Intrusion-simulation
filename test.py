import subprocess
import time
import os

# VM details (replace with your VM's specifics)
vm_name = "kali-linux-2024.3-virtualbox-amd64"
username = "kali"
password = "kali"

# Function to wait for the VM to be ready
def wait_for_vm_ready(vm_name, username, password):
    print(f"Waiting for {vm_name} to be ready...")
    for _ in range(12):  # Retry for up to 60 seconds
        try:
            subprocess.check_call([
                "VBoxManage", "guestcontrol", vm_name, "run",
                "--username", username, "--password", password,
                "--", "/bin/echo", "hello"
            ], stderr=subprocess.PIPE)
            print(f"{vm_name} is ready.")
            return True
        except subprocess.CalledProcessError:
            time.sleep(5)
    print(f"Failed to connect to {vm_name}.")
    return False

def start_ssh_service(vm_name, username, password):
    print(f"Checking SSH service status on {vm_name}...")
    try:
        result = subprocess.run([
            "VBoxManage", "guestcontrol", vm_name, "run",
            "--username", username, "--password", password,
            "--", "/bin/systemctl", "is-active", "ssh"
        ], capture_output=True, text=True)
        if "active" in result.stdout:
            print(f"SSH service is already running on {vm_name}.")
            return
    except subprocess.CalledProcessError:
        pass  # Proceed if the status check fails

    print(f"Starting SSH service on {vm_name}...")
    try:
        subprocess.check_call([
            "VBoxManage", "guestcontrol", vm_name, "run",
            "--username", username, "--password", password,
            "--", "/usr/bin/sudo", "/bin/systemctl", "start", "ssh"
        ], stderr=subprocess.PIPE)
        print(f"SSH service started on {vm_name}.")
    except subprocess.CalledProcessError as e:
        print(f"Failed to start SSH on {vm_name}: {e}")

# Main function to start VM and SSH
def start_vm_and_ssh():
    # Start the VM in headless mode
    print(f"Starting {vm_name}...")
    subprocess.run(["VBoxManage", "startvm", vm_name, "--type", "headless"])

    # Wait for the VM to be ready
    if wait_for_vm_ready(vm_name, username, password):
        # Start the SSH service
        start_ssh_service(vm_name, username, password)
    else:
        print("VM not ready. Aborting.")

# Execute the function
if __name__ == "__main__":
    start_vm_and_ssh()