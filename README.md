# IDPS Simulation

This project simulates an Intrusion Detection and Prevention System (IDPS) using two virtual machines: a Kali Linux attacker and an Ubuntu defender. The system is controlled using a Python-based GUI, which allows users to start VMs, run attacks, and observe detection and blocking behavior.

## Features

- Start and stop VirtualBox VMs using the GUI
- Run simulated DoS attacks from Kali to Ubuntu
- Automatically detect and block malicious IPs on Ubuntu using UFW
- Retrieve and display IP addresses of VMs
- Simple SSH-based command execution between VMs
- Includes regression, performance, and security testing

## VMs Used

- kali-linux
- ubuntuDesktop

Both VMs should be set to Host-Only networking mode to isolate traffic.

## Requirements

- Python 3
- VirtualBox
- Tshark/wireshark
- Python packages: `virtualbox` (pyvbox), `paramiko`, `pyshark`
- Kali and Ubuntu VMs installed in VirtualBox
- Guest Additions installed in the VMs
- the ubuntu VM should have the IDPS.py installed and ready to run

