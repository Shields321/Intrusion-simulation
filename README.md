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
- Python packages: `virtualbox`, `paramiko`, `pyshark`
- Kali and Ubuntu VMs installed in VirtualBox
- Guest Additions installed in the VMs
- the ubuntu VM should have the IDPS.py installed and ready to run


3. Use the GUI to start VMs, run the attack, monitor detection, and stop VMs.

## Test Cases Summary

| Test ID   | Description                          | Result |
|-----------|--------------------------------------|--------|
| TC-01     | Start VMs via GUI                    | Pass   |
| TC-02     | Execute attack via GUI               | Pass   |
| TC-03     | Block IP on suspicious packet        | Pass   |
| TC-04     | No VM selected warning               | Pass   |
| TC-05     | SSH into VMs and run attack          | Fail   |
| TC-06     | Stop attack                          | Fail   |
| TC-07     | Stop VMs                             | Fail   |
| Reg-08    | Regression test on attack change     | Pass   |
| Perf-09   | Monitor performance during attack    | Pass   |
| Sec-10    | Attempt attack outside local network | Pass   |

## Notes

This simulation is for testing and learning purposes only. It is not intended for real-world deployment or use outside a secure test environment.


