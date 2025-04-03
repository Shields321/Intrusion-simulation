import pyshark
import warnings
import subprocess
from datetime import datetime, time, timedelta


warnings.filterwarnings("ignore")


ipAddressSRC = []
ipAddressSRC_unique = []
ipAddressDist = []
ipAddressDist_unique = []
ipAddress_blocked = []
threshold = 5000
threshold_5 = 300
threshold_high = 400

signatures = [
    "ifconfig",
    "ls",
    "test"
]

real_ip = [
    "10.0.2.12",
    "10.0.2.13",
    "10.0.2.13",
    "10.0.2.13"
]

def sortIPaddress(copy):
    try:
        for cap1 in copy:
            if "IP" in cap1:
                ipAddressSRC.append(cap1.ip.src)
                ipAddressDist.append(cap1.ip.dst)
                
        for srcIP in ipAddressSRC:
            if srcIP not in ipAddressSRC_unique:
                ipAddressSRC_unique.append(srcIP)

        for dstIP in ipAddressDist:
            if dstIP not in ipAddressDist_unique:
                ipAddressDist_unique.append(dstIP)      
    except:
        pass

def block_ip(block_ip):
    try:
        ipAddress_blocked.append(block_ip)
        subprocess.run(["sudo","ufw","deny", "from", block_ip], check = True)
        print(f'IP address {block_ip} is blocked')
    except:
        pass
    
def ipAddress_Source_Frequncy_ddos(copy):
    try:
        IP_count = 0
        for IP_total in copy:
            if "IP" in IP_total:
                IP_count +=1
        
        for fiveSec_check in ipAddressSRC_unique:
            five_frequncy = 0
            for individual_ip in copy:
                if "IP" in individual_ip:
                    if individual_ip.ip.src == fiveSec_check:
                        five_frequncy += 1
            if (five_frequncy > threshold_5) and (fiveSec_check not in ipAddress_blocked):
                print(f'{individual_ip.ip.src} over threshold in the last 5 seconds')
                block_ip(individual_ip.ip.src)
        
        if (IP_count > threshold_high):
            print(f'Frequncy of packets too high within 5 seconds')
            for massBlock in copy:
                if "IP" in massBlock:
                    if fiveSec_check not in real_ip:
                        block_ip(massBlock.ip.src)
                    
        for sourceIP in ipAddressSRC_unique:
            srcFrequncy = 0
            for sourceIP1 in ipAddressSRC:
                if sourceIP1 == sourceIP:
                    srcFrequncy+=1
            if (srcFrequncy >= threshold): 
                if (sourceIP not in ipAddress_blocked):
                    print(f'high packet activity since IDPS launch Source IP: {sourceIP}, Frequncy: {srcFrequncy}')
                
    except:
        pass

def malicous_payload_detection(copy):
    try:
        for command_detect in copy:
            if "IP" in command_detect and "TCP" in command_detect:
                malicious_ip = command_detect.ip.src
                
                if hasattr(command_detect.tcp, 'payload'):
                    print(f'{malicious_ip} has a payload')
                    payloadrRaw = command_detect.tcp.payload.replace(':', '')
                    payloadToBytes = bytes.fromhex(payloadrRaw)
                    payloadRead = payloadToBytes.decode('utf-8', errors='ignore')
                    
                    for check in signatures:
                        if check in payloadRead and malicious_ip not in ipAddress_blocked:
                            print(f'{malicious_ip} has a command of {payloadRead}')
                            block_ip(malicious_ip)
                            break                
    except:
        pass

def spoof_packet(copy):
    try:
        for spoof in copy:
            if "IP" in spoof:
                spoof_ip = spoof.ip.src
                
                ttl_packet = int(spoof.ip.ttl)
                
                if (ttl_packet < 30 or ttl_packet > 80) and spoof_ip not in ipAddress_blocked:
                    print(f'{spoof_ip} has a ttl of {ttl_packet}')
                    block_ip(spoof_ip)
                
    except:
        pass

def five_sec_interval(copy):
    start = 0
    packet_analyze = []
    for packet in copy:
        packet_time = packet.sniff_time  
    
        if start == 0:
            start = packet_time
        
        end_time = start + timedelta(seconds=5)
        
        if packet_time < end_time:
            packet_analyze.append(packet)
        else:
            break
    return(packet_analyze)

while(True):
    print("Scan for 1 seconds")
    liveCapture = pyshark.LiveCapture(interface="enp0s3", output_file="pyshark.pcap")
    try:
        liveCapture.sniff(timeout=1)
        liveCapture.close()
        with pyshark.FileCapture("pyshark.pcap", keep_packets=False) as file_capture:
            packetCapture = list(file_capture)
        copy = packetCapture
        sortIPaddress(copy)
        five_sec_pac = five_sec_interval(copy)
        ipAddress_Source_Frequncy_ddos(five_sec_pac)
        malicous_payload_detection(copy)
        spoof_packet(copy)
    except:
        pass

    
    


