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
threshold = 3000
threshold_5 = 2000

signatures = [
    "ifconfig",
    "ls",
    "test"
]

real_ip = [
    "192.168.10.1",
    "192.168.10.2",
    "192.168.10.3",
    "192.168.10.4"
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
        subprocess.run(["sudo","ufw","deny",block_ip], check = True)
        print(f'IP address {block_ip} is blocked')
    except:
        pass
    
def ipAddress_Source_Frequncy_ddos(copy):
    try:
        for fiveSec_check in ipAddressSRC_unique:
            five_frequncy = 0
            for individual_ip in copy:
                if "IP" in individual_ip:
                    if individual_ip.ip.src == fiveSec_check:
                        five_frequncy += 1
            if five_frequncy > threshold_5:
                print(f'{individual_ip.ip.src} over threshold in the last 5 seconds')
                #block_ip(individual_ip.ip.src)
                    
        for sourceIP in ipAddressSRC_unique:
            srcFrequncy = 0
            for sourceIP1 in ipAddressSRC:
                if sourceIP1 == sourceIP:
                    srcFrequncy+=1
            if srcFrequncy >= threshold:
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
                    payload_hex = command_detect.tcp.payload.replace(':', '')
                    payload_bytes = bytes.fromhex(payload_hex)
                    payload_str = payload_bytes.decode('utf-8', errors='ignore')
                    
                    for check in signatures:
                        if check in payload_str:
                            print(f'{malicious_ip} has a command of {payload_str}')
                            #block_ip(malicious_ip)
                            break                
    except:
        pass

def spoof_packet(copy):
    try:
        for spoof in copy:
            if "IP" in spoof:
                spoof_ip = spoof.ip.src
                
                ttl_packet = int(spoof.ip.ttl)
                
                if ttl_packet < 30 or ttl_packet > 80:
                    print(f'{spoof_ip} has a ttl of {ttl_packet}')
                    #block_ip(spoof_ip)
                
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
    liveCapture = pyshark.LiveCapture(interface="Wi-Fi", output_file="pyshark.pcap")
    try:
        liveCapture.sniff(timeout=1)
        liveCapture.close()
        with pyshark.FileCapture("pyshark.pcap", keep_packets=False) as file_capture:
            packetCapture = list(file_capture)
        copy = packetCapture
        sortIPaddress(copy)
        five_sec_pac = five_sec_interval(copy)
        ipAddress_Source_Frequncy_ddos(five_sec_pac)
        #malicous_payload_detection(copy)
        #spoof_packet(copy)
    except:
        pass

    
    


