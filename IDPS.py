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
threshold = 5000 #used for high frequncy from start to end
threshold_5 = 300 #used high frequncy within 5 seconds for one IP
threshold_high = 400 #used high frequncy within 5 seconds for multiple different IPs

#signatures of known bad commands, for this simulation no actually bad command is used. 
signatures = [ 
    "ifconfig",
    "ls",
    "test"
]

#This is for known non malicious IPs. 
real_ip = [
    "10.0.2.12",
    "10.0.2.13",
    "10.0.2.14",
    "10.0.2.15"
]

#This function is to sort what IP is a source IP and what is a destination IP. 
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

#This function is to block the IP.
def block_ip(block_ip):
    try:
        ipAddress_blocked.append(block_ip)
        subprocess.run(["sudo","ufw","deny", "from", block_ip], check = True)
        print(f'IP address {block_ip} is blocked')
    except:
        pass

#This function is detect a denial of service attacks. 
def ipAddress_Source_Frequncy_ddos(copy):
    try:
        IP_count = 0
        for IP_total in copy:
            if "IP" in IP_total:
                IP_count +=1
        
        for fiveSec_check in ipAddressSRC_unique: #checks for an attack based on a single IP.
            five_frequncy = 0
            for individual_ip in copy:
                if "IP" in individual_ip:
                    if individual_ip.ip.src == fiveSec_check:
                        five_frequncy += 1
            if (five_frequncy > threshold_5) and (fiveSec_check not in ipAddress_blocked):
                print(f'{individual_ip.ip.src} over threshold in the last 5 seconds')
                block_ip(individual_ip.ip.src)
        
        if (IP_count > threshold_high): #check for an attack for multiple different IPs. 
            print(f'Frequncy of packets too high within 5 seconds')
            for massBlock in copy:
                if "IP" in massBlock:
                    if fiveSec_check not in real_ip:
                        block_ip(massBlock.ip.src)
                    
        for sourceIP in ipAddressSRC_unique: #check for a high frequncy of an IP from the start of the IDPS.
            srcFrequncy = 0
            for sourceIP1 in ipAddressSRC:
                if sourceIP1 == sourceIP:
                    srcFrequncy+=1
            if (srcFrequncy >= threshold): 
                if (sourceIP not in ipAddress_blocked):
                    print(f'high packet activity since IDPS launch Source IP: {sourceIP}, Frequncy: {srcFrequncy}')
                
    except:
        pass
#This function is to detect a packet that has a payload that is malicous. 
def malicous_payload_detection(copy): 
    try:
        for command_detect in copy:
            if "IP" in command_detect and "TCP" in command_detect:
                malicious_ip = command_detect.ip.src
                
                if hasattr(command_detect.tcp, 'payload'):
                    print(f'{malicious_ip} has a payload')
                    payloadrRaw = command_detect.tcp.payload.replace(':', '') #makes ":" into spaces
                    payloadToBytes = bytes.fromhex(payloadrRaw)
                    payloadRead = payloadToBytes.decode('utf-8', errors='ignore') #This is the actaully payload in readable language. 
                    
                    for check in signatures: #checks signatures if the payload is in that list. 
                        if check in payloadRead and malicious_ip not in ipAddress_blocked:
                            print(f'{malicious_ip} has a command of {payloadRead}')
                            block_ip(malicious_ip)
                            break                
    except:
        pass
#This function is to look for a spoofed packet. 
def spoof_packet(copy):
    try:
        for spoof in copy:
            if "IP" in spoof:
                spoof_ip = spoof.ip.src
                
                ttl_packet = int(spoof.ip.ttl)

                #checks for the spoofed packet based on this range.
                if (ttl_packet < 30 or ttl_packet > 80) and spoof_ip not in ipAddress_blocked: 
                    print(f'{spoof_ip} has a ttl of {ttl_packet}')
                    block_ip(spoof_ip)
                
    except:
        pass

#this function is to make the 5 second interval of packets. 
def five_sec_interval(copy):
    start = 0
    packet_analyze = []
    for packet in copy:
        packet_time = packet.sniff_time  
    
        if start == 0: #get the first packet time. 
            start = packet_time
        
        end_time = start + timedelta(seconds=5) #define interval end time. 
        
        if packet_time < end_time: #saving the packets.
            packet_analyze.append(packet)
        else:
            break
    return(packet_analyze)

while(True): #while loop to continuously sniff the network. 
    print("Scan for 1 seconds")
    liveCapture = pyshark.LiveCapture(interface="enp0s3", output_file="pyshark.pcap") #sniffing the network.
    try:
        liveCapture.sniff(timeout=1) #sniff for 1 second.
        liveCapture.close()
        with pyshark.FileCapture("pyshark.pcap", keep_packets=False) as file_capture:
            packetCapture = list(file_capture)
        #this part below is calling the functions and analyzing the packets. 
        copy = packetCapture
        sortIPaddress(copy)
        five_sec_pac = five_sec_interval(copy)
        ipAddress_Source_Frequncy_ddos(five_sec_pac)
        malicous_payload_detection(copy)
        spoof_packet(copy)
    except:
        pass

    
    


