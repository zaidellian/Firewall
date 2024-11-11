from scapy.all import sniff, IP, TCP, UDP  #tools to capture packets and read network layers

#IP addresses to block
blocked_ips = ["192.168.1.100"]  #block all packets from or to this IP

#list of ports to block
blocked_ports = [80, 443]  #block HTTP (80) and HTTPS (443) traffic

#check if we should allow or block a packet
def check_packet(packet):
    #check if the packet has an IP layer (contains IP info)
    if IP in packet:
        src_ip = packet[IP].src  #get source IP address (where the packet is coming from)
        dst_ip = packet[IP].dst  #get destination IP address (where the packet is going to)

        #if the source or destination IP is in our blocked list, we block it
        if src_ip in blocked_ips or dst_ip in blocked_ips:
            print(f"Blocked packet from/to blocked IP: {src_ip} -> {dst_ip}")
            return False  #return False to show this packet is blocked

    #check if the packet has a TCP or UDP layer (contains port info)
    if TCP in packet or UDP in packet:
        #use TCP or UDP layers to find the source and destination ports
        if TCP in packet:
            src_port = packet[TCP].sport  #source port
            dst_port = packet[TCP].dport  #destination port
        else:
            src_port = packet[UDP].sport  #source port
            dst_port = packet[UDP].dport  #destination port

        # If the source or destination port is in our blocked list, we block it
        if src_port in blocked_ports or dst_port in blocked_ports:
            print(f"Blocked packet from/to blocked port: {src_port} -> {dst_port}")
            return False  #packet is blocked too

    #if the packet doesn't match any blocking rules, allow it
    return True

#start our firewall and sniff packets
def run_firewall():
    print("Firewall is running...")  #show that the  firewall is active
    #capture packets in real-time and check each one with check_packet function
    sniff(prn=lambda packet: check_packet(packet), store=False)

#run the firewall only if we run this script directly
if __name__ == "__main__":
    run_firewall()
