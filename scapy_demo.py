from scapy.all import sniff, wrpcap

# Function to handle each packet
def packet_callback(packet):
    print(packet.summary())
    with open("packet_log.txt", "a") as f:
        f.write(str(packet.summary()) + "\n")

#store first 10 packets to pcap file
packets = sniff(filter="tcp port 80",count=50)
wrpcap('captured_packets.pcap', packets)
print("Packets saved to captured_packets.pcap")

# Print next 10 packets on screen and save to text file
sniff(filter="tcp port 80", count=10, prn=packet_callback) #TCP port 80=HTTP; port 443=https
print("Packet details saved to packet_log.txt")
