from scapy.all import sniff, Ether, Dot11
import pandas as pd

# Save data to a csv file
def packet_callback(packet, var):
    if packet.haslayer(var):
        npacket = packet.getlayer(var)
        if var == Ether:
            print("Source MAC:", npacket.src)
            print("Destination MAC:", npacket.dst)
            print("Type:", npacket.type)
            print("Packet Summary:", npacket.summary())
        else:
            print("Source MAC:", npacket.addr2)
            print("Destination MAC:", npacket.addr1)
            print("Type:", npacket.type)
            print("Packet Summary:", npacket.summary())
        df.loc[len(df)] = [npacket.src, npacket.dst, npacket.type, npacket.summary()]
        df.to_csv("packet.csv", index=False)

df = pd.DataFrame(columns=["Source MAC", "Destination MAC", "Type", "Packet Summary"])

# Start sniffing for all packets
interface = input("Enter the interface to sniff on 1) Ether 2) Wlan: ")
if interface == "1":
    sniff(prn=lambda x: packet_callback(x, Ether), store=0)
elif interface == "2":
    sniff(prn=lambda x: packet_callback(x, Dot11), store=0)
else:
    print("Invalid interface")
