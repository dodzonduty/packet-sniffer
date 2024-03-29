# packet-sniffer
<h1>Objective</h1>
The objective of this project is to develop a packet sniffer capable of analyzing TCP, UDP, Ethernet, and ICMP packets. The packet sniffer will be designed to extract essential information such as source and destination IP addresses, source and destination MAC addresses, and port numbers. Additionally, the project aims to manipulate packet bits to extract sufficient information for further analysis using tools like Wireshark.

<h1>Journey</h1>
1. Exploring Packet Protocols
The journey began with an in-depth exploration of TCP, UDP, Ethernet, and ICMP packet protocols. Understanding the structure and format of these packets was crucial for developing a robust packet sniffer.

2. Writing Code
Once the packet protocols were thoroughly understood, the next step involved writing code to capture and analyze packets. This required implementing algorithms to extract relevant information from the packet headers.

3. Bit Manipulation
One of the significant challenges faced during development was bit manipulation. Extracting essential information from packet headers often required intricate bit manipulation techniques to ensure accurate data extraction.

4. Compatibility with Wireshark
To enhance the usability of the packet sniffer, efforts were made to ensure compatibility with Wireshark. This involved formatting the extracted packet data in a manner that could be easily interpreted and analyzed using Wireshark.

<h1>Functionality</h1>
The packet sniffer developed as part of this project offers the following functionality:

Determination of source and destination IP addresses
Determination of source and destination MAC addresses
Identification of port numbers
Compatibility with Wireshark for further analysis
<h1>Usage</h1>
To use the packet sniffer, simply clone this repo and use sudo to enable the socket server to work properly. The captured packet data will be displayed, providing valuable insights into network traffic
