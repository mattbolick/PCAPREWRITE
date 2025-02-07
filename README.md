# PCAPREWRITE
Takes a pcap packet capture file and rewrites the server - client IP address pairs to be in a user defined new subnet. Also rewrites the destination MAC addresses to point to a forwarding router. 
This is intended for rewriting captured packets to be replayed to a test network with a new forwarding router. 

Sample Usage:
python pcap_rewrite.py capturefile.pcap --server_subnet 10.1.2.0/24 --server_mac 00:00:00:00:00:02 --client_subnet 10.1.1.0/24 --client_mac 00:00:00:00:00:01
The program will also prompt you for these values if they aren't provided on the command line. 

What the program does:
1) Use tcpprep with auto=first to discover which packets are server - client and which are client - server.
2) Use tshark to identify server - client IP address pairs. This is flaky so the code throws out invalid responses from tshark.
3) Use tcprewrite iteratively to rewrite the server, client and destination MAC addresses to match user input. This code could be significantly more efficient.
4) Write the new pcap to capturefile_rewritten.pcap.

pcikle_viewer.py is an optional program for displaying the optional .pkl file created by the main program. This file includes the server - client address pairs identified by the program and how it plans to rewrite them. Useful for debugging purposes. 
