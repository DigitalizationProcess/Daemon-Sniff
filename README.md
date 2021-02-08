# Daemon-Sniff
Service that collects statistics about network traffic. 
1. Daemon sniffs packets from a particular interface. 
    Daemon ip addresses of incoming and out-coming packets and number of packets from each ip. 
2. Time complexity for ip search log(N). 
3. Statistics persistent through reboots. 
4. Command line interface (cli)  implemented - another process that interacts with the daemon. 
5. The cli support command: 	a. start (packets are being sniffed from now on from default iface(eth0)) 
	b. stop (packets are not sniffed)
	c. show [ip] count (print number of packets received from ip address) 
	d. select iface [iface] /under construction/
	e. stat [iface] show collected statistics /partly arranged/
	f. --help (show usage information) 

gcc main.c data_flow.c data_process.c -o testDaemon -Wall
