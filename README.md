# Daemon-Sniff
Service that collects statistics about network traffic. 
1. Daemon sniffs packets from a particular interface. 
    Daemon ip addresses of incoming and out-coming packets and number of packets from each ip. 
2. Time complexity for ip search log(N). 
3. Statistics persistent through reboots. 
4. Command line interface (cli)  implemented - another process that interacts with the daemon. 
5. The Daemon support command at start:

	a. -- help 	- show usage information and available interfaces
	
	b. start	- start Daemon to collect statistics for all available interfaces
	
	c. start [iFace]- start Daemon to collect statistics for [iFace] interface
	
	d. 		- start command line interface
	
6. The cli support commands:

	a. start 	- checks if the daemon is turned ON and starts sniffing if it was turned OFF before
	
	b. stop		- checks if the daemon is turned OFF and stop sniffing if it was turned ON before
	
	c. show [ip] count - print number of packets with [IP] 
	
	d. stat [iface] - show collected statistics for current iFace
	
	e. flush	- enable writing statistics to file dmnsnf_[iFace].dat
	
			  where  [iFace] current network interface
			  
			  above mentioned file will be crearted in working directory
			  
	f. q		- quit
	
	g. DOWN		- shutdown Daemon
	
	h. --help 	- show usage information

gcc main.c data_flow.c data_process.c data_cli.c -o testDaemon -Wall

to start Daemon use
./testDaemon start
