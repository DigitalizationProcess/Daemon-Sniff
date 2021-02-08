#ifndef _DAEMON_SNIFF_H
#define _DAEMON_SNIFF_H

#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <errno.h>
#include <fcntl.h>
#include <ifaddrs.h>
#include <limits.h>
#include <netdb.h>
#include <unistd.h>

#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/un.h>

#include <arpa/inet.h>
#include <netdb.h>
#include <net/if.h>
#include <net/ethernet.h>			  //ether_header

#include <netinet/ip_icmp.h>		//icmp header declarations
#include <netinet/udp.h>				//udp header declarations
#include <netinet/tcp.h>				//tcp header declarations
#include <netinet/in.h>         //sockaddr_in
#include <netinet/ip.h>				  //ip header declarations
#include <netinet/if_ether.h>	  //ETH_P_ALL

#include <linux/if_link.h>
#include <linux/wireless.h>

#define SOCKET_NAME "/tmp/9Lq7BNBnBycd6nxy.socket"
#define BUFFER_SIZE 200

#define BUFF_SIZE           100
#define PACKET_BUFF_SIZE    8192

#define ANSI_COLOR_RED     "\x1b[31m"
#define ANSI_COLOR_GREEN   "\x1b[32m"
#define ANSI_COLOR_CYAN    "\x1b[36m"
#define ANSI_COLOR_RESET   "\x1b[0m"

unsigned int iFace;

struct addrIP
{
   char ip_addr[16];
   unsigned int ip_int;
   int quantity;
};

/*
data_flow.c
*/

int check_wireless(const char* ifname);
void list_devices();
void start_daemon(unsigned int iface);
int sniffer(unsigned int iface);
void cmnd_line_interface(void);

/*
data_process.c
*/
void structuredArrayPrint(struct addrIP *arr, int lenArr);
void structuredArraySortAscending(struct addrIP *arr, int lenArr);
bool structuredArrayFindData(struct addrIP *arr, int *lenArr, char ipToFind[]);
int structuredArrayFindDataQTTY(struct addrIP *arr, int *lenArr, char ipToFind[]);

#endif
