#include "daemon-sniff.h"

int check_wireless(const char* ifname)
{
  int sock = -1;
  struct iwreq pwrq;
  memset(&pwrq, 0, sizeof(pwrq));
  strncpy(pwrq.ifr_name, ifname, IFNAMSIZ);

  if ((sock = socket(AF_INET, SOCK_STREAM, 0)) == -1) {
    perror("socket");
    return 0;
  }
  if (ioctl(sock, SIOCGIWNAME, &pwrq) != -1) {
    //if (protocol) strncpy(protocol, pwrq.u.name, IFNAMSIZ);
    close(sock);
    return 1;
  }
  close(sock);
  return 0;
}

void list_devices()
{
  struct ifaddrs *ifap, *ifa;
  struct sockaddr_in *sa;
  unsigned int ifindex = 0;
  unsigned int tmp_ifindex;
  char *addr, *defdev;

  if (getifaddrs(&ifap) == -1)
  {
      perror("getifaddrs");
      exit(EXIT_FAILURE);
  }

  for (ifa = ifap; ifa!= NULL; ifa = ifa->ifa_next)
  {
      if (ifa->ifa_addr &&
          ifa->ifa_addr->sa_family==AF_INET)
      {
          sa = (struct sockaddr_in *) ifa->ifa_addr;
          addr = inet_ntoa(sa->sin_addr);
          printf("Interface: %s\tAddress: %s\n", ifa->ifa_name, addr);
      }
  }

  ifa = ifap;
	while (ifa)
  {
		if (ifa->ifa_addr &&
        ifa->ifa_addr->sa_family == AF_PACKET &&
		    !check_wireless(ifa->ifa_name) &&
        !(ifa->ifa_flags & IFF_LOOPBACK))
		{
			tmp_ifindex = if_nametoindex(ifa->ifa_name);

			if (ifindex == 0)
      {
				ifindex = tmp_ifindex;
        defdev = ifa->ifa_name;
      }
			else if (ifindex > tmp_ifindex)
      {
      	ifindex = tmp_ifindex;
        defdev = ifa->ifa_name;
      }
		}
		ifa = ifa->ifa_next;
	}
  printf("Default iFace: %s\n", defdev);
  freeifaddrs(ifap);
}

void start_daemon(unsigned int iFace)
{
    /* Process ID and Session ID */
    pid_t pid, sid; // int pidFilehandle;

    /* Fork off the parent process */
    pid = fork();
    if (pid < 0) // check to see if fork() succeeded
    {
        printf("fork filed!\n");
        exit(EXIT_FAILURE);
    }

    /* If we got a good PID, then
    we can exit the parent process. */
    if (pid > 0)
    {
        printf("pid of child process %d \n",pid);
        exit(0);
    }

    /* Change the file mode mask */
    umask(0);

    /* Create a new SID for the child process */
    sid = setsid();
    if (sid < 0)
        exit(EXIT_FAILURE);

    /* Close out the standard file descriptors */
    close(STDIN_FILENO);
    close(STDOUT_FILENO);
    close(STDERR_FILENO);

    sniffer(iFace);

    exit(EXIT_SUCCESS);
}

int sniffer(unsigned int iFace)
{
  int saddr_size, data_size;
  int n;
  int i;
  int j;
  int down_flag = 0;
  int ret;
  int connection_socket;
  int data_socket;
  int d_status;

  unsigned char *buffer_NP = (unsigned char *) malloc(65536);
  memset(buffer_NP,0,65536);

  struct sockaddr saddr;
  struct sockaddr_in source;
  struct sockaddr_in dest;
  struct sockaddr_un name;

  char buffer[BUFFER_SIZE];
  char answer[BUFFER_SIZE];

  char datFileName[255];
  char prefix[100] = "";
  char result[4];
  char * line = NULL;
  size_t len = 0;
  ssize_t read_line;
  fd_set master;
  struct timeval timeout;
  short int av,bv,cv,dv;
  int nv;
  unsigned int mv;
  int fdmax;

  struct addrIP record[10000];
  /*
   yes of course - may be dinamic (growing) array should be implemented
   Fact: The C programming language does not have dynamic array as a language feature
   However: The C programming language does have sufficient number of powerful features
   that a C programmer can implement dynamic array (among other things) using these features !!!
  */

  d_status = 1;

  if (iFace == UINT_MAX) //Defines the maximum value for an unsigned int.
    strcpy(prefix,"all");
  else
    if_indextoname(iFace, prefix);

  strcat(datFileName, "dmnsnf_");
  strcat(datFileName,  prefix);
  strcat(datFileName,  ".dat");

  FILE *fpCheck = NULL;
  fpCheck = fopen(datFileName, "r");
  if (fpCheck)
  {
    //file exists and can be opened
    //read initial data from it and fill into empty "record" array

    n = 0;
    while ((read_line = getline(&line, &len, fpCheck)) != -1)
    {
      i = sscanf(line, "%hd.%hd.%hd.%hd %d %u",&av,&bv,&cv,&dv,&nv,&mv);

      sprintf(result, "%i", av);
      strcpy(record[n].ip_addr, result);
      strcat(record[n].ip_addr, ".");

      sprintf(result, "%i", bv);
      strcat(record[n].ip_addr, result);
      strcat(record[n].ip_addr, ".");

      sprintf(result, "%i", cv);
      strcat(record[n].ip_addr, result);
      strcat(record[n].ip_addr, ".");

      sprintf(result, "%i", dv);
      strcat(record[n].ip_addr, result);

      record[n].ip_int = mv;
      record[n].quantity = nv;

      n++;
    }

    //close file
    fclose(fpCheck);
  }
  else
  {
    /*IPV4*/
    strcpy(record[0].ip_addr, "0.0.0.0");
    record[0].ip_int=0;
    record[0].quantity=0;

    strcpy(record[1].ip_addr, "255.255.255.255");
    record[1].ip_int=4294967295;
    record[1].quantity=0;
    n=2;
  }

  int sock_raw = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
  if (iFace != UINT_MAX)
  {
    //should be enabled to select specified iFace
    if_indextoname(iFace, prefix);
    setsockopt(sock_raw , SOL_SOCKET , SO_BINDTODEVICE , prefix , strlen(prefix)+ 1 );
  }
  if(sock_raw < 0)
  {
    //Print the error with proper message
    perror("Socket Error");
    return 1;
  }

  unlink(SOCKET_NAME);

  connection_socket = socket(AF_UNIX, SOCK_SEQPACKET, 0);
  if (connection_socket == -1)
  {
      perror("socket");
      exit(EXIT_FAILURE);
  }

  memset(&name, 0, sizeof(name));
  name.sun_family = AF_UNIX;
  strncpy(name.sun_path, SOCKET_NAME, sizeof(name.sun_path) - 1);
  ret = bind(connection_socket, (const struct sockaddr *) &name,
             sizeof(name));
  if (ret == -1)
  {
      perror("bind");
      exit(EXIT_FAILURE);
  }

  //Prepare for accepting connections. The backlog size is set
  //to 20. So while one request is being processed other requests can be waiting.
  ret = listen(connection_socket, 20);
  if (ret == -1)
  {
      perror("listen");
      exit(EXIT_FAILURE);
  }

  i = 0;
  // This is the main loop for handling connections.

  for (;;)
  {
    timeout.tv_sec = 0;
    timeout.tv_usec = 5000;
    FD_ZERO(&master);    // clear the master set
    // add the connection_socket to the master set
    FD_SET(sock_raw,          &master);
    FD_SET(connection_socket, &master);
    // keep track of the biggest file descriptor
    if (sock_raw > connection_socket)
    {
      fdmax = sock_raw;
    }
    else if (sock_raw < connection_socket)
    {
      fdmax = connection_socket;
    }
    else if (sock_raw == connection_socket)
    {
      fdmax = sock_raw;
    }
    //read_fds = master;
    ret = select(fdmax+1, &master, NULL, NULL, &timeout);
    if (ret < 0)
    {
        perror("Server: select result negative");
        //exit(4);
        return -1;
    }

    if ((FD_ISSET(sock_raw, &master)) && (ret >0) && (d_status == 1))
    {
      saddr_size = sizeof(saddr);
      //Receive a packet
      data_size = recvfrom(sock_raw , buffer_NP , 65536 , 0 , &saddr , (socklen_t*)&saddr_size);
      if(data_size <0 )
        {
          printf("Recvfrom error , failed to get packets\n");
          return 1;
        }
      //Process the packet
      //Get the IP Header part of this packet , excluding the ethernet header
      struct iphdr *iph = (struct iphdr*)(buffer_NP + sizeof(struct ethhdr));
      memset(&source, 0, sizeof(source));
      source.sin_addr.s_addr = iph->saddr;
      memset(&dest, 0, sizeof(dest));
      dest.sin_addr.s_addr = iph->daddr;
      if (structuredArrayFindData(record, &n, inet_ntoa(source.sin_addr))) {};
      if (structuredArrayFindData(record, &n, inet_ntoa(dest.sin_addr))) {};
    }
    if ((FD_ISSET(connection_socket, &master)) && (ret >0))
    {
      //accept connection
      data_socket = accept(connection_socket, NULL, NULL);
      if (data_socket == -1)
      {
        perror("accept");
        exit(EXIT_FAILURE);
      }

      ret = read(data_socket, buffer, sizeof(buffer));
      if (ret == -1)
      {
            perror("read");
            exit(EXIT_FAILURE);
      }

      /* Ensure buffer is 0-terminated. */
      buffer[sizeof(buffer) - 1] = 0;

      /* Handle commands. */
      if (!strncmp(buffer, "DOWN", sizeof(buffer)))
      {
            sprintf(answer, "SRV:%s", "DOWN");
            down_flag = 1;
            //break;
      }

      if (!strncmp(buffer, "flush", sizeof(buffer)))
      {
            sprintf(answer, "SRV:%s", "flush");
            FILE *fpFlush= NULL;
            fpFlush = fopen(datFileName, "w+");
            for(i=0; i < n; i++)
            {
              fprintf(fpFlush, "%s %d %u\n",record[i].ip_addr, record[i].quantity, record[i].ip_int);
            }
            fflush(fpFlush);
            fclose(fpFlush);
      }

      if (!strncmp(buffer, "ABCD", sizeof(buffer)))
      {
            sprintf(answer, "SRV:%s", "ABCD");
            //break;
      }

      if (!strncmp(buffer, "show", 4))
      {
            strncpy(prefix, &buffer[5], sizeof(buffer)-5);
            j = structuredArrayFindDataQTTY(record, &n, prefix);
            sprintf(answer, "SRV: qtty for IP %s : %d\n", prefix, j);
            //break;
      }

      if (!strncmp(buffer, "start", 5))
      {
        if (d_status == 0)
        {
          d_status = 1;
          sprintf(answer, "SRV:%s", "daemon status switched to On");
        }
        else if (d_status == 1)
        {
          d_status = 1;
          sprintf(answer, "SRV:%s", "daemon status already On");
        }
      }
      if (!strncmp(buffer, "stop", 4))
      {
        if (d_status == 0)
        {
          d_status = 0;
          sprintf(answer, "SRV:%s", "daemon status already Off");
        }
        else if (d_status == 1)
        {
          d_status = 0;
          sprintf(answer, "SRV:%s", "daemon status switched to Off");
        }
      }

      if (!strncmp(buffer, "END", sizeof(buffer)))
      {
        sprintf(answer, "SRV:%s", "END");
        //break;
      }

      ret = write(data_socket, answer, sizeof(answer));
      if (ret == -1)
      {
          perror("write");
          exit(EXIT_FAILURE);
      }

      /* Close socket. */
      close(data_socket);

      // Quit on DOWN command.
      if (down_flag)
      {
        FILE *fpEnd= NULL;
        fpEnd = fopen(datFileName, "w+");
        for(i=0; i < n; i++)
        {
          fprintf(fpEnd, "%s %d %u\n",record[i].ip_addr, record[i].quantity, record[i].ip_int);
        }
        fflush(fpEnd);
        fclose(fpEnd);
        break;
      }
    }
  }

  unlink(SOCKET_NAME);
  exit(EXIT_SUCCESS);

}

void talk_with_daemon(char *buffer, int length)
 {
   struct sockaddr_un addr;
   int ret;
   int data_socket;
   char bufferA[BUFFER_SIZE];
   char prefix[100] = "";

   // Create local socket.
   data_socket = socket(AF_UNIX, SOCK_SEQPACKET, 0);
   //data_socket = socket(AF_UNIX, SOCK_STREAM, 0);
   if (data_socket == -1) {
       perror("socket");
       exit(EXIT_FAILURE);
   }
   memset(&addr, 0, sizeof(addr));

   /* Connect socket to socket address */
   addr.sun_family = AF_UNIX;
   strncpy(addr.sun_path, SOCKET_NAME, sizeof(addr.sun_path) - 1);

   ret = connect(data_socket, (const struct sockaddr *) &addr,
                  sizeof(addr));
   if (ret == -1) {
       fprintf(stderr, "The server is down.\n");
       exit(EXIT_FAILURE);
   }

   strcpy(prefix, buffer);
   ret = write(data_socket, prefix, strlen(prefix) + 1);
   if (ret == -1)
   {
       perror("write");
       exit(EXIT_FAILURE);
   }

   ret = read(data_socket, bufferA, sizeof(bufferA));
   if (ret == -1)
   {
       perror("read");
       exit(EXIT_FAILURE);
   }
   /* Ensure buffer is 0-terminated. */
   bufferA[sizeof(bufferA) - 1] = 0;
   // printf("Answer = %s\n", buffer);

   strcpy(buffer,bufferA);
}

void cmnd_line_interface(void)
{
    char buff[BUFF_SIZE];
    char *argum1;
    char *argum2;
    char *argum3;
    char sep[] = " \n\t";
    struct addrIP dataS;
    size_t len = 0;
    ssize_t read_line;
    FILE * fp;
    char result[4];
    char checkIP[100];
    int j;
    char * line = NULL;
    short int av,bv,cv,dv;
    int nv;
    unsigned int mv;

    printf("Command Line interface already started.\n");

    printf(ANSI_COLOR_RED "daemon-with-sniff> " ANSI_COLOR_RESET);

    while (fgets(buff, BUFF_SIZE, stdin) != NULL)
    {
        argum1 = strtok(buff, sep);
        argum2 = strtok(NULL, sep);
        argum3 = strtok(NULL, sep);

        if (argum1 && !argum2 && !argum3 && !strcmp("start", argum1))
        {
          strcpy(buff,"start");
          talk_with_daemon(buff, sizeof(buff));
          printf("%s\n", buff);
        }

        if (argum1 && !argum2 && !argum3 && !strcmp("stop", argum1))
        {
          strcpy(buff,"stop");
          talk_with_daemon(buff, sizeof(buff));
          printf("%s\n", buff);
        }

        if (argum1 && !argum2 && !argum3 && !strcmp("stat", argum1))
        {
          strcpy(buff,"flush");
          talk_with_daemon(buff, sizeof(buff));
          printf("%s\n", buff);
          printf("QTTY \t IP \n");

          fp = fopen("dmnsnf_eno1.dat", "r"); //!!!! should be changed accordingly
          // dmnsnf_eno1.dat filled with abstract data is added
          if (fp == NULL)
          {
              printf("NULL");
              exit(EXIT_FAILURE);
          }

          j = 0;
          while ((read_line = getline(&line, &len, fp)) != -1)
          {
            sscanf(line, "%hd.%hd.%hd.%hd %d %u",&av,&bv,&cv,&dv,&nv,&mv);

            sprintf(result, "%i", av);
            strcpy(dataS.ip_addr, result);
            strcat(dataS.ip_addr, ".");

            sprintf(result, "%i", bv);
            strcat(dataS.ip_addr, result);
            strcat(dataS.ip_addr, ".");

            sprintf(result, "%i", cv);
            strcat(dataS.ip_addr, result);
            strcat(dataS.ip_addr, ".");

            sprintf(result, "%i", dv);
            strcat(dataS.ip_addr, result);

            dataS.ip_int = mv;
            dataS.quantity = nv;

            printf("%d \t %s \n", dataS.quantity, dataS.ip_addr);
            j++;
          }
          fclose(fp);
        }

        if (argum1 && !argum2 && !argum3 && !strcmp("flush", argum1))
        {
          strcpy(buff,"flush");
          talk_with_daemon(buff, sizeof(buff));
          printf("%s\n", buff);
        }

        if (argum1 && argum2 && argum3 && !strcmp("show", argum1) && !strcmp("count", argum3))
        {
          strcpy(checkIP, argum1);
          strcat(checkIP, " ");
          strcat(checkIP, argum2);
          strcpy(buff,checkIP);
          talk_with_daemon(buff, sizeof(buff));
          printf("%s\n", buff);

        }

        if (argum1 && !argum2 && !argum3 && !strcmp("DOWN", argum1))
        {
          strcpy(buff,"DOWN");
          talk_with_daemon(buff, sizeof(buff));
          printf("%s\n", buff);
          exit(0);
        }

        if (argum1 && !argum2 && !argum3 && !strcmp("q", argum1))
        {
          exit(0);
        }

        if (argum1 && !argum2 && !argum3 && !strcmp("--help", argum1))
        {
          printf(">start<            check if daemon in switched On and start it if necessary\n");
          printf(">stop<             check if daemon in switched Off and stop it if necessary\n");
          printf(">show [IP] count<  print number of packets with [IP] \n");
          printf(">stat<             show collected statistics\n");
          printf(">flush<            enable writing statistics to file dmnsnf_[iFace].dat\n");
          printf("                    - where [iFace] current network interface\n");
          printf("                    - above mentioned file will be crearted in working directory\n");
          printf(">q<                quit\n");
          printf(">--help<           this info\n");
        }
        printf(ANSI_COLOR_RED "daemon-with-sniff> " ANSI_COLOR_RESET);
      }
  exit(EXIT_SUCCESS);
}
