// gcc main.c data_flow.c data_process.c -o testDaemon -Wall

#include "daemon-sniff.h"

int main(int argc, char *argv[])
{
  char prefix[100] = "";

  if (argc == 1)
  {
    printf("Command Line interface should be started \n");
    cmnd_line_interface();
  }
  else if (argc == 2)
  {
    if (strcmp(argv[1],"--help")==0)
    {
      printf("Help\n");
      printf(" - type sudo %s [start [iFace]] - to start for iFace interface.\n", argv[0]);
      printf(" - type sudo %s [start]         - to start for all available interfaces.\n", argv[0]);
      printf("List of available interfaces :\n");
      list_devices();
      exit(0);
    }
    else if (strcmp(argv[1],"start")==0)
    {
      printf("Daemon should be started for All available interfaces.\n");
      iFace = UINT_MAX; //Defines the maximum value for an unsigned int.
      start_daemon(iFace);
    }
  }
  else if (argc == 3)
  {
    if (strcmp(argv[1],"start")==0)
    {
      iFace = if_nametoindex(argv[2]);
      /* Get the interface index */
      if ((iFace = if_nametoindex(argv[2])) == 0)
      {
        sprintf(prefix,"Failed to obtain interface index for >%s< ...",argv[2]);
        perror (prefix);
        exit (EXIT_FAILURE);
      }
      else
      {
        if_indextoname(iFace, prefix);
        printf("Daemon should be started for interface # %d : %s.\n", iFace, argv[2]);
        start_daemon(iFace);
      }
    }
  }
  else
  {
    printf("Help\n");
    printf(" - type sudo %s [start [iFace]] - to start for iFace interface.\n", argv[0]);
    printf(" - type sudo %s [start]         - to start for all available interfaces.\n", argv[0]);
    printf("List of available interfaces :\n");
    list_devices();
    exit(0);
  }
  return(0);
}
