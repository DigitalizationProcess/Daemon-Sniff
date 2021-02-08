#include "daemon-sniff.h"

void structuredArrayPrint(struct addrIP *arr, int lenArr)
{
    int i;
    char prefix[100] = "";
    for(i=0; i<lenArr; i++)
    {
      strcpy(prefix,"IP[%d] \t : %s \t with qtty %d. \n");
      if (strlen(arr[i].ip_addr) < 11)
        strcpy(prefix,"IP[%d] \t : %s \t\t with qtty %d. \n");
      printf(prefix, i+1, arr[i].ip_addr, arr[i].quantity);
    }
};

void structuredArraySortAscending(struct addrIP *arr, int lenArr)
//Sort the Array of IP in an Ascending Order to performed quick binary search in next steps.
{
    int i;
    int j;
    struct addrIP addrIPSort;

    for (i = 0; i < lenArr; ++i)
    {
        for (j = i + 1; j < lenArr; ++j)
        {
            if (arr[i].ip_int > arr[j].ip_int)
            {
               addrIPSort = arr[i];
               arr[i] = arr[j];
               arr[j] = addrIPSort;
             }
        }
    }
};

bool structuredArrayFindData(struct addrIP *arr, int *lenArr, char ipToFind[])
{
  int k,nmax,nmin;
  bool solution = false;
  short int av,bv,cv,dv;
  unsigned int ipIntv;

  nmax=*lenArr-1;
  nmin=0;
  k=0;

  //The efficient way of to achieve goal of Log(N) is so called binary search
	//Of course it should be arranged that all IP addresses don't duplicated
	//Hash Map:
  //Convert the range A.B.C.D into a 32-bit integer representing the IP address

  sscanf(ipToFind, "%hd.%hd.%hd.%hd",&av,&bv,&cv,&dv);
  ipIntv = av*16777216+bv*65536+cv*256+dv;
  if (ipIntv == arr[0].ip_int)
  {
            k = 0;
            ++arr[k].quantity;
            solution = true;
  }
  else if (ipIntv == arr[*lenArr-1].ip_int)
  {
                 k = *lenArr-1;
                 ++arr[k].quantity;
                 solution = true;
  }
  else
  {
    k = *lenArr/2;
    solution = false;
    while ((nmax != nmin) && (k != nmax) && (k != nmin))
    {
      if (ipIntv > arr[k].ip_int) {nmin = k;}
      else if (ipIntv < arr[k].ip_int) {nmax = k;}
           else if (ipIntv == arr[k].ip_int)
           {
             nmax = k;
             nmin = k;
             ++arr[k].quantity;
             solution = true;
           }
      k = nmin + (nmax-nmin)/2;
    }
  }

  if (solution)
  {
         return(true);
  }
  else
  {
         strcpy(arr[*lenArr].ip_addr,ipToFind);
         arr[*lenArr].ip_int=ipIntv;
         arr[*lenArr].quantity=1;
         ++*lenArr;
         structuredArraySortAscending(arr, *lenArr);
         return(false);
  }
};

int structuredArrayFindDataQTTY(struct addrIP *arr, int *lenArr, char ipToFind[])
{
  int k,nmax,nmin,n;
  bool solution = false;
  short int av,bv,cv,dv;
  unsigned int ipIntv;

  nmax=*lenArr-1;
  nmin=0;
  k=0;

  //The efficient way of to achieve goal of Log(N) is so called binary search
	//Of course it should be arranged that all IP addresses don't duplicated
	//Hash Map:
  //Convert the range A.B.C.D into a 32-bit integer representing the IP address

  sscanf(ipToFind, "%hd.%hd.%hd.%hd",&av,&bv,&cv,&dv);
  ipIntv = av*16777216+bv*65536+cv*256+dv;
  if (ipIntv == arr[0].ip_int)
  {
            k = 0;
            n = arr[k].quantity;
            solution = true;
  }
  else if (ipIntv == arr[*lenArr-1].ip_int)
  {
            k = *lenArr-1;
            n = arr[k].quantity;
            solution = true;
  }
  else
  {
    k = *lenArr/2;
    solution = false;
    while ((nmax != nmin) && (k != nmax) && (k != nmin))
    {
      if (ipIntv > arr[k].ip_int) {nmin = k;}
      else if (ipIntv < arr[k].ip_int) {nmax = k;}
           else if (ipIntv == arr[k].ip_int)
           {
             nmax = k;
             nmin = k;
             n = arr[k].quantity;
             solution = true;
           }
      k = nmin + (nmax-nmin)/2;
    }
  }
  if (solution)
         return(n);
  else
         return(-1);
};
