#include<stdio.h>
#include<stdlib.h>
#include<string.h>
#include<unistd.h>
#include <pthread.h>
#include <sys/types.h>
#include <ifaddrs.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/types.h>

#include "wifi_event.h"
#include "wifi_state_machine.h"
#include "wifi.h"
#include "user_define.h"

extern int disconnecting;
extern int connecting_ap_event_label;
extern wifi_callback global_callback_func;

static int get_net_ip(const char *if_name, char *ip, int *len, int *vflag)
{
    struct ifaddrs * ifAddrStruct = NULL, *pifaddr = NULL;
    void * tmpAddrPtr = NULL;

    *vflag = 0;
    getifaddrs(&ifAddrStruct);
    pifaddr = ifAddrStruct;

    while(pifaddr != NULL) 
    {
       if(pifaddr->ifa_addr->sa_family == AF_INET)          // check it is IP4
       {
            tmpAddrPtr = &((struct sockaddr_in *)pifaddr->ifa_addr)->sin_addr;
            if(strcmp(pifaddr->ifa_name, if_name) == 0)
            {
                inet_ntop(AF_INET, tmpAddrPtr, ip, INET_ADDRSTRLEN);
                *vflag = 4;
                break;
            }
       } 
       else if(pifaddr->ifa_addr->sa_family == AF_INET6)    // check it is IP6
       {
            // is a valid IP6 Address
            tmpAddrPtr = &((struct sockaddr_in *)pifaddr->ifa_addr)->sin_addr;
            if(strcmp(pifaddr->ifa_name, if_name) == 0)
            {
                inet_ntop(AF_INET6, tmpAddrPtr, ip, INET6_ADDRSTRLEN);
                *vflag = 6;
                break;
            }
       }
       pifaddr=pifaddr->ifa_next;
    }

    if(ifAddrStruct != NULL)
        freeifaddrs(ifAddrStruct);

    return 0;
}

int is_ip_exist()
{
    int len = 0;
    int vflag = 0;  // ipv4 or ipv6
    char ipaddr[INET6_ADDRSTRLEN];

    get_net_ip(global_callback_func.device_name, ipaddr, &len, &vflag);
    return vflag;
}

void *udhcpc_thread(void *args)
{
    int len = 0, vflag = 0, times = 0;
    char ipaddr[INET6_ADDRSTRLEN];
    char cmd[256] = {0}, reply[8] = {0};

    // dhcp command
    memset(cmd, 0, 256);
    sprintf(cmd, "%s %s", DHCP_COMMAND_START, global_callback_func.device_name);
    system(cmd);

    memset(cmd, 0, 256);
    if(strlen(DHCP_COMMAND_STOP))
        sprintf(cmd, "%s %s", DHCP_COMMAND_STOP, global_callback_func.device_name);

    // check ip exist
    len = INET6_ADDRSTRLEN;
    times = 0;

    do
    {
        usleep(100000);
        if(disconnecting == 1)
        {
            if(cmd[0])
                system(cmd);
            break;
        }
        get_net_ip(global_callback_func.device_name, ipaddr, &len, &vflag);
        times++;
    }while((vflag == 0) && (times < 400));

    printf("vflag= %d\n",vflag);
    if(vflag != 0)
    {
        set_wifi_machine_state(CONNECTED_STATE);
		set_cur_wifi_event(AP_CONNECTED);
        call_event_callback_function(WIFIMG_NETWORK_CONNECTED, NULL, connecting_ap_event_label);
    }
    else
    {
        // stop dhcpc thread
        if(cmd[0])
            system(cmd);

	    // send disconnect
        memset(cmd, 0, 256);
        sprintf(cmd, "%s", "DISCONNECT");
        wifi_command(cmd, reply, sizeof(reply));

        set_wifi_machine_state(DISCONNECTED_STATE);
		set_cur_wifi_event(OBTAINING_IP_TIMEOUT);
        call_event_callback_function(WIFIMG_CONNECT_TIMEOUT, NULL, connecting_ap_event_label);
    }

    pthread_exit(NULL);
}


void start_udhcpc_thread(void *args)
{
    pthread_t thread_id;
    pthread_create(&thread_id, NULL, &udhcpc_thread, args);
}
