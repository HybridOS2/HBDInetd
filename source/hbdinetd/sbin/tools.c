#include "tools.h"

extern void report_wifi_scan_info(char * device_name, int type, void * hotspots, int number);

// get device index from device array
int get_device_index(const network_device * device, const char * ifname)
{
    int i = 0;
    int find_index = -1;

    for(i = 0; i < MAX_DEVICE_NUM; i++)
    {
        if((ifname != NULL) && device[i].ifname[0] && (strncasecmp(device[i].ifname, ifname, strlen(ifname)) == 0))
        {
            find_index = i;
            break;
        }
    }

    return find_index;
}

unsigned int is_if_changed(const network_device * pre, const network_device * now)
{
    int changed = 0;

    if((pre == NULL) || (now == NULL))
        return changed;

    if(strcmp(pre->ifname, now->ifname))
        changed |= NETWORK_CHANGED_NAME;
    if(pre->type != now->type)
        changed |= NETWORK_CHANGED_TYPE;
    if(pre->status != now->status)
        changed |= NETWORK_CHANGED_STATUS;
    if(strcmp(pre->mac, now->mac))
        changed |= NETWORK_CHANGED_MAC;
    if(strcmp(pre->ip, now->ip))
        changed |= NETWORK_CHANGED_IP;
    if(strcmp(pre->broadAddr, now->broadAddr))
        changed |= NETWORK_CHANGED_BROADCAST;
    if(strcmp(pre->subnetMask, now->subnetMask))
        changed |= NETWORK_CHANGED_SUBNETMASK;
        
    return changed;
}

// ifconfig ifname up|down
int ifconfig_helper(const char *if_name, const int up)
{
    int fd;
    struct ifreq ifr;

    if((fd = socket(AF_INET, SOCK_STREAM, 0)) < 0) 
        return -1;

    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, if_name, IFNAMSIZ);

    if(ioctl(fd, SIOCGIFFLAGS, &ifr) != 0) 
    {
        close(fd);
        return -2;
    }

    if(up)
        ifr.ifr_flags |= IFF_UP;
    else
        ifr.ifr_flags &= ~IFF_UP;

    if(ioctl(fd, SIOCSIFFLAGS, &ifr) != 0) 
    {
        close(fd);
        return -3;
    }

    close(fd);

    return 0;
}

// get device: status, mac, ip, broadcast, subnetmask, speed
int get_if_info(network_device * device)
{
    struct ifreq ifr;
    struct iwreq wrq;
    int socket_fd = -1;
    int ret = 0;

    if((socket_fd = socket(AF_INET, SOCK_DGRAM, 0)) < 0)
        return -1;

    // initialize
    device->type = DEVICE_TYPE_UNKONWN;
    device->status = DEVICE_STATUS_UNCERTAIN;
    memset(device->mac, 0, NETWORK_ADDRESS_LENGTH);
    memset(device->ip, 0, NETWORK_ADDRESS_LENGTH);
    memset(device->broadAddr, 0, NETWORK_ADDRESS_LENGTH);
    memset(device->subnetMask, 0, NETWORK_ADDRESS_LENGTH);
    device->speed = 0;

    // set device interface name
    memset(&ifr, 0, sizeof(ifr));
    strcpy(ifr.ifr_name, device->ifname);

    // get device status: down or up
    if(ioctl(socket_fd, SIOCGIFFLAGS, &ifr) != 0) 
    {
        close(socket_fd);
        return -2;
    }
    if(ifr.ifr_flags & IFF_UP)
        device->status = DEVICE_STATUS_UP;
    else
        device->status = DEVICE_STATUS_DOWN;

    if(ifr.ifr_flags & IFF_RUNNING)
        device->status = DEVICE_STATUS_RUNNING;

    // get device type: lo, ethernet, wifi, mobile
    if(ifr.ifr_flags & IFF_LOOPBACK)
        device->type = DEVICE_TYPE_LO;
    else
    {
        strncpy(wrq.ifr_name, device->ifname, IFNAMSIZ);
        ret = ioctl(socket_fd, SIOCGIWNAME, &wrq);
        if(ret < 0)
            device->type = DEVICE_TYPE_ETHERNET;
        else
        {
            device->type = DEVICE_TYPE_WIFI;

            // get wifi speed
            ret = ioctl(socket_fd, SIOCGIWRATE, &wrq);
            if(ret >= 0)
                device->speed = wrq.u.bitrate.value / 1000000;
        }

#ifdef PLATFORM_R818
        if(strncasecmp(device->ifname, "wlan0", strlen(device->ifname)) == 0)
            device->type = DEVICE_TYPE_WIFI;
#endif
    }
    // TODO: how to judge mobile device

    //get the mac of this interface  
    if (!ioctl(socket_fd, SIOCGIFHWADDR, &ifr))
    {
        snprintf(device->mac, sizeof(device->mac), "%02x:%02x:%02x:%02x:%02x:%02x",
                (unsigned char)ifr.ifr_hwaddr.sa_data[0],
                (unsigned char)ifr.ifr_hwaddr.sa_data[1],
                (unsigned char)ifr.ifr_hwaddr.sa_data[2],
                (unsigned char)ifr.ifr_hwaddr.sa_data[3],
                (unsigned char)ifr.ifr_hwaddr.sa_data[4],
                (unsigned char)ifr.ifr_hwaddr.sa_data[5]);
    }

    if(device->status == DEVICE_STATUS_RUNNING)
    {
        //get the IP of this interface  
        if (!ioctl(socket_fd, SIOCGIFADDR, &ifr))
        {
            snprintf(device->ip, sizeof(device->ip), "%s",
                    (char *)inet_ntoa(((struct sockaddr_in *)&(ifr.ifr_addr))->sin_addr));
        }

        //get the broad address of this interface  
        if(!ioctl(socket_fd, SIOCGIFBRDADDR, &ifr))
        {
            snprintf(device->broadAddr, sizeof(device->broadAddr), "%s",
                    (char *)inet_ntoa(((struct sockaddr_in *)&(ifr.ifr_broadaddr))->sin_addr));
        }

        //get the subnet mask of this interface  
        if (!ioctl(socket_fd, SIOCGIFNETMASK, &ifr))
        {
            snprintf(device->subnetMask, sizeof(device->subnetMask), "%s",
                    (char *)inet_ntoa(((struct sockaddr_in *)&(ifr.ifr_netmask))->sin_addr));
        }

    }

    close(socket_fd);

    return 0;
}

// get all network interfaces, no matter active or inactive
int get_if_name(network_device * device)
{
    struct if_nameindex *if_ni = NULL;
    struct if_nameindex *i = NULL;
    int number = 0;

    if_ni = if_nameindex();
    if(if_ni == NULL) 
    {
    }
    else
    {
        for(i = if_ni; !(i->if_index == 0 && i->if_name == NULL); i++)
        {
            strcpy(device[number].ifname, i->if_name);
            get_if_info(&device[number]);
printf("================================ %s: %d, %d, %s, %s, %s, %s, %d\n", device[number].ifname, device[number].type, device[number].status, device[number].ip, device[number].mac, device[number].broadAddr, device[number].subnetMask, device[number].speed);
            ++number;
        }
        if_freenameindex(if_ni);
    }

    return number;
}


//int load_device_library(network_device * device, int device_index, char * lib_name)
int load_device_library(network_device * device)
{
    char library_path[MAX_PATH];
    void * library_handle = NULL;               // handle of loaded library
	char * library_error = NULL;                // the error message during loading

    if(strlen(device->libpath) == 0)
    {   
        fprintf(stderr, "INETD: library path is invalid for device %s!", device->ifname);
        return -1;
    }

    memset(library_path, 0, MAX_PATH);
    sprintf(library_path, "%s/%s", INETD_LIBRARY_PATH, device->libpath);

    if((access(library_path, F_OK)) == -1)   
    {   
        fprintf(stderr, "INETD: library file %s does not exist, ignore it!", library_path);
        return -1;
    }

    library_handle = dlopen(library_path, RTLD_LAZY);  
    if(!library_handle) 
    {
        fprintf (stderr, "INETD: load %s error: %s\n", library_path, dlerror());
        return -1;
    }

    if(device->type == DEVICE_TYPE_WIFI)
    {
	    hiWiFiDeviceOps * (* __wifi_device_ops_get)(void);   // get all invoke functions 
        hiWiFiDeviceOps * wifi_device_Ops = NULL;

        __wifi_device_ops_get = (hiWiFiDeviceOps * (*) (void))dlsym(library_handle, "__wifi_device_ops_get");
        if((library_error = dlerror()) != NULL)
        {
            fprintf(stderr, "INETD: get wifi_init pointer error: %s\n", library_error);
            dlclose(library_handle);
            return -1;
        }
        wifi_device_Ops = __wifi_device_ops_get();

        if(wifi_device_Ops)
        {
            wifi_device_Ops->report_wifi_scan_info = report_wifi_scan_info;

            WiFi_device * wifi_device = (WiFi_device *)device->device; 
            wifi_device->wifi_device_Ops = wifi_device_Ops;
            pthread_mutex_init(&wifi_device->list_mutex, NULL);
            device->lib_handle = library_handle;
        }
        else
        {
            dlclose(library_handle);
            return -1;
        }
    }

    return 0;
}

