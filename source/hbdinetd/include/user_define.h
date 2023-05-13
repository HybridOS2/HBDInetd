#ifndef __USER_DEFINE__H__
#define __USER_DEFINE__H__

// only for develop
#if defined(PLATFORM_R818)
    #define INETD_CONFIG_FILE   "/usr/libexec/inetd.cfg"
    #define INETD_LIBRARY_PATH  "/usr/lib"
    #define DAEMON_WORKING_PATH "/home/gengyue"
#elif defined(PLATFORM_ROCKCHIP)
    #define INETD_CONFIG_FILE   "/userdata/target/usr/libexec/inetd.cfg"
    #define INETD_LIBRARY_PATH  "/userdata/target/usr/lib"
    #define DAEMON_WORKING_PATH "/userdata/target/usr/libexec"
#else
    #define INETD_CONFIG_FILE   "/home/projects/cn.fmsoft.hybridos.settings/inetd/bin/inetd.cfg"
    #define INETD_LIBRARY_PATH  "/home/projects/cn.fmsoft.hybridos.settings/inetd/lib"
    #define DAEMON_WORKING_PATH "/home/gengyue"
#endif

// dhcp command in user board
#define DHCP_COMMAND_START  "dhclient"          // for ubuntu 18.04: dhclient wlan0
#define DHCP_COMMAND_STOP   "dhclient -r"       // for ubuntu 18.04: dhclient -r wlan0 
//#define DHCP_COMMAND_START    "udhcpc -n 5 -i"   // for px30: udhcpc -n 5 -i wlan0
//#define DHCP_COMMAND_STOP     ""                 // for px30: do nothing

#endif      // __USER_DEFINE__H__

