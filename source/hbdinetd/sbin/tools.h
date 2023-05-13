#ifndef __INETD_TOOLS__
#define __INETD_TOOLS__

int get_device_index(const network_device * device, const char * ifname);
int get_if_name(network_device * device);
int get_if_info(network_device * device);
int ifconfig_helper(const char *if_name, const int up);
unsigned int is_if_changed(const network_device * pre, const network_device * now);
int load_device_library(network_device * device);   //, int device_index, char * lib_name);

#endif  // __INETD_TOOLS__
