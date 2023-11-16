#ifndef __COMMON_H
#define __COMMON_H

#ifndef DEBUG_PRINT
#define DEBUG_PRINT
#endif

#define XLB_SERVER_IP_STR "192.168.122.2"
#define XLB_SERVER_PORT 8899

struct load_info{
    int loadavg[3];
};

#endif