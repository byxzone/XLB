#ifndef __METRIC_H
#define __METRIC_H

#ifndef DEBUG_PRINT
#define DEBUG_PRINT
#endif

extern int init_metric_module();
extern int exit_metric_module();

extern int get_loadavg(int *load);

#endif