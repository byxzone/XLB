#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include "metric.h"

int inited;
int nproc; //number of processers

int init_metric_module()
{
    nproc = sysconf(_SC_NPROCESSORS_ONLN);
    if (nproc < 0) {
        perror("Error getting number of processors");
        return -1;
    }
    #ifdef DEBUG_PRINT
    printf("Number of CPUs: %d\n", nproc);
    #endif

    inited = 1;
    return 1;
}


int exit_metric_module()
{
    inited = 0;
    return 1;
}

int get_loadavg(int *load)
{
    FILE *loadavg_file;
    double load_raw[3];

    if(inited == 0){
        perror("Error Using the metric module before init");
        return -1;
    }

    loadavg_file = fopen("/proc/loadavg", "r");
    if (loadavg_file == NULL) {
        perror("Error opening file");
        return -1;
    }
    
    int res = fscanf(loadavg_file, "%lf %lf %lf", &load_raw[0], &load_raw[1], &load_raw[2]);

    load[0] = (int)((load_raw[0]*100)/nproc);
    load[1] = (int)((load_raw[1]*100)/nproc);
    load[2] = (int)((load_raw[2]*100)/nproc);

    if(!fclose(loadavg_file))
        return -1;

    return res;
}

int test_main() {
    init_metric_module();
    int load[3];
    get_loadavg(load);
    printf("%d,%d,%d",load[0],load[1],load[2]);
    return 0;
}