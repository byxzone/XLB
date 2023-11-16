/* SPDX-License-Identifier: GPL-2.0 */
static const char *__doc__ = "XLB MAP program\n";

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <getopt.h>

#include <locale.h>
#include <unistd.h>
#include <time.h>

#include <bpf/bpf.h>

#include <bpf/libbpf.h> /* libbpf_num_possible_cpus */

#include <net/if.h>
#include <linux/if_link.h> /* depend on kernel-headers installed */

#include "xlb_map.h"

static const struct option_wrapper long_options[] = {
	{{"help",        no_argument,		NULL, 'h' },
	 "Show help", false},

	{{"dev",         required_argument,	NULL, 'd' },
	 "Operate on device <ifname>", "<ifname>", true},

	{{"quiet",       no_argument,		NULL, 'q' },
	 "Quiet mode (no output)"},

	{{0, 0, NULL,  0 }}
};

//maps fd
int global_config_map;
int servs_map_ipv4;
int rs_info_map;

//global config
__u32 global_config[last];

void set_global_config(){
	global_config[max_rs_count] = 2;
}

//libxdp cfg
struct config cfg = {
	.ifindex   = -1,
	.do_unload = false,
};

int init_test_data(){
	rs_id rid;
	struct rs_info rs1 = {.mac = {0x52, 0x54, 0x00, 0x31, 0x6a, 0xb6}, .weight = 4};
	struct rs_info rs2 = {.mac = {0x52, 0x54, 0x00, 0xcc, 0xca, 0xa9}, .weight = 3};

	struct serv_key_ipv4 s1_k = {.ipaddr = 3232266853, .port = 80};
	struct serv_val_ipv4 s1_v = {.lb_alg = wrr, .lb_mode = dr};

	bpf_map_update_elem_check(servs_map_ipv4, &s1_k, &s1_v, BPF_ANY);
	rid = 1;
	bpf_map_update_elem_check(rs_info_map, &rid, &rs1, BPF_ANY);
	rid = 2;
	bpf_map_update_elem_check(rs_info_map, &rid, &rs2, BPF_ANY);

	return 1;
}

int init_config_map(){
	int i;

	set_global_config();

	for(i = begin + 1; i < last; i++){
		int key = i;
		int val = global_config[i];
		if(!bpf_map_update_elem_check(global_config_map, &key, &val, BPF_ANY)){
			fprintf(stderr, "ERR: init_config_map(key:%d,val:%d)\n",key, val);
			return -1;
		}
	}

	return 1;
} 

int init_map(){
	if(!init_config_map())
		goto err_init_map;

	if(!init_test_data())
		return -1;

    return 1;

err_init_map:
	if(verbose) fprintf(stderr, "ERR: init_map\n");
	return -1;
}

int main(int argc, char **argv)
{
	/* Cmdline options can change progname */
	parse_cmdline_args(argc, argv, long_options, &cfg, __doc__);

	/* Required option */
	if (cfg.ifindex == -1) {
		fprintf(stderr, "ERR: required option --dev missing\n\n");
		usage(argv[0], __doc__, long_options, (argc == 1));
		return EXIT_FAIL_OPTION;
	}

	global_config_map  = open_map(cfg.ifname, "global_config_map");
	servs_map_ipv4 = open_map(cfg.ifname, "servs_map_ipv4");
	rs_info_map = open_map(cfg.ifname, "rs_info_map");

    if(!global_config_map || !servs_map_ipv4 || !rs_info_map){
        return EXIT_FAIL_BPF;
    }

    init_map();
	
	return EXIT_OK;
}
