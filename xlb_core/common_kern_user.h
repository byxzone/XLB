/* This common_kern_user.h is used by kernel side BPF-progs and
 * userspace programs, for sharing common struct's and DEFINEs.
 */
#ifndef __COMMON_KERN_USER_H
#define __COMMON_KERN_USER_H

#include <linux/bpf.h>

typedef __u32 rs_id;
typedef __u32 xdp_act;

//#define DEBUG_PRINT
//#define DEBUG_PRINT_EVERY

#define MIN_WEIGHT 0

struct datarec {
	__u64 rx_packets;
	__u64 rx_bytes;
};

/*
union tcp_flag_u {
	__u8 flag;
	__u8 fin:1,
		 syn:1,
		 rst:1,
		 psh:1,
		 ack:1,
		 urg:1,
		 ece:1,
		 cwr:1;
};
*/

struct conn_ipv4 {
	__u32 saddr;
	__u32 daddr;
	__u16 sport;
	__u16 dport;
};

struct serv_key_ipv4 {
	__u32 ipaddr;
	__u16 port;
	__u16 align;
};

struct serv_val_ipv4 {
	__u8 lb_alg;
	__u8 lb_mode;
};

struct rs_info {
	__u8 mac[6];
	__u32 weight;
};

enum global_cfg { 
	begin = 0, 
	max_rs_count = 1, 
	last 
};

enum lb_algorithm {
	wrr = 1,
	hash = 2 //not support now
};

enum lb_mode{
	dr = 1,
	nat = 2 //not support now
};

#ifndef XDP_ACTION_MAX
#define XDP_ACTION_MAX (XDP_REDIRECT + 1)
#endif

#endif /* __COMMON_KERN_USER_H */
