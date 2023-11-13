/* SPDX-License-Identifier: GPL-2.0 */
#include <linux/bpf.h>
#include <linux/in.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#include "common_kern_user.h" 
#include "../common/parsing_helpers.h"

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__type(key, __u32);
	__type(value, struct datarec);
	__uint(max_entries, XDP_ACTION_MAX);
} xdp_stats_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, __u32);
	__type(value, __u32);
	__uint(max_entries, 1024);
} global_config_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, struct serv_key_ipv4);
	__type(value, struct serv_val_ipv4); 
	__uint(max_entries, 1024);
} servs_map_ipv4 SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, rs_id);
	__type(value, struct rs_info); 
	__uint(max_entries, 1024);
} rs_info_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__type(key, struct conn_ipv4);
	__type(value, rs_id); 
	__uint(max_entries, 10240);
} conn_hash_map SEC(".maps");

static __always_inline
__u32 xdp_stats_record_action(struct xdp_md *ctx, __u32 action)
{
	void *data_end = (void *)(long)ctx->data_end;
	void *data     = (void *)(long)ctx->data;

	if (action >= XDP_ACTION_MAX)
		return XDP_ABORTED;

	/* Lookup in kernel BPF-side return pointer to actual data record */
	struct datarec *rec = bpf_map_lookup_elem(&xdp_stats_map, &action);
	if (!rec)
		return XDP_ABORTED;

	/* Calculate packet length */
	__u64 bytes = data_end - data;

	/* BPF_MAP_TYPE_PERCPU_ARRAY returns a data record specific to current
	 * CPU and XDP hooks runs under Softirq, which makes it safe to update
	 * without atomic operations.
	 */
	rec->rx_packets++;
	rec->rx_bytes += bytes;

	return action;
}

struct wrr_loop_ctx{
	__u32 max_weight;
	rs_id max_rid;
};

static int find_rs_wrr_loop_callback(__u32 index, void *ctx)
{
	struct rs_info *p_rs_info;
	struct wrr_loop_ctx *c = (struct wrr_loop_ctx *)ctx;

	index += 1;
	p_rs_info = bpf_map_lookup_elem(&rs_info_map, &index);

	if(!p_rs_info){
		bpf_printk("XLB ERR: rs(rid %u) info cannot find in map(wrr_loop)", index);
		return 1; //in bpf_loop, when ret = 1 then exit the loop
	}
	
	if(p_rs_info->weight > c->max_weight){
		c->max_weight = p_rs_info->weight;
		c->max_rid = index;
	}
	
	return 0;
}

static __always_inline
rs_id find_rs_wrr(){
	int cfg_k = max_rs_count;
	int looped = 0;
	struct wrr_loop_ctx ctx = {.max_weight = 0, .max_rid = 0};

	__u32 *p_max_rs_count = bpf_map_lookup_elem(&global_config_map, &cfg_k);
	if(!p_max_rs_count){
		bpf_printk("XLB ERR: global_config[max_rs_count] cannot find in map");
		return 0;
	}

	looped = bpf_loop(*p_max_rs_count, find_rs_wrr_loop_callback, &ctx, 0);
	if(looped < *p_max_rs_count){
		bpf_printk("XLB ERR: find_rs_wrr_loop failed(%u<%u)",looped, *p_max_rs_count);
		return 0;
	}
	
	return ctx.max_rid;
}

static __always_inline
xdp_act direct_ipv4_dr(rs_id rid, struct ethhdr *p_eth)
{
	struct rs_info *p_rs_info = bpf_map_lookup_elem(&rs_info_map, &rid);
	if(!p_rs_info){	
		bpf_printk("XLB ERR: rs(rid %u) info cannot find in map, cannot direct!", rid);
		return XDP_PASS;
	}

	if(p_rs_info->weight <= MIN_WEIGHT){
		bpf_printk("XLB ERR: rs(rid %u) weight is %u (<= %d), cannot direct!", rid, p_rs_info->weight, MIN_WEIGHT);
		return XDP_PASS;
	}

	__builtin_memcpy(p_eth->h_source, p_eth->h_dest, ETH_ALEN);
	__builtin_memcpy(p_eth->h_dest, p_rs_info->mac, ETH_ALEN);

	#ifdef DEBUG_PRINT	
	__u32 u_mac1;
	__u16 u_mac2;
	__builtin_memcpy(&u_mac1, p_rs_info->mac, 4);
	__builtin_memcpy(&u_mac2, p_rs_info->mac+4, 2);
	bpf_printk("XLB :redir to rs(%d),mac(%x%x)",rid, bpf_ntohl(u_mac1), bpf_ntohs(u_mac2));
	#endif
	
	return XDP_TX;
}

static __always_inline
xdp_act find_rs_and_direct_ipv4(struct conn_ipv4 *p_conn, struct ethhdr *p_eth, __u8 is_tcp)
{	
	struct serv_key_ipv4 serv_k = {.ipaddr = p_conn -> daddr, .port = p_conn -> dport, .align = 0 };
	struct serv_val_ipv4 *p_serv_v;
	rs_id *p_rid;

	if(is_tcp){
		p_rid = bpf_map_lookup_elem(&conn_hash_map, p_conn);
		if(p_rid){
			if(direct_ipv4_dr(*p_rid, p_eth) == XDP_TX){
				return XDP_TX;
			}
			else{
				bpf_map_delete_elem(&conn_hash_map, p_conn);
			}
		}		
	}

	p_serv_v = bpf_map_lookup_elem(&servs_map_ipv4, &serv_k);
	if(!p_serv_v){

		#ifdef DEBUG_PRINT_EVERY
		if(p_conn-> dport != 22)
			bpf_printk("XLB ERR: service(%u:%u) cannot find in map!",serv_k.ipaddr, serv_k.port);
		#endif

		goto out_err_find_rs_and_direct_ipv4;
	}

	if(p_serv_v -> lb_alg == wrr){
		rs_id rid = find_rs_wrr();

		if(!rid){ // 0 - not found
			bpf_printk("XLB ERR: wrr cannot find rs");
			goto out_err_find_rs_and_direct_ipv4;
		}

		#ifdef DEBUG_PRINT_EVERY
		bpf_printk("conn(%u:%u to %u:%u) find rs(%u)", p_conn->saddr, p_conn->sport, p_conn->daddr, p_conn->dport, rid);
		#endif

		if(is_tcp){
			bpf_map_update_elem(&conn_hash_map, p_conn, &rid, BPF_ANY);
		}
		
		if(p_serv_v -> lb_mode == dr)
			return direct_ipv4_dr(rid, p_eth);
	}

out_err_find_rs_and_direct_ipv4:
	return XDP_PASS;
}

SEC("xdp")
int xdp_entry(struct xdp_md *ctx)
{
	xdp_act action = XDP_PASS; /* XDP_PASS = 2 */
	void *data_end = (void *)(long)ctx->data_end;
	void *data = (void *)(long)ctx->data;
	struct hdr_cursor nh;
	int nh_type; //next header type
	struct ethhdr *eth;
	struct iphdr *iph;
	struct tcphdr *tcph; 
	struct udphdr *udph;
	struct conn_ipv4 conn = {.saddr = 0, .daddr = 0, .sport = 0, .dport = 0};
	__u8 is_tcp = 0;

	nh.pos = data;
	
	nh_type = parse_ethhdr(&nh, data_end, &eth);

	if(nh_type < 0)
		goto out;

	if (nh_type == bpf_htons(ETH_P_IP)) { 

		nh_type = parse_iphdr(&nh, data_end, &iph);

		if(nh_type < 0)
			goto out;
		
		if (nh_type == IPPROTO_TCP) {
			if(parse_tcphdr(&nh, data_end, &tcph) < 0)
				goto out;
			
			conn.sport = bpf_ntohs(tcph -> source);
			conn.dport = bpf_ntohs(tcph -> dest);

			is_tcp = 1;
			
		}
		else if(nh_type == IPPROTO_UDP){
			if(parse_udphdr(&nh, data_end, &udph) < 0){
				goto out;
			}
			conn.sport = bpf_ntohs(udph -> source);
			conn.dport = bpf_ntohs(udph -> dest);
		}

		conn.saddr = bpf_ntohl(iph -> saddr);
		conn.daddr = bpf_ntohl(iph -> daddr);
		
		#ifdef DEBUG_PRINT_EVERY
		if(conn.dport != 22)
			bpf_printk("conn(%u:%u to %u:%u)", conn.saddr, conn.sport, conn.daddr, conn.dport);
		#endif

		action = find_rs_and_direct_ipv4(&conn, eth, is_tcp);
	}
	
		

out:
	return xdp_stats_record_action(ctx, action);
}


char _license[] SEC("license") = "GPL";
