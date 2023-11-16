/* SPDX-License-Identifier: GPL-2.0 */
static const char *__doc__ = "XLB SERVER program\n";

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/epoll.h>
#include <signal.h>

#include <bpf/bpf.h>

#include <bpf/libbpf.h> /* libbpf_num_possible_cpus */

#include "xlb_server.h"
#include "rs_hash.h"
#include "../common/common_params.h"
#include "../xlb_core/map_common.h"
#include "../xlb_core/common_kern_user.h"

#include <pthread.h>

#define MAX_CLIENTS 100

int exit_flag = 0;

int rs_info_map;

DHT *rs_id_ip_tbl;

int server_socket;

struct config cfg = {
	.ifindex   = -1,
	.do_unload = false,
};

static const struct option_wrapper long_options[] = {
	{{"help",        no_argument,		NULL, 'h' },
	 "Show help", false},

	{{"dev",         required_argument,	NULL, 'd' },
	 "Operate on device <ifname>", "<ifname>", true},

	{{"quiet",       no_argument,		NULL, 'q' },
	 "Quiet mode (no output)"},

	{{0, 0, NULL,  0 }}
};

void sigint_handler(int signo) {
    if (signo == SIGINT) {
        printf("Received Ctrl+C. Exiting...\n");
        exit_flag = 1;
        close(server_socket);
        exit(1);
    }
}

void init_rs_dht(){
    rs_id_ip_tbl = createDHT(100);
    insertDHT(rs_id_ip_tbl,1,3232266832);
    insertDHT(rs_id_ip_tbl,2,3232266987);
}

int update_rs_info_map(rs_id rid, struct load_info *data){
    struct rs_info rinfo;
    if(bpf_map_lookup_elem(rs_info_map, &rid, &rinfo) !=  0){
        perror("update_rs_info_map");
        return -1;
    }
    if(data->loadavg[0]){
        if(data->loadavg[0] >= 100){
            rinfo.weight = 0;
        }
        else
            rinfo.weight = 100 - data->loadavg[0];
    }
    else
        rinfo.weight = 100;
    bpf_map_update_elem_check(rs_info_map, &rid, &rinfo, BPF_ANY);
    return 1;
}

void *handle_client(void *arg) {
    int client_socket = *((int *)arg);
    free(arg);
    struct sockaddr_in client_addr;
    struct load_info data;
    socklen_t client_addr_len = sizeof(client_addr);

    if (getpeername(client_socket, (struct sockaddr *)&client_addr, &client_addr_len) == -1) {
        perror("Error getting client address");
        close(client_socket);
        pthread_exit(NULL);
    }

    char client_ip_str[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &(client_addr.sin_addr), client_ip_str, INET_ADDRSTRLEN);

    printf("New client from %s\n", client_ip_str);

    while (!exit_flag) {
        ssize_t bytes_received = recv(client_socket, &data, sizeof(struct load_info), 0);

        if (bytes_received <= 0) {
            close(client_socket);
            printf("Client disconnected from %s\n", client_ip_str);
            pthread_exit(NULL);
        }

        __u32 ip_u32 = client_addr.sin_addr.s_addr;

        rs_id rid = findId(rs_id_ip_tbl, ntohl(ip_u32));
        printf("addr:%u,rid:%u\n",ip_u32,rid);
        update_rs_info_map(rid, &data);
        #ifdef DEBUG_PRINT
        printf("\nReceived data from %s,: %d,%d,%d \n",client_ip_str,data.loadavg[0], data.loadavg[1], data.loadavg[2]);
        #endif       
    }

    return NULL;
}

int main(int argc, char **argv) {
    int client_socket;
    struct sockaddr_in server_addr, client_addr;
    socklen_t client_addr_len = sizeof(client_addr);
    pthread_t thread_id;

    /* Cmdline options can change progname */
	parse_cmdline_args(argc, argv, long_options, &cfg, __doc__);

	/* Required option */
	if (cfg.ifindex == -1) {
		fprintf(stderr, "ERR: required option --dev missing\n\n");
		usage(argv[0], __doc__, long_options, (argc == 1));
		return EXIT_FAIL_OPTION;
	}

    rs_info_map = open_map(cfg.ifname, "rs_info_map");

    init_rs_dht();

    signal(SIGINT, sigint_handler);

    if ((server_socket = socket(AF_INET, SOCK_STREAM, 0)) == -1) {
        perror("Error creating socket");
        exit(EXIT_FAILURE);
    }

    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(XLB_SERVER_PORT);
    server_addr.sin_addr.s_addr = INADDR_ANY;

    if (bind(server_socket, (struct sockaddr *)&server_addr, sizeof(server_addr)) == -1) {
        perror("Error binding socket");
        exit(EXIT_FAILURE);
    }

    if (listen(server_socket, MAX_CLIENTS) == -1) {
        perror("Error listening on socket");
        exit(EXIT_FAILURE);
    }

    printf("Server is waiting for connections...\n");

    while (!exit_flag) {
       if ((client_socket = accept(server_socket, (struct sockaddr *)&client_addr, &client_addr_len)) == -1) {
            perror("Error accepting connection");
            continue;
        }

        int *client_socket_ptr = (int *)malloc(sizeof(int));
        *client_socket_ptr = client_socket;

        if (pthread_create(&thread_id, NULL, handle_client, (void *)client_socket_ptr) != 0) {
            perror("Error creating thread");
            continue;
        }

        pthread_detach(thread_id);
    }

    close(server_socket);
    printf("main exited\n");

    return 0;
}