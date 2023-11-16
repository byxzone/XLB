#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <signal.h>

#include "xlb_client.h"
#include "metric.h"

int client_socket;
int exit_flag = 0;

void sigint_handler(int signo) {
    if (signo == SIGINT) {
        printf("Received Ctrl+C. Exiting...\n");
        exit_flag = 1;
    }
}

int init_socket(){
    struct sockaddr_in server_addr;
    if ((client_socket = socket(AF_INET, SOCK_STREAM, 0)) == -1) {
        perror("socket");
        return -1;
    }

    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(XLB_SERVER_PORT);
    server_addr.sin_addr.s_addr = inet_addr(XLB_SERVER_IP_STR);

    if (connect(client_socket, (struct sockaddr*)&server_addr, sizeof(server_addr)) == -1) {
        perror("connect");
        return -1;
    }

    return 1;
}

int send_data(){
    struct load_info data;
    get_loadavg(data.loadavg);
    ssize_t bytes_sent = send(client_socket, &data, sizeof(struct load_info), 0);
    if (bytes_sent == -1) {
        perror("send");
        return -1;
    } 
    #ifdef DEBUG_PRINT
    printf("bytes_sent:%d \n",(int)bytes_sent);
    #endif
    return 1;
}

int main() {
    if(!init_socket()){
        perror("init_socket");
        exit(EXIT_FAILURE);
    }
    

    if(!init_metric_module()){
        perror("init_metric_module");
        exit(EXIT_FAILURE);
    }

    signal(SIGINT, sigint_handler);

    while (!exit_flag) {
        send_data();
        sleep(1);
    }

    exit_metric_module();
    close(client_socket);

    return 0;
}
