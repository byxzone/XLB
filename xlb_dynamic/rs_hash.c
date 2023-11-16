#include <stdlib.h>

#include "rs_hash.h"

DHT *createDHT(__u32 size) {
    DHT *d = (DHT *)malloc(sizeof(DHT));
    d->size = size;
    d->idTable = (Node **)malloc(sizeof(Node *) * size);
    d->ipTable = (Node **)malloc(sizeof(Node *) * size);

    for (__u32 i = 0; i < size; i++) {
        d->idTable[i] = NULL;
        d->ipTable[i] = NULL;
    }

    return d;
}

__u32 hash(__u32 key, __u32 size) {
    return key % size;
}

void insertDHT(DHT *d, __u32 id, __u32 ip) {
    __u32 idIndex = hash(id, d->size);
    __u32 ipIndex = hash(ip, d->size);

    Node *idNode = (Node *)malloc(sizeof(Node));
    idNode->key = id;
    idNode->value = ip;
    idNode->next = NULL;

    Node **idTable_cur = &(d->idTable[idIndex]);
    while(*idTable_cur != NULL){
        idTable_cur = &((*idTable_cur)->next);
    }
    *idTable_cur = idNode;

    Node *ipNode = (Node *)malloc(sizeof(Node));
    ipNode->key = ip;
    ipNode->value = id;
    
    Node **ipTable_cur = &(d->ipTable[ipIndex]);
    while(*ipTable_cur != NULL){
        ipTable_cur = &((*ipTable_cur)->next);
    }
    *ipTable_cur = ipNode;
}
__u32 findIp(DHT *d, __u32 id) {
    __u32 idIndex = hash(id, d->size);

    Node **idTable_cur = &d->idTable[idIndex];

    while (*idTable_cur != NULL) {
        if((*idTable_cur)->key == id)
            return (*idTable_cur)->value;
         idTable_cur = &((*idTable_cur)->next);
    } 
    return -1;
}

__u32 findId(DHT *d, __u32 ip) {
    __u32 ipIndex = hash(ip, d->size);

    Node *ipTable_cur = d->ipTable[ipIndex];

    while (ipTable_cur != NULL) {
        if(ipTable_cur->key == ip)
            return ipTable_cur->value;
        ipTable_cur = ipTable_cur->next;
    } 
    return -1;
}

void destroyDHT(DHT *d) {
    for (__u32 i = 0; i < d->size; i++) {
        if (d->idTable[i] != NULL) {
            free(d->idTable[i]);
        }
        if (d->ipTable[i] != NULL) {
            free(d->ipTable[i]);
        }
    }

    free(d->idTable);
    free(d->ipTable);
    free(d);
}