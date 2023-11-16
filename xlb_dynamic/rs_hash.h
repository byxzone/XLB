#ifndef __RS_HASH_H
#define __RS_HASH_H

#include "common.h"
#include "../common/common_defines.h"

struct Node {
    __u32 key;
    __u32 value;
    struct Node *next;
};

typedef struct Node Node;

typedef struct {
    __u32 size;
    Node **idTable;  
    Node **ipTable; 
} DHT; //double hash table

extern DHT *createDHT(__u32 size);
extern void destroyDHT(DHT *d);
extern void insertDHT(DHT *d, __u32 id, __u32 ip);
extern __u32 findIp(DHT *d, __u32 id);
extern __u32 findId(DHT *d, __u32 ip);

#endif