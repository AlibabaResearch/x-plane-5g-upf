#ifndef _CONFIGURATION_
#define _CONFIGURATION_

/* storage design configurations */
#define UE_KEY_LEN 10 //9 + 1 (type)
#define PDR_LEN 90
#define UE_RULE_LEN PDR_LEN // keep them consistent for simplicity

#define UE_FLOW_KEY_LEN 14 // 5 tuples： 13 + 1 (type)
#define UE_FLOW_RULE_LEN 7 
#define UE_FLOW_TABLE_OFFSET 0x120000000 //PDR_TABLE_OFFSET * (MAX_PDR_TBL_NUM + 1): 4.5 GB

//for calculating hash
#define UE_SIZE_POWER 32
#define UE_SIZE_MASK 0x1ffff000 // 2^29 = 0.5 GB/server
#define UE_FLOW_SIZE_POWER 32 // 2^32 = 4 GB/server
#define UE_FLOW_SIZE_MASK 0xfffff000
// the above two can share the same hash algorithm
#define SERVER_SIZE_POWER 1 // 8 servers
#define QP_POWER 5 // 2^QP_POWER qps to randomly distribute the requests to 
//#define SERVER_SIZE_MASK 0x00000007
//#define QP_SIZE_MASK 0x0000000f

//#define NUM_PDR_PER_FETCH 5
//define ENTRY_SLOT_LEN_SHIFT 12 
#define ENTRY_SLOT_LEN 4096 // = 2 << ENTRY_SLOT_LEN_SHIFT
//#define MAX_NUM_FETCH_SHIFT 3
#define MAX_PDR_TBL_NUM 8
#define MAX_FETCH_ID 9 // = 2 << MAX_NUM_FETCH_SHIFT + 1 (the first ue_flow lookup)
#define PDR_TABLE_OFFSET 0x20000000 //memory divided into two parts: for UE / PDR, this is the size for UE table: 0.5 GB
/*paging*/
#define TO_BUFFER_OFFSET 0x20000000 // [paging todo:]
#define UE_TABLE_OFFSET 0x20000000

/* Servers Configurations */
#define MAX_QP_NUM 32
#define NUMBER_OF_SERVERS 8
#define TOTAL_QP MAX_QP_NUM * NUMBER_OF_SERVERS
#define OUTSTAND_WINDOW_SIZE 16

/* hot table configurations */
#define HOT_ENTRY_SIZE 128

/* Headers Configurations */
#define HEADER_REGISTER_SIZE 2000
#define PKT_MIN_LENGTH 71

/* Port Numbers */
#define SERVER_1_PORT 0
#define SINGLE_SERVER_PORT 188
#define SERVER_2_PORT 20
#define SERVER_3_PORT 16
#define SERVER_4_PORT 32

#define NF_PORT 36

#define OUTPUT_1_PORT 48
#define OUTPUT_2_PORT 52
#define OUTPUT_3_PORT 44
#define OUTPUT_4_PORT 40

#define CONCURRENCY_CONTROL_TABLE_SIZE_POWER 13 
#define CONCURRENCY_CONTROL_TABLE_SIZE 8192 // 2^CONCURRENCY_CONTROL_TABLE_SIZE_POWER

//for hot table cache
#define CM_SIZE_POWER 13 // len of hash range

#endif /* _CONFIGURATION_ */
