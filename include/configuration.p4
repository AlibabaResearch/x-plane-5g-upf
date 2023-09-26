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

#define ENTRY_SLOT_LEN 4096 
#define MAX_PDR_TBL_NUM 8
#define MAX_FETCH_ID 9 
#define PDR_TABLE_OFFSET 0x20000000 
/*paging*/
#define TO_BUFFER_OFFSET 0x20000000 
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

/* Port Number */
#define SINGLE_SERVER_PORT 144


#define CONCURRENCY_CONTROL_TABLE_SIZE_POWER 13 
#define CONCURRENCY_CONTROL_TABLE_SIZE 8192 // 2^CONCURRENCY_CONTROL_TABLE_SIZE_POWER
#define CONCURRENCY_CONTROL_TABLE_MASK 0x1fff

//for hot table cache
#define CM_SIZE_POWER 13 // len of hash range

/* software UPF port */
#define SOFT_UPF_PORT 188

#endif /* _CONFIGURATION_ */
