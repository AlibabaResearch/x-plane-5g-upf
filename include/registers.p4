#ifndef _REGISTERS_
#define _REGISTERS_

#include "configuration.p4"

/* QP Status Registers */
Register<bit<32>, _>(TOTAL_QP) qp;
Register<bit<32>, _>(TOTAL_QP) qp2;
Register<bit<16>, _>(TOTAL_QP) enabled_qp;
Register<bit<1>, _>(TOTAL_QP) restore_qp;
/* Sequence Number and other RDMA Data */
Register<bit<32>, _>(TOTAL_QP) seq_n;

Register<bit<32>, _>(NUMBER_OF_SERVERS) remote_address_1;
Register<bit<32>, _>(NUMBER_OF_SERVERS) remote_address_2;
Register<bit<32>, _>(NUMBER_OF_SERVERS) remote_key;
Register<bit<32>, _>(NUMBER_OF_SERVERS) r2emote_address_1;
Register<bit<32>, _>(NUMBER_OF_SERVERS) r2emote_address_2;
Register<bit<32>, _>(NUMBER_OF_SERVERS) r2emote_key;
/* Server interfaces info */
Register<bit<16>, _>(NUMBER_OF_SERVERS) server_mac_address_1;
Register<bit<32>, _>(NUMBER_OF_SERVERS) server_mac_address_2;
Register<ipv4_addr_t, _>(NUMBER_OF_SERVERS) server_ip_address;
Register<bit<16>, _>(NUMBER_OF_SERVERS) server_port;

Register<bit<32>, _>(TOTAL_QP) outstand_n;
Register<bit<32>, _>(TOTAL_QP) loss_cnt_w;
Register<bit<32>, _>(TOTAL_QP) loss_cnt_r;
// for debugging
Register<bit<32>, _>(1) loss_cnt_w2;
Register<bit<32>, _>(1) loss_cnt_r2;
Register<bit<32>, _>(1) lat_cnt;
Register<bit<32>, _>(1) lat_sum;

/* Current QP to use, this is a RR counter */
Register<bit<16>, _>(1) current_qp;
Register<bit<32>, _>(1) addr_idx;

/* Memory Region current offset */
Register<bit<32>, _>(NUMBER_OF_SERVERS) memory_offset;
Register<bit<32>, _>(NUMBER_OF_SERVERS) add_memory_offset;

/* Registers for controling server hash */
Register<bit<16>, _>(NUMBER_OF_SERVERS) server_hash_start;

/* concurrency control */
// keys
Register<bit<32>, _>(CONCURRENCY_CONTROL_TABLE_SIZE) c_src_ip;
Register<bit<32>, _>(CONCURRENCY_CONTROL_TABLE_SIZE) c_dst_ip;
Register<bit<16>, _>(CONCURRENCY_CONTROL_TABLE_SIZE) c_src_port;
Register<bit<16>, _>(CONCURRENCY_CONTROL_TABLE_SIZE) c_dst_port;
Register<bit<8>, _>(CONCURRENCY_CONTROL_TABLE_SIZE) c_protocol;
Register<bit<1>, _>(CONCURRENCY_CONTROL_TABLE_SIZE) c_occupied;
Register<bit<8>, _>(CONCURRENCY_CONTROL_TABLE_SIZE) c_filled;
Register<bit<16>, _>(CONCURRENCY_CONTROL_TABLE_SIZE) c_inflight_counter;
// inflight counter
Register<bit<32>, _>(CONCURRENCY_CONTROL_TABLE_SIZE) c_inflight_flow;
Register<bit<32>, _>(CONCURRENCY_CONTROL_TABLE_SIZE) c_inflight_ue;
Register<bit<16>, _>(CONCURRENCY_CONTROL_TABLE_SIZE) c_lst_flow_key;
Register<bit<16>, _>(CONCURRENCY_CONTROL_TABLE_SIZE) c_lst_ue_key;

// state data
// 1. counter
Register<bit<32>, _>(CONCURRENCY_CONTROL_TABLE_SIZE) c_counter;
// 2. meter token
Register<bit<32>, _>(CONCURRENCY_CONTROL_TABLE_SIZE) c_meter_token;
// 3. buffer counter
Register<bit<32>, _>(CONCURRENCY_CONTROL_TABLE_SIZE) c_buffer_counter;
/*paging*/
Register<bit<8>,_>(CONCURRENCY_CONTROL_TABLE_SIZE) c_buffer_pop_locker;
Register<bit<8>,_>(CONCURRENCY_CONTROL_TABLE_SIZE) c_idle;
Register<bit<8>,_>(CONCURRENCY_CONTROL_TABLE_SIZE) c_buffer_push_index;
Register<bit<8>,_>(CONCURRENCY_CONTROL_TABLE_SIZE) c_buffer_pop_index;


#endif /* _REGISTERS_ */
