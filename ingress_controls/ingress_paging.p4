#ifndef _PAGING_
#define _PAGING_

#include "../include/configuration.p4"
#include "../include/types_r.p4"
#include "../include/registers.p4"

control Paging_Push_Ingress(inout headers_t hdr,
        inout ig_metadata_t meta,
        inout ingress_intrinsic_metadata_for_deparser_t ig_dprsr_md,
        inout ingress_intrinsic_metadata_for_tm_t ig_tm_md,
        in bit<16> server_mac_addr_1,
        in bit<32> server_mac_addr_2,
        in ipv4_addr_t server_ip_addr,
        in bool write_locker
        ) 
{

    Hash<bit<16>>(HashAlgorithm_t.CRC16) hash_slot_idx;
    bit<16> slot_idx;
    bool pop_locker = true;
    bit<8> idle_state = 0;
    bit<8> exit_flag = 0;

    // optimized
    RegisterAction<bit<8>, _, bit<8>>(c_buffer_push_index) c_buffer_WI_op = {
        void apply(inout bit<8> value, out bit<8> read_value) {
            if(write_locker){
                value = (value + 1);// & 0x7f;
            }else{
                value = (hdr.ue.write_index + 8w0x1);//& 0x7f;
            }
            read_value = value;
        }
    };

    action c_buffer_WI_act(){
        hdr.ue.write_index = c_buffer_WI_op.execute(slot_idx) & 0x7f;
    }

    table c_buffer_WI_tbl{
        key = {}
        actions = {c_buffer_WI_act;}
        size = 1;
        default_action = c_buffer_WI_act;
    }


    RegisterAction<bit<8>, _, bit<8>>(c_idle) c_idle_op = {
        void apply(inout bit<8> value, out bit<8> read_value) {
            if (write_locker) value = hdr.ue.idle;
            read_value = value;
        }
    };

    action c_idle_act() {
        idle_state = c_idle_op.execute(slot_idx);
    }

    @stage(7)
    table c_idle_tbl{
        key = {}
        actions = {c_idle_act;}
        size = 1;
        default_action = c_idle_act;
    }

    RegisterAction<bit<8>, _, bit<8>>(c_buffer_pop_index) c_RI_get = {
        void apply(inout bit<8> value, out bit<8> read_value) {
            read_value = value;
        }
    };

    action c_RI_get_act(){
        hdr.ue.read_index= c_RI_get.execute(slot_idx);
    }

    //@stage(5)
    table c_buffer_RI_reg_get_tbl{
        key = {}
        actions = {c_RI_get_act;}
        size = 1;
        default_action = c_RI_get_act;
    }

    apply{

        slot_idx  = hash_slot_idx.get({
				hdr.ipv4.src_addr
		}) & CONCURRENCY_CONTROL_TABLE_MASK;
        

        if(write_locker){
            hdr.ib_bth.reserved2 = 0x01;
        }
        else{	
            ig_dprsr_md.mirror_type = TRUNCATE_MIRROR_TYPE;
            meta.mirror_session = TRUNCATE_MIRROR_SESSION;
            meta.packet_type = PKT_TYPE_MIRROR_TRUNCATE;
            hdr.ib_bth.reserved2 = 0x02;
        }

        c_idle_tbl.apply();   
        if(idle_state == 0){
            meta.write_index = 0;        
            meta.read_index = 0;
            hdr.ib_bth.opcode = ib_opcode_t.NOOP;
        }else{
            c_buffer_WI_tbl.apply();
            hdr.ib_bth.opcode = ib_opcode_t.BUFFER_PACKET; 
        }

        meta.payload_addr = hdr.next_fetch_info.addr;
        meta.pdr_fetch_round_id = idle_state;

        meta.payload_len = IB_MIRROR_BUFFER_TYPE.BUFFER_COUNTER;
        meta.server_qp_index = hdr.next_fetch_info.current_qp_idx;
        meta.server_index = hdr.next_fetch_info.current_server_idx;
        meta.server_mac_addr_1 = server_mac_addr_1;
        meta.server_mac_addr_2 = server_mac_addr_2;
        meta.server_ip_addr = server_ip_addr;
        meta.rdma_remote_key = hdr.next_fetch_info.rdma_remote_key;

        hdr.ethernet.dst_addr_1 = server_mac_addr_1;
        hdr.ethernet.dst_addr_2 = server_mac_addr_2;
        hdr.ethernet.src_addr = 0x000000000001;
        hdr.ipv4.src_addr = RDMA_IP;
        hdr.ipv4.dst_addr = server_ip_addr; 
        hdr.ipv4.ttl = 64;
        hdr.ipv4.flags = 0x2;
        hdr.ipv4.total_len = hdr.ipv4.minSizeInBytes() + hdr.udp.minSizeInBytes() + 
            hdr.ib_bth.minSizeInBytes() + hdr.ib_reth.minSizeInBytes() + 4;

        hdr.udp.setValid();
        hdr.udp.length = hdr.udp.minSizeInBytes() + hdr.
            ib_bth.minSizeInBytes() + hdr.ib_reth.minSizeInBytes() + 4;
        hdr.ib_bth.setValid();
  
        //setTag
        hdr.ib_bth.ack = 1;
        hdr.ib_bth.dst_qp = (bit<24>) hdr.next_fetch_info.current_server_idx; 
        hdr.ib_bth.psn = (bit<24>) hdr.next_fetch_info.current_qp_idx;
 
        hdr.ib_reth.setValid();
    
        hdr.next_fetch_info.addr = hdr.next_fetch_info.addr +  UE_KEY_LEN + UE_RULE_LEN - UE_TABLE_OFFSET + TO_BUFFER_OFFSET;
        
        hdr.next_fetch_info.has_value = idle_state;

        //Tmp Store
        hdr.ib_reth.remote_key = ((bit<32>)hdr.ue.write_index);

        hdr.ib_reth.dma_len2 = hdr.next_fetch_info.payload_len; 
        hdr.next_fetch_info.setValid();
        hdr.next_fetch_info.pdr_fetch_round_id = hdr.ue.write_index;

        hdr.ib_aeth.setInvalid();
        hdr.ue_key.setInvalid();
        hdr.ue.setInvalid();
        hdr.lookup_resp_type.setInvalid();
        hdr.pdr0.setInvalid();
        hdr.pdr1.setInvalid();
        hdr.pdr2.setInvalid();
        hdr.pdr3.setInvalid();
        hdr.pdr4.setInvalid();

    }
}

control Paging_Pop_Loop_Ingress(inout headers_t hdr, inout ig_metadata_t meta, 
        in bit<16> server_mac_addr_1,
        in bit<32> server_mac_addr_2,
        inout ingress_intrinsic_metadata_for_deparser_t ig_dprsr_md,
        in ingress_intrinsic_metadata_from_parser_t ig_prsr_md,
        inout ingress_intrinsic_metadata_for_tm_t ig_tm_md,
        in ipv4_addr_t server_ip_addr,
        in bool write_locker){
      
    Hash<bit<16>>(HashAlgorithm_t.CRC16) hash_slot_idx; 
    bit<16> slot_idx;

    RegisterAction<bit<8>, _, bool>(c_buffer_pop_locker) c_pop_lock_set = {
        void apply(inout bit<8> value, out bool read_value) {
            if(!write_locker){
                if(value == 0){
                    value =  1;
                    read_value = true;
                }else{
                    value = 0;
                    read_value = false;
                }
            }else{
                read_value = true;
            }
        }
    };
    bool pop_locker = false;
    action c_pop_lock_set_act(){
        pop_locker = c_pop_lock_set.execute(slot_idx);
    }
    
    table c_pop_lock_set_tbl{
        key = {}
        actions = {c_pop_lock_set_act;}
        size = 1;
        default_action = c_pop_lock_set_act;
    }

    RegisterAction<bit<8>, _, bit<8>>(c_buffer_pop_index) c_RI_set = {
        void apply(inout bit<8> value) {
            value = hdr.next_fetch_info.pdr_fetch_round_id;
        }
    };

    action c_RI_set_act(){
        c_RI_set.execute(slot_idx);
    }

    table c_buffer_RI_reg_set_tbl{
        key = {}
        actions = {c_RI_set_act;}
        size = 1;
        default_action = c_RI_set_act;
    }

    //optimized
    RegisterAction<bit<8>, _, bit<8>>(c_idle) c_idle_op = {
        void apply(inout bit<8> value, out bit<8> read_value) {
            value = 0;
        }
    };

    action c_idle_act(){
        c_idle_op.execute(slot_idx);
    }

    @stage(7)
    table c_idle_tbl {
        key = {}
        actions = {c_idle_act;}
        size = 1;
        default_action = c_idle_act;
    }

    apply{

        slot_idx  = hash_slot_idx.get({
				hdr.ipv4.src_addr
		}) & CONCURRENCY_CONTROL_TABLE_MASK;
        

        if(hdr.next_fetch_info.has_value != 2){
            c_pop_lock_set_tbl.apply();
            c_buffer_RI_reg_set_tbl.apply();
        }

        if(write_locker){
            if(hdr.ue.idle == 0){
                hdr.ib_bth.opcode = ib_opcode_t.NOOP;
                meta.payload_addr = hdr.next_fetch_info.addr - TO_BUFFER_OFFSET - UE_KEY_LEN - UE_RULE_LEN + UE_KEY_LEN + 5;
                meta.read_index = 0;
                meta.pdr_fetch_round_id = 0;
            }else{
                hdr.next_fetch_info.addr = hdr.next_fetch_info.addr + hdr.next_fetch_info.mem_offset2;
                hdr.ib_bth.se = 1;
                hdr.ib_bth.opcode = ib_opcode_t.BUFFER_REPLAY;
            }
        }else if(hdr.next_fetch_info.has_value == 0){
            c_idle_tbl.apply();
            hdr.ib_bth.opcode = ib_opcode_t.NOOP;
            hdr.ib_bth.reserved = IB_RES_TYPE.BUFFER_REPLAY;
            meta.payload_addr = hdr.next_fetch_info.addr - TO_BUFFER_OFFSET - UE_KEY_LEN - UE_RULE_LEN + UE_KEY_LEN + 5;
            meta.read_index = 0 ; 
            meta.pdr_fetch_round_id = 0;
            hdr.next_fetch_info.setInvalid();
        }
        else if(hdr.next_fetch_info.has_value == 2){
            hdr.ib_bth.se = 0;
            hdr.ib_bth.opcode = ib_opcode_t.BUFFER_REPLAY;
            meta.payload_addr = hdr.next_fetch_info.addr - TO_BUFFER_OFFSET - UE_KEY_LEN - UE_RULE_LEN + UE_KEY_LEN + 6;
            hdr.next_fetch_info.addr = hdr.next_fetch_info.addr + (bit<64>) hdr.next_fetch_info.mem_offset2;
            meta.read_index = hdr.next_fetch_info.pdr_fetch_round_id;
            meta.pdr_fetch_round_id = 0;
        }
        else{
            if(pop_locker){
                hdr.ib_bth.se = 1;
                hdr.ib_bth.opcode = ib_opcode_t.BUFFER_REPLAY;
                hdr.ib_bth.reserved = IB_RES_TYPE.BUFFER_REPLAY;
                meta.payload_addr = hdr.next_fetch_info.addr - TO_BUFFER_OFFSET - UE_KEY_LEN - UE_RULE_LEN + UE_KEY_LEN + 6;
                hdr.next_fetch_info.addr = hdr.next_fetch_info.addr + (bit<64>) hdr.next_fetch_info.mem_offset2;
                meta.read_index = hdr.next_fetch_info.pdr_fetch_round_id;
                meta.pdr_fetch_round_id = 2;
            }
            else{
                hdr.ib_bth.se = 0;
                hdr.ib_bth.opcode = ib_opcode_t.BUFFER_REPLAY;

                hdr.next_fetch_info.addr = hdr.next_fetch_info.addr + (bit<64>) hdr.next_fetch_info.mem_offset2;
                meta.payload_addr = hdr.next_fetch_info.addr + 12;
                meta.read_index = 0;
                meta.pdr_fetch_round_id = 0;
            }
            
        }
        ig_dprsr_md.mirror_type = TRUNCATE_MIRROR_TYPE;
        meta.mirror_session = TRUNCATE_MIRROR_SESSION;
        meta.packet_type = PKT_TYPE_MIRROR_TRUNCATE;
        meta.payload_len = IB_MIRROR_BUFFER_TYPE.BUFFER_CLEAR;
        meta.server_qp_index = (bit<16>) hdr.next_fetch_info.current_qp_idx;
        meta.server_index = hdr.next_fetch_info.current_server_idx;
        meta.server_mac_addr_1 = server_mac_addr_1;
        meta.server_mac_addr_2 = server_mac_addr_2;
        meta.server_ip_addr = server_ip_addr;
        meta.rdma_remote_key = hdr.next_fetch_info.rdma_remote_key;

        hdr.ethernet.dst_addr_1 = server_mac_addr_1;
        hdr.ethernet.dst_addr_2 = server_mac_addr_2;
        hdr.ethernet.src_addr = 0x000000000001;
        hdr.ipv4.src_addr = RDMA_IP;
        hdr.ipv4.dst_addr = server_ip_addr; 
        hdr.ipv4.ttl = 64;
        hdr.ipv4.flags = 0x2;
        hdr.ipv4.total_len = hdr.ipv4.minSizeInBytes() + hdr.udp.minSizeInBytes() + 
            hdr.ib_bth.minSizeInBytes() + hdr.ib_reth.minSizeInBytes() + 4;

        hdr.udp.setValid();
        hdr.udp.length = hdr.udp.minSizeInBytes() + hdr.
            ib_bth.minSizeInBytes() + hdr.ib_reth.minSizeInBytes() + 4;
        hdr.udp.src_port = 0;
        hdr.udp.dst_port = UDP_PORT_ROCEV2;

        hdr.ib_bth.setValid();
        
        hdr.ib_bth.migration_req = 1;
        hdr.ib_bth.pad_count = 0;
        hdr.ib_bth.transport_version = 0;
        hdr.ib_bth.partition_key = 0xffff;
        hdr.ib_bth.ack = 1;
        hdr.ib_bth.reserved2 = 0;

        hdr.ib_bth.dst_qp = (bit<24>) hdr.next_fetch_info.current_server_idx; 
        hdr.ib_bth.psn = (bit<24>) hdr.next_fetch_info.current_qp_idx;
        hdr.ib_reth.setValid();
        hdr.next_fetch_info.setValid();

        hdr.ib_reth.remote_key = hdr.next_fetch_info.rdma_remote_key;
        hdr.ib_reth.dma_len1 = 0; 
        hdr.ib_reth.dma_len2 = 700;

        hdr.ib_aeth.setInvalid();
        hdr.ue_key.setInvalid();
        hdr.lookup_resp_type.setInvalid();
        hdr.ue.setInvalid();
        hdr.gtpu.setInvalid();
        hdr.inner_ipv4.setInvalid();
        hdr.inner_udp.setInvalid();

        hdr.icrc.setValid();

    }
}
#endif
