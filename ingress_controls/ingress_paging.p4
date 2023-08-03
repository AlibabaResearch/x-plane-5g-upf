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
        in ipv4_addr_t server_ip_addr
        ) 
{


    bool pop_locker = true;
    bool write_locker = true;
    // bool filled;
    bit<8> idle_state = 0;
    bit<8> exit_flag = 0;
 
 

    // Hash<bit<CONCURRENCY_CONTROL_TABLE_SIZE_POWER>>(HashAlgorithm_t.CRC16) c_hash; 
    // bit<CONCURRENCY_CONTROL_TABLE_SIZE_POWER> slot_idx;

    Hash<bit<10>>(HashAlgorithm_t.CRC16) c_hash; 
    bit<10> slot_idx;

    /* dec inflight counter */
    // bit<16> inflight_num;
    RegisterAction<bit<16>, _, bool>(c_inflight_counter) c_inflight_dec = {
        void apply(inout bit<16> value, out bool read_value) {
            if (value > 1) {
                value = value - 1;
                read_value = true; 
            }else{
                read_value = false;
            }
        }
    };
    action c_inflight_dec_act() {
        write_locker = c_inflight_dec.execute(slot_idx);
    }
    @stage(1)
        table c_inflight_dec_tbl {
            key = {}
            actions = {c_inflight_dec_act;}
            size = 1;
            default_action = c_inflight_dec_act;
        }

    RegisterAction<bit<8>, _, bit<8>>(c_idle) c_idle_get = {
        void apply(inout bit<8> value, out bit<8> read_value) {
            if(!hdr.ue.idle_locker){
                value = hdr.ue.idle;
            }
            read_value = value;
        }
    };


    action c_idle_get_act(){
        idle_state = c_idle_get.execute(slot_idx);
    }

    @stage(8)
    table c_idle_get_tbl{
        key = {}
        actions = {c_idle_get_act;}
        size = 1;
        default_action = c_idle_get_act;
    }


    RegisterAction<bit<8>, _, bit<8>>(c_buffer_pop_index) c_RI_get = {
        void apply(inout bit<8> value, out bit<8> read_value) {
            read_value = value;
        }
    };

    action c_RI_get_act(){
        hdr.ue.read_index= c_RI_get.execute(slot_idx);
    }

    @stage(5)
    table c_buffer_RI_reg_get_tbl{
        key = {}
        actions = {c_RI_get_act;}
        size = 1;
        default_action = c_RI_get_act;
    }


    RegisterAction<bit<8>, _, bool>(c_buffer_pop_locker) c_pop_lock_get = {
        void apply(inout bit<8> value, out bool read_value) {

            read_value = (value == 1);
        }
    };
    action c_pop_lock_get_act(){
        pop_locker = c_pop_lock_get.execute(slot_idx);

    }

    @stage(3)
    table c_pop_lock_get_tbl{
        key = {}
        actions = {c_pop_lock_get_act;}
        size = 1;
        default_action = c_pop_lock_get_act;
    }

    //Buffer Counter
    RegisterAction<bit<8>, _, bit<8>>(c_buffer_push_index) c_buffer_WI_mem_add = {
        void apply(inout bit<8> value, out bit<8> read_value) {
            if(hdr.ue.write_index == 0xff){
                value = 0x80;
            }else{
                value = hdr.ue.write_index + 8w0x1; //todo
            }
            read_value = value;
        }
    };
    RegisterAction<bit<8>, _, bit<8>>(c_buffer_push_index) c_buffer_WI_reg_add = {
        void apply(inout bit<8> value, out bit<8> read_value) {
            if(value == 0xff){
                value = 0x80;
            }else{
                value = value + 1;
            } 
            read_value = value;
        }
    };

    action bufferC_m_add(){
        meta.write_index = c_buffer_WI_mem_add.execute(slot_idx);
    }

    action	bufferC_r_add(){
        meta.write_index = c_buffer_WI_reg_add.execute(slot_idx);
    }

    @stage(5)
        table c_buffer_WI_mem_add_tbl{
            key = {}
            actions = {
                bufferC_m_add;
            }
            size = 1;
            default_action = bufferC_m_add;
        }

    @stage(5)
        table c_buffer_WI_reg_add_tbl{
            key = {}
            actions = {
                bufferC_r_add;
            }
            size = 1;
            default_action = bufferC_r_add;
        }

    /* check and inc filled flag */
// 
    // RegisterAction<bit<8>, _, bool>(c_filled) c_filled_check = {
    //     void apply(inout bit<8> value, out bool read_value) {
            
    //         if (value == 0) {
    //             value = 1;
    //             read_value = false;
    //         }else{
    //             read_value = true;
    //         }
    //     }
    // };
    // action c_filled_check_act() {
    //     filled = c_filled_check.execute(slot_idx);
    // }
    // @stage(2)
    //     table c_filled_check_tbl {
    //         key = {}
    //         actions = {c_filled_check_act;}
    //         size = 1;
    //         default_action = c_filled_check_act;
    //     }


    apply{
        hdr.ue.idle_locker = false;
        slot_idx = c_hash.get({ // UDP packet only for now
                hdr.packet_pdr_key.ue_addr,
                hdr.packet_pdr_key.inet_addr,
                hdr.packet_pdr_key.ue_port,
                hdr.packet_pdr_key.inet_port,
                IpProtocol.UDP				
                });

        //Niehao 2023.1.30 Paging Buffer
        //inflight 正在转的包数
        //buffer counter buffer的偏移值
        //filled 标志位

        c_inflight_dec_tbl.apply();

        // c_filled_check_tbl.apply();

        c_pop_lock_get_tbl.apply();

        if(write_locker){
            c_buffer_WI_reg_add_tbl.apply();  
            hdr.ue.idle_locker = true;
            hdr.ib_bth.reserved2 = 0x01;
        }
        else{	
            c_buffer_WI_mem_add_tbl.apply();
            ig_dprsr_md.mirror_type = TRUNCATE_MIRROR_TYPE;
            meta.mirror_session = TRUNCATE_MIRROR_SESSION;
            meta.packet_type = PKT_TYPE_MIRROR_TRUNCATE;
             //mirror when write not locked
            hdr.ib_bth.reserved2 = 0x02;
        }
        if(meta.write_index > 0x7f){
            hdr.ue.write_index = meta.write_index - 0x80;
        }else{
            hdr.ue.write_index = meta.write_index;
        }
        if(pop_locker){
            c_buffer_RI_reg_get_tbl.apply();
            hdr.ue.idle_locker = true;
        }

        meta.read_index = hdr.ue.read_index;

        if(hdr.ue.idle == 1){
          hdr.ue.idle_locker = false;  
        } 
        else if(hdr.ue.write_index == hdr.ue.read_index){
            hdr.ue.idle = 0;
            hdr.ue.idle_locker = false;
        }

        c_idle_get_tbl.apply();
        
        if(idle_state == 0){
            meta.write_index = 0;        
            meta.read_index = 0;
            hdr.ib_bth.opcode = ib_opcode_t.NOOP;
        }else{
            hdr.ib_bth.opcode = ib_opcode_t.BUFFER_PACKET; 
        }

        meta.payload_addr = hdr.next_fetch_info.addr;
        // meta.payload_len = hdr.ue.write_index ++ hdr.ue.read_index;
        // meta.next_fetch
        // meta.write_index = hdr.ue.write_index;
        // meta.read_index = hdr.ue.read_index;
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
        // hdr.ib_bth.reserved = IB_RES_TYPE.BUFFER_PACKET;
        hdr.ib_bth.ack = 1;
        hdr.ib_bth.dst_qp = (bit<24>) hdr.next_fetch_info.current_server_idx; 
        hdr.ib_bth.psn = (bit<24>) hdr.next_fetch_info.current_qp_idx;
// 
        hdr.ib_reth.setValid();
    


        hdr.next_fetch_info.addr = hdr.next_fetch_info.addr +  UE_KEY_LEN + UE_RULE_LEN - UE_TABLE_OFFSET + TO_BUFFER_OFFSET;// - hdr.next_fetch_info.mem_offset;
        
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
        in ipv4_addr_t server_ip_addr){
      
    Hash<bit<10>>(HashAlgorithm_t.CRC16) c_hash; 
    bit<10> slot_idx;

    /* dec inflight counter */
    bool write_locker;
    RegisterAction<bit<16>, _, bool>(c_inflight_counter) c_inflight_check = {
        void apply(inout bit<16> value, out bool read_value) {
            if(value > 0){
                read_value = true;
            }else{
                read_value = false;
            }
        }
    };
    action c_inflight_get_act() {
        write_locker = c_inflight_check.execute(slot_idx);
    }
    @stage(1)
        table c_write_locker_get {
            key = {}
            actions = {c_inflight_get_act;}
            size = 1;
            default_action = c_inflight_get_act;
        } 


    RegisterAction<bit<8>, _, bit<8>>(c_idle) c_idle_get = {
        void apply(inout bit<8> value, out bit<8> read_value) {
            read_value = value;
        }
    };

    action c_idle_get_act(){
        hdr.ue.idle = c_idle_get.execute(slot_idx);
    }

    @stage(8)
    table c_idle_get_tbl{
        key = {}
        actions = {c_idle_get_act;}
        size = 1;
        default_action = c_idle_get_act;
    }

    RegisterAction<bit<8>, _, bit<8>>(c_idle) c_idle_clear = {
        void apply(inout bit<8> value) {
            value = 0;
        }
    };

    action c_idle_clear_act(){
        c_idle_clear.execute(slot_idx);
    }

    @stage(8)
    table c_idle_clear_tbl{
        key = {}
        actions = {c_idle_clear_act;}
        size = 1;
        default_action = c_idle_clear_act;
    }

    RegisterAction<bit<8>, _, bool>(c_buffer_pop_locker) c_pop_lock_set = {
        void apply(inout bit<8> value, out bool read_value) {
            if(!hdr.ue.idle_locker){
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
    @stage(3)
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

    @stage(5)
    table c_buffer_RI_reg_set_tbl{
        key = {}
        actions = {c_RI_set_act;}
        size = 1;
        default_action = c_RI_set_act;
    }


    apply{
        slot_idx = c_hash.get({ // UDP packet only for now
            hdr.packet_pdr_key.ue_addr,
            hdr.packet_pdr_key.inet_addr,
            hdr.packet_pdr_key.ue_port,
            hdr.packet_pdr_key.inet_port,
            IpProtocol.UDP				
        });
        
        c_write_locker_get.apply();
   
        hdr.ue.idle_locker = write_locker;
        // c_idle_get_tbl.apply();
        if(hdr.next_fetch_info.has_value != 2){
            c_pop_lock_set_tbl.apply();
            c_buffer_RI_reg_set_tbl.apply();
        }
        if(write_locker){
            c_idle_get_tbl.apply();
            if(hdr.ue.idle == 0){
                hdr.ib_bth.opcode = ib_opcode_t.NOOP;
                meta.payload_addr = hdr.next_fetch_info.addr - TO_BUFFER_OFFSET - UE_KEY_LEN - UE_RULE_LEN + UE_KEY_LEN + 5;
                meta.read_index = 0;// hdr.next_fetch_info.pdr_fetch_round_id;
                meta.pdr_fetch_round_id = 0;//idle
            }else{
                hdr.next_fetch_info.addr = hdr.next_fetch_info.addr + hdr.next_fetch_info.mem_offset2;
                hdr.ib_bth.se = 1;
                hdr.ib_bth.opcode = ib_opcode_t.BUFFER_REPLAY;
            }
        }else if(hdr.next_fetch_info.has_value == 0){
            //break;
            c_idle_clear_tbl.apply();
            hdr.ib_bth.opcode = ib_opcode_t.NOOP;
            hdr.ib_bth.reserved = IB_RES_TYPE.BUFFER_REPLAY;
            //mirror清 0包
            meta.payload_addr = hdr.next_fetch_info.addr - TO_BUFFER_OFFSET - UE_KEY_LEN - UE_RULE_LEN + UE_KEY_LEN + 5;
         
            meta.read_index = 0 ; //hdr.next_fetch_info.pdr_fetch_round_id;
            meta.pdr_fetch_round_id = 0;//idle 
            hdr.next_fetch_info.setInvalid();
            // hdr.ib_bth.setInvalid();
        }
        else if(hdr.next_fetch_info.has_value == 2){
            //出发包

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
                //首包
                //转发
                //write r_ptr
                //
                ;
            }
            else{
                hdr.ib_bth.se = 0;
                hdr.ib_bth.opcode = ib_opcode_t.BUFFER_REPLAY;

                hdr.next_fetch_info.addr = hdr.next_fetch_info.addr + (bit<64>) hdr.next_fetch_info.mem_offset2;
                meta.payload_addr = hdr.next_fetch_info.addr + 12;
                meta.read_index = 0;// hdr.next_fetch_info.pdr_fetch_round_id;
                meta.pdr_fetch_round_id = 0;
                //次包
                ;
            }
            
        }
        //hdr.packet_pdr_key.ts = ig_prsr_md.global_tstamp;
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

        // meta.pdr_fetch_round_id = IB_RES_TYPE.BUFFER_COUNTER; // only used to signal the flow control

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
        hdr.ib_reth.dma_len1 = 0; //hdr.next_fetch_info.payload_len;
        hdr.ib_reth.dma_len2 = 700;

        hdr.ib_aeth.setInvalid();
        hdr.ue_key.setInvalid();
        hdr.lookup_resp_type.setInvalid();
        hdr.ue.setInvalid();
        // hdr.icrc.setInvalid();
        hdr.gtpu.setInvalid();
        hdr.inner_ipv4.setInvalid();
        hdr.inner_udp.setInvalid();
        

        hdr.icrc.setValid();

    }
}
#endif
