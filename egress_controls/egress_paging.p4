#ifndef _EGRESS_PAGING_
#define _EGRESS_PAGING_

#include "../include/types_r.p4"
#include "../include/configuration.p4"

//Construct Buffer Counter Update Write
control Paging_Counter_Write(inout headers_t hdr, inout eg_metadata_t meta) {
    apply {
        /* Chosen RDMA Server MAC Address */
        hdr.ethernet.dst_addr_1 = meta.mirror_truncate.server_mac_addr_1;
        hdr.ethernet.dst_addr_2 = meta.mirror_truncate.server_mac_addr_2;
        /* Fake MAC Address as source */
        hdr.ethernet.src_addr = 0x000000000001;

        /* Static RDMA Client IP Address where the connection is opened */
        hdr.ipv4.src_addr = RDMA_IP;//RDMA_IP;
        /* Chosen RDMA Server IP Address */
        hdr.ipv4.dst_addr = meta.mirror_truncate.server_ip_addr; 
        hdr.ipv4.ttl = 64;
        hdr.ipv4.flags = 0x2;
        hdr.ipv4.protocol = ipv4_protocol_t.UDP;
        /* Set base IPv4 len, will be updated with payload and padding in Egress */
        // Payload长度至少为4
        hdr.ipv4.total_len = hdr.ipv4.minSizeInBytes() + hdr.udp.minSizeInBytes() + 
            hdr.ib_bth.minSizeInBytes() + hdr.ib_reth.minSizeInBytes() + 4 + 4; 
        //+ hdr.next_fetch_info.minSizeInBytes() + hdr.packet_ue_key.minSizeInBytes() + hdr.packet_pdr_key.minSizeInBytes();

        /* Invalidate TCP header ([lyz]:assume only UDP packets for now), it'll be replaced with UDP/IB */
        hdr.udp.setValid();
        hdr.udp.src_port = 0;
        hdr.udp.dst_port = UDP_PORT_ROCEV2;
        hdr.udp.checksum = 0;

        /* Set base UDP len, will be updated with payload and padding in Egress */
        hdr.udp.length = hdr.udp.minSizeInBytes() + hdr.ib_bth.minSizeInBytes() + 
            hdr.ib_reth.minSizeInBytes() + 4 + 4;
        //+ hdr.next_fetch_info.minSizeInBytes() + hdr.packet_ue_key.minSizeInBytes() + hdr.packet_pdr_key.minSizeInBytes();

        //hdr.udp_payload.setInvalid();
        hdr.ib_bth.setValid();
        hdr.ib_bth.opcode = ib_opcode_t.RDMA_WRITE;
        hdr.ib_bth.se = 0;
        hdr.ib_bth.migration_req = 1;
        hdr.ib_bth.pad_count = 0;
        hdr.ib_bth.transport_version = 0;
        hdr.ib_bth.partition_key = 0xffff;
        hdr.ib_bth.reserved = IB_RES_TYPE.BUFFER_COUNTER;
        hdr.ib_bth.ack = 1;
        hdr.ib_bth.reserved2 = 0;
        // hdr.ib_bth.dst_qp = meta.mirror_truncate.server_index; //determined in the egress logic
        /* Store the QP Index where we will read the real seq_n in the Egress */
        //hdr.ib_bth.psn = meta.mirror_truncate.server_qp_index;

        hdr.ib_reth.setValid();
        hdr.ib_reth.addr = meta.mirror_truncate.payload_addr  - PDR_TABLE_OFFSET + UE_KEY_LEN + 5;
        hdr.ib_reth.remote_key = meta.mirror_truncate.rdma_remote_key;
        hdr.ib_reth.dma_len1 = 0;
        hdr.ib_reth.dma_len2 = 4; 
        // meta.write_index = hdr.ue.write_index;
        // meta.read_index = hdr.ue.read_index;
        // meta.pdr_fetch_round_id = hdr.ue.idle;
        
        //模拟payload
        hdr.payload_request.setValid();
        // if(meta.mirror_truncate.pdr_fetch_round_id==0){
            // hdr.payload_request.padding = 0;
            // hdr.payload_request.padding1 = 0;
        // }else{
            hdr.payload_request.padding = meta.mirror_truncate.write_index;
            hdr.payload_request.padding1 = meta.mirror_truncate.read_index;
        // }        
        hdr.payload_request.padding2 = meta.mirror_truncate.pdr_fetch_round_id;
        //Bug Feature, only one can be attached
        hdr.icrc.setValid(); 
        hdr.icrc2.setValid(); 
    }
}

control Paging_Packet_Write(inout headers_t hdr, inout eg_metadata_t meta) {
    // bit<32> counter_shift = 0;
    bit<64> final_offset = 0;
    bit<64> base_addr  = 0;

    action getShift(){
        // hash_shift = hdr.next_fetch_info.mem_offset2<< 5;
        final_offset = 32w0x0 ++ hdr.ib_reth.remote_key ;
        base_addr = hdr.next_fetch_info.mem_offset2 << 6;
    }    

    action getOffset(){
        final_offset = final_offset<<11;
        base_addr = base_addr - hdr.next_fetch_info.mem_offset2;
        // hdr.next_fetch_info.addr = hdr.next_fetch_info.addr + hdr.next_fetch_info.mem_offset2;
    }
    action step3(){
        hdr.next_fetch_info.mem_offset2 = final_offset + base_addr;
    }

    apply {

        if(hdr.next_fetch_info.has_value == 0){
            hdr.ib_bth.opcode =  ib_opcode_t.NOOP2;
        }else{

            getShift();
            getOffset();
            step3();

            hdr.ipv4.protocol = ipv4_protocol_t.UDP;
            /* Set base IPv4 len, will be updated with payload and padding in Egress */
            hdr.ipv4.total_len = hdr.ipv4.minSizeInBytes() + hdr.udp.minSizeInBytes() + 
                hdr.ib_bth.minSizeInBytes() + hdr.ib_reth.minSizeInBytes() + 4; 

            hdr.udp.length = hdr.udp.minSizeInBytes() + hdr.ib_bth.minSizeInBytes() + 
                hdr.ib_reth.minSizeInBytes() +  4;
            
            hdr.ib_bth.opcode = ib_opcode_t.RDMA_WRITE;
            
            hdr.ib_bth.se = 0;
            hdr.ib_bth.migration_req = 1;
            hdr.ib_bth.pad_count = 0;
            hdr.ib_bth.transport_version = 0;
            hdr.ib_bth.partition_key = 0xffff;
            hdr.ib_bth.ack = 1;
            // hdr.ib_bth.reserved2 = 0;
            hdr.ib_reth.remote_key = hdr.next_fetch_info.rdma_remote_key;
            hdr.next_fetch_info.has_value = 1 ;
            //// hdr.next_fetch_info.pdr_fetch_round_id = IB_RES_TYPE.BUFFER_REPLAY;
            // n.addr - UE_TABLE_OFFSET - n.mem_offset2 + TO_BUFFER_OFFSET + 100 + buffer_counter<<11 + n.mem_offset2 << 6

            hdr.ib_reth.addr = hdr.next_fetch_info.addr + hdr.next_fetch_info.mem_offset2;
            hdr.ib_reth.dma_len1 = 0;
        }
    }
}


control Paging_Pop_Loop_Egress(inout headers_t hdr){


    apply{
        if(hdr.ib_bth.se == 0){
            if(hdr.next_fetch_info.pdr_fetch_round_id == 0x7f){
                hdr.next_fetch_info.addr = hdr.next_fetch_info.addr - 0x3f800 - UE_RULE_LEN - UE_KEY_LEN;
            }else{
                hdr.next_fetch_info.addr = hdr.next_fetch_info.addr + 0x800 - UE_RULE_LEN - UE_KEY_LEN;
            }
        }else{
           hdr.next_fetch_info.addr = hdr.next_fetch_info.addr - UE_RULE_LEN - UE_KEY_LEN; 
        }
        hdr.ib_bth.opcode = ib_opcode_t.RDMA_READ;
        hdr.ib_reth.addr = hdr.next_fetch_info.addr ;
        hdr.next_fetch_info.setInvalid();
        hdr.ib_bth.se = 0;
    }
}


control Paging_Pop_Loop_Clear_Mirror(inout headers_t hdr, inout eg_metadata_t meta){
    apply {
        /* Chosen RDMA Server MAC Address */
        hdr.ethernet.dst_addr_1 = meta.mirror_truncate.server_mac_addr_1;
        hdr.ethernet.dst_addr_2 = meta.mirror_truncate.server_mac_addr_2;
        /* Fake MAC Address as source */
        hdr.ethernet.src_addr = 0x000000000001;

        /* Static RDMA Client IP Address where the connection is opened */
        hdr.ipv4.src_addr = RDMA_IP;//RDMA_IP;
        /* Chosen RDMA Server IP Address */
        hdr.ipv4.dst_addr = meta.mirror_truncate.server_ip_addr; 
        hdr.ipv4.ttl = 64;
        hdr.ipv4.flags = 0x2;
        hdr.ipv4.protocol = ipv4_protocol_t.UDP;
        /* Set base IPv4 len, will be updated with payload and padding in Egress */
        // Payload长度至少为4
        hdr.ipv4.total_len = hdr.ipv4.minSizeInBytes() + hdr.udp.minSizeInBytes() + 
            hdr.ib_bth.minSizeInBytes() + hdr.ib_reth.minSizeInBytes() + 4 + 4; 
        //+ hdr.next_fetch_info.minSizeInBytes() + hdr.packet_ue_key.minSizeInBytes() + hdr.packet_pdr_key.minSizeInBytes();

        /* Invalidate TCP header ([lyz]:assume only UDP packets for now), it'll be replaced with UDP/IB */
        hdr.udp.setValid();
        hdr.udp.src_port = 0;
        hdr.udp.dst_port = UDP_PORT_ROCEV2;
        hdr.udp.checksum = 0;

        /* Set base UDP len, will be updated with payload and padding in Egress */
        hdr.udp.length = hdr.udp.minSizeInBytes() + hdr.ib_bth.minSizeInBytes() + 
            hdr.ib_reth.minSizeInBytes() + 4 + 4;
        //+ hdr.next_fetch_info.minSizeInBytes() + hdr.packet_ue_key.minSizeInBytes() + hdr.packet_pdr_key.minSizeInBytes();

        //hdr.udp_payload.setInvalid();
        hdr.ib_bth.setValid();
        hdr.ib_bth.opcode = ib_opcode_t.RDMA_WRITE;
        hdr.ib_bth.se = 0;
        hdr.ib_bth.migration_req = 1;
        hdr.ib_bth.pad_count = 0;
        hdr.ib_bth.transport_version = 0;
        hdr.ib_bth.partition_key = 0xffff;
        hdr.ib_bth.reserved = IB_RES_TYPE.BUFFER_COUNTER;
        hdr.ib_bth.ack = 1;
        // hdr.ib_bth.reserved2 = 0;
        // hdr.ib_bth.dst_qp = meta.mirror_truncate.
        // hdr.ib_bth.psn = (bit<24>)meta.mirror_truncate.server_index; //determined in the egress logic
        /* Store the QP Index where we will read the real seq_n in the Egress */
        //hdr.ib_bth.psn = meta.mirror_truncate.server_qp_index;

        hdr.ib_reth.setValid();
        //next_fetch_info->pdr_fetch_round_id
        hdr.ib_reth.addr = meta.mirror_truncate.payload_addr;
        hdr.ib_reth.remote_key = meta.mirror_truncate.rdma_remote_key;
        hdr.ib_reth.dma_len1 = 0;
        hdr.ib_reth.dma_len2 = 4; 

        // next_fetch_info.pdr_fetch_round_id <- 0
        //模拟payload
        hdr.payload_request.setValid();
        hdr.payload_request.padding = meta.mirror_truncate.read_index;
        hdr.payload_request.padding1 = meta.mirror_truncate.pdr_fetch_round_id; 
        hdr.payload_request.padding2 = 0;
        hdr.payload_request.hdr_idx = 0;
        // hdr.payload_request.hdr_idx = 0x00; // IB_RES_TYPE.NULL;
        //Bug Feature, only one can be attached
        hdr.icrc.setValid(); 
        hdr.icrc2.setValid(); 
    }
}
#endif 
