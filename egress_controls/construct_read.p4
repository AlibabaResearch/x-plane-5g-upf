#ifndef _CONSTRUCT_READ_
#define _CONSTRUCT_READ_

#include "../include/types_r.p4"
#include "../include/configuration.p4"

control ConstructRead(inout headers_t hdr, inout eg_metadata_t meta) {
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
        hdr.ipv4.total_len = hdr.ipv4.minSizeInBytes() + hdr.udp.minSizeInBytes() + 
                        hdr.ib_bth.minSizeInBytes() + hdr.ib_reth.minSizeInBytes() + 4; 
                        //+ hdr.next_fetch_info.minSizeInBytes() + hdr.packet_ue_key.minSizeInBytes() + hdr.packet_pdr_key.minSizeInBytes();

        /* Invalidate TCP header ([lyz]:assume only UDP packets for now), it'll be replaced with UDP/IB */
        hdr.udp.setValid();
        hdr.udp.src_port = 0;
        hdr.udp.dst_port = UDP_PORT_ROCEV2;
        hdr.udp.checksum = 0;

        /* Set base UDP len, will be updated with payload and padding in Egress */
        hdr.udp.length = hdr.udp.minSizeInBytes() + hdr.ib_bth.minSizeInBytes() + 
                            hdr.ib_reth.minSizeInBytes() + 4;
                             //+ hdr.next_fetch_info.minSizeInBytes() + hdr.packet_ue_key.minSizeInBytes() + hdr.packet_pdr_key.minSizeInBytes();

        //hdr.udp_payload.setInvalid();
        hdr.ib_bth.setValid();
        hdr.ib_bth.opcode = ib_opcode_t.RDMA_READ;
        hdr.ib_bth.se = 0;
        hdr.ib_bth.migration_req = 1;
        hdr.ib_bth.pad_count = 0;
        hdr.ib_bth.transport_version = 0;
        hdr.ib_bth.partition_key = 0xffff;
        hdr.ib_bth.reserved = 7;
        hdr.ib_bth.ack = 1;
        hdr.ib_bth.reserved2 = 0;
        //hdr.ib_bth.dst_qp = meta.mirror_truncate.server_index; //determined in the egress logic
        /* Store the QP Index where we will read the real seq_n in the Egress */
        //hdr.ib_bth.psn = meta.mirror_truncate.server_qp_index;

        hdr.ib_reth.setValid();
        //hdr.ib_reth.addr = meta.mirror_truncate.payload_addr;// + UE_KEY_LEN + UE_RULE_LEN;// + (bit<64>) mem_addr_offset;//base_addr + mem_addr_offset;// + UE_KEY_LEN + UE_RULE_LEN);//  + UE_KEY_LEN + UE_RULE_LEN;// + final_offset; //lyz
        hdr.ib_reth.remote_key = meta.mirror_truncate.rdma_remote_key;
        hdr.ib_reth.dma_len1 = 0;
        if (meta.mirror_truncate.pdr_fetch_round_id == 0) {
            hdr.ib_reth.addr = meta.mirror_truncate.payload_addr + UE_FLOW_TABLE_OFFSET;
            hdr.ib_reth.dma_len2 = meta.mirror_truncate.payload_len + UE_FLOW_KEY_LEN + UE_FLOW_RULE_LEN; // [todo: replace with padding] // + hdr.payload_request.padding;
        }
        else if (meta.mirror_truncate.pdr_fetch_round_id == 1) { // rdma read of ue state data
            hdr.ib_reth.addr = meta.mirror_truncate.payload_addr + UE_KEY_LEN;
            hdr.ib_reth.dma_len2 = 4; // counter of 4 bytes
            // to trigger outstand window control
            //meta.mirror_truncate.pdr_fetch_round_id = 0;
        }
        else {
            hdr.ib_reth.addr = meta.mirror_truncate.payload_addr;
            hdr.ib_reth.dma_len2 = meta.mirror_truncate.payload_len + UE_KEY_LEN + UE_RULE_LEN;
        }
        hdr.icrc.setValid(); 
        hdr.icrc2.setValid(); 
        /*
        hdr.ib_bth.opcode = ib_opcode_t.RDMA_READ;
        if (hdr.next_fetch_info.pdr_fetch_round_id > 0) {
            hdr.ib_reth.addr = hdr.next_fetch_info.addr - UE_KEY_LEN - UE_RULE_LEN;
        }
        else {
            hdr.ib_reth.addr = hdr.ib_reth.addr - UE_KEY_LEN - UE_RULE_LEN;
        }
        hdr.ib_reth.dma_len2 = meta.mirror_truncate.payload_len; //todo: change to the corrent size

        // todo: change to the corrent length
        hdr.ipv4.total_len = PKT_MIN_LENGTH - meta.mirror_truncate.minSizeInBytes() - hdr.ethernet.minSizeInBytes();
        if (hdr.udp.isValid()) {
            hdr.udp.length = PKT_MIN_LENGTH - meta.mirror_truncate.minSizeInBytes() - hdr.ethernet.minSizeInBytes() -
                 hdr.ipv4.minSizeInBytes();
        }

        hdr.next_fetch_info.setInvalid();
        hdr.packet_ue_key.setInvalid();
        hdr.packet_pdr_key.setInvalid();
        */
    }
}



control ConstructWrite(inout headers_t hdr, inout eg_metadata_t meta) {
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
        hdr.ipv4.total_len = hdr.ipv4.minSizeInBytes() + hdr.udp.minSizeInBytes() + 
                        hdr.ib_bth.minSizeInBytes() + hdr.ib_reth.minSizeInBytes() + 4 + 
                        hdr.ue_flow_key.minSizeInBytes() + hdr.ue_flow_rule.minSizeInBytes(); 
                        //+ hdr.next_fetch_info.minSizeInBytes() + hdr.packet_ue_key.minSizeInBytes() + hdr.packet_pdr_key.minSizeInBytes();

        /* Invalidate TCP header ([lyz]:assume only UDP packets for now), it'll be replaced with UDP/IB */
        hdr.udp.setValid();
        hdr.udp.src_port = 0;
        hdr.udp.dst_port = UDP_PORT_ROCEV2;
        hdr.udp.checksum = 0;

        /* Set base UDP len, will be updated with payload and padding in Egress */
        hdr.udp.length = hdr.udp.minSizeInBytes() + hdr.ib_bth.minSizeInBytes() + 
                            hdr.ib_reth.minSizeInBytes() + 4 +
                             hdr.ue_flow_key.minSizeInBytes() + hdr.ue_flow_rule.minSizeInBytes(); 
                             //+ hdr.next_fetch_info.minSizeInBytes() + hdr.packet_ue_key.minSizeInBytes() + hdr.packet_pdr_key.minSizeInBytes();

        //hdr.udp_payload.setInvalid();
        hdr.ib_bth.setValid();
        hdr.ib_bth.opcode = ib_opcode_t.RDMA_WRITE;
        hdr.ib_bth.se = 0;
        hdr.ib_bth.migration_req = 1;
        hdr.ib_bth.pad_count = 0;
        hdr.ib_bth.transport_version = 0;
        hdr.ib_bth.partition_key = 0xffff;
        hdr.ib_bth.reserved = 9;
        hdr.ib_bth.ack = 1;
        hdr.ib_bth.reserved2 = 0;
        //hdr.ib_bth.dst_qp = meta.mirror_truncate.server_index; //determined in the egress logic
        /* Store the QP Index where we will read the real seq_n in the Egress */
        //hdr.ib_bth.psn = meta.mirror_truncate.server_qp_index;

        hdr.ib_reth.setValid();
        //hdr.ib_reth.addr = meta.mirror_truncate.payload_addr;// + UE_KEY_LEN + UE_RULE_LEN;// + (bit<64>) mem_addr_offset;//base_addr + mem_addr_offset;// + UE_KEY_LEN + UE_RULE_LEN);//  + UE_KEY_LEN + UE_RULE_LEN;// + final_offset; //lyz
        hdr.ib_reth.remote_key = meta.mirror_truncate.rdma_remote_key;
        hdr.ib_reth.dma_len1 = 0;
        hdr.ib_reth.dma_len2 = hdr.ue_flow_key.minSizeInBytes() + hdr.ue_flow_rule.minSizeInBytes(); 
        hdr.ib_reth.addr = meta.mirror_truncate.payload_addr + PDR_TABLE_OFFSET + 1; // todo！！！！" cahngeto the correct ue flow table addr
           
        
        // add ue flow data [todo]
        hdr.lookup_resp_type.setInvalid();
        // hdr.lookup_resp_type.resp_type = LookupRespType.UE_FLOW;
        hdr.ue_flow_key.setValid();
        hdr.ue_flow_key.ue_addr = 0;//hdr.ipv4.src_addr;
        hdr.ue_flow_key.inet_addr = 0;//hdr.ipv4.dst_addr;
        hdr.ue_flow_key.ue_port = 0;//hdr.udp.src_port;
        hdr.ue_flow_key.inet_port = 0;//hdr.udp.dst_port;
        hdr.ue_flow_rule.setValid();
        //hdr.ue_flow_rule.counter = meta.mirror_truncate.payload_len; // use this field to carry state data
        
        hdr.icrc.setValid(); 
        hdr.icrc2.setValid(); 
    
    }
}

#endif 
