#ifndef _FETCH_RULE_
#define _FETCH_RULE_

#include "../include/types_r.p4"
#include "../include/configuration.p4"
#include "../include/registers.p4"

// initialize the first round of rule fetch
control FetchRule(inout headers_t hdr, inout ig_metadata_t meta,
                     //inout ingress_intrinsic_metadata_t ig_intr_md,
                     in ingress_intrinsic_metadata_from_parser_t ig_prsr_md,
                     inout ingress_intrinsic_metadata_for_deparser_t ig_dprsr_md,
                     inout ingress_intrinsic_metadata_for_tm_t ig_tm_md,
                     in bit<16> server_mac_addr_1,
                     in bit<32> server_mac_addr_2,
                     in ipv4_addr_t server_ip_addr,
                     in bit<32> mem_addr_offset,
                     in bit<16> current_server_idx,
                     in bit<16> current_qp_idx,
                     //in bit<32> addr_1,
                     //in bit<32> addr_2,
                     in bit<32> rdma_remote_key) {
                        
    bit<16> payload_len;
    bit<32> addr_1; //= remote_address_1_read.execute(current_server_idx);
    bit<32> addr_2;// = remote_address_2_read.execute(current_server_idx);// + mem_addr_offset;
    bit<64> base_addr_ue;// = addr_1 ++ addr_2 + UE_KEY_LEN + UE_RULE_LEN;
    //bit<64> base_addr_pdr;// = addr_1 ++ addr_2 + PDR_TABLE_OFFSET + UE_KEY_LEN + PDR_LEN;
    bit<64> final_offset = 32w0x0 ++ mem_addr_offset;

    RegisterAction<bit<32>, _, bit<32>>(remote_address_1) remote_address_1_read = {
        void apply(inout bit<32> value, out bit<32> read_value) {
            read_value = value;
        }
    };

    RegisterAction<bit<32>, _, bit<32>>(remote_address_2) remote_address_2_read = {
        void apply(inout bit<32> value, out bit<32> read_value) {
            read_value = value;
        }
    };

    action remote_addr1_read_act() {
        addr_1 = remote_address_1_read.execute(current_server_idx);
    }

    @stage(7)
    table remote_addr1_read_tbl {
		key = {}
		actions = {remote_addr1_read_act;}
		size = 1;
		default_action = remote_addr1_read_act;
	}

	action remote_addr2_read_act() {
        addr_2 = remote_address_2_read.execute(current_server_idx);
    }

    @stage(7)
    table remote_addr2_read_tbl {
		key = {}
		actions = {remote_addr2_read_act;}
		size = 1;
		default_action = remote_addr2_read_act;
	}

    action add_addr_act() {
        base_addr_ue = addr_1 ++ addr_2;// + UE_KEY_LEN + UE_RULE_LEN;
    }

    table add_addr_tbl {
		key = {}
		actions = {add_addr_act;}
		size = 1;
		default_action = add_addr_act;
	}

    action udp_packet() {
        payload_len = payload_len - hdr.udp.minSizeInBytes() +
                         hdr.next_fetch_info.minSizeInBytes() + hdr.packet_ue_key.minSizeInBytes() + hdr.packet_pdr_key.minSizeInBytes();
    }

    /* RDMA WRITE Action */
    action send_rdma_write() {
        /* Chosen RDMA Server MAC Address */
        hdr.ethernet.dst_addr_1 = server_mac_addr_1;//server_mac_address_1_read.execute(0);//server_mac_addr_1;
        hdr.ethernet.dst_addr_2 = server_mac_addr_2;//server_mac_address_2_read.execute(0);//server_mac_addr_2;
        /* Fake MAC Address as source */
        hdr.ethernet.src_addr = 0x000000000001;

        /* to be modified */
        hdr.packet_ue_key.setValid();
        hdr.packet_ue_key.teid = hdr.gtpu.pdr_round;
        hdr.packet_ue_key.src_addr = hdr.inner_ipv4.src_addr;
        hdr.packet_ue_key.qfi = hdr.gtpu_ext_psc.qfi;
        hdr.packet_pdr_key.setValid();  // we only use part of the fields for the first-step test
        hdr.packet_pdr_key.qfi = hdr.gtpu_ext_psc.qfi;
        //hdr.packet_pdr_key.teid = hdr.gtpu.teid;
        hdr.packet_pdr_key.ue_port = hdr.udp.src_port;
        hdr.packet_pdr_key.inet_port = hdr.inner_udp.dst_port;
        hdr.packet_pdr_key.ue_addr = hdr.ipv4.src_addr;
        hdr.packet_pdr_key.inet_addr = hdr.ipv4.dst_addr;

        /* Static RDMA Client IP Address where the connection is opened */
        hdr.ipv4.src_addr = RDMA_IP;//RDMA_IP;
        /* Chosen RDMA Server IP Address */
        hdr.ipv4.dst_addr = server_ip_addr; 
		hdr.ipv4.ttl = 64;
        hdr.ipv4.flags = 0x2;
        hdr.ipv4.protocol = ipv4_protocol_t.UDP;
        /* Set base IPv4 len, will be updated with payload and padding in Egress */
        // todo: add packet_ue_key length (the same for other places)
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
        hdr.ib_bth.opcode = ib_opcode_t.RDMA_WRITE; 
        hdr.ib_bth.se = 0;
        hdr.ib_bth.migration_req = 1;
        hdr.ib_bth.pad_count = 0;
        hdr.ib_bth.transport_version = 0;
        hdr.ib_bth.partition_key = 0xffff;
        hdr.ib_bth.reserved = 1; // 1: write ue_flow_table; 2: write ue_table 3: write pdr table
        hdr.ib_bth.ack = 1;
        hdr.ib_bth.reserved2 = 0;
        hdr.ib_bth.dst_qp = (bit<24>) (current_server_idx << QP_POWER); //determined in the egress logic
        /* Store the QP Index where we will read the real seq_n in the Egress */
        hdr.ib_bth.psn = (bit<24>) current_qp_idx;

        hdr.ib_reth.setValid();
        hdr.ib_reth.addr = base_addr_ue + final_offset; // lyz
        hdr.ib_reth.remote_key = rdma_remote_key;
        hdr.ib_reth.dma_len1 = 0;
        hdr.ib_reth.dma_len2 = payload_len; 

        /* lyz: we no longer use payload_request */
        hdr.payload_request.setInvalid();

        //todo: server id
        hdr.next_fetch_info.setValid();
        hdr.next_fetch_info.addr = base_addr_ue;// + PDR_TABLE_OFFSET;
        hdr.next_fetch_info.pdr_fetch_round_id = 0;
        hdr.next_fetch_info.current_server_idx = 0;//current_server_idx << QP_POWER; //used as QP server-level offset
        hdr.next_fetch_info.current_qp_idx = current_qp_idx;
        hdr.next_fetch_info.payload_len = payload_len;
        hdr.next_fetch_info.mem_offset = UE_FLOW_TABLE_OFFSET;//mem_addr_offset; // used to store UE_FLOW table offset
        hdr.next_fetch_info.rdma_remote_key = rdma_remote_key;
        //hdr.next_fetch_info.c_slot_idx = c_slot_idx;
        //hdr.next_fetch_info.ints_fwd = (bit<32>) ig_prsr_md.global_tstamp;

		hdr.icrc.setValid(); //potential problem - shifted payload data（but not relevant to the performance test, solve it later）
    }

    /* Packet Cloning action - to construct RDMA read */
    action mirror() {
        //todo: remove unused fields
        meta.payload_addr = base_addr_ue + final_offset;//hdr.ib_reth.addr;
        //meta.hdr_idx = 0;//hdr.payload_request.hdr_idx;
        meta.payload_len = payload_len;//hdr.ib_reth.dma_len2;
        meta.server_qp_index = current_qp_idx + (bit<16>) hdr.ib_bth.dst_qp;
        meta.server_index = current_server_idx << QP_POWER; // used as QP server-level offset
        meta.server_mac_addr_1 = server_mac_addr_1;
        meta.server_mac_addr_2 = server_mac_addr_2;
        meta.server_ip_addr = server_ip_addr;
        meta.rdma_remote_key = rdma_remote_key;
        meta.pdr_fetch_round_id = 0;//hdr.next_fetch_info.pdr_fetch_round_id; 

        ig_dprsr_md.mirror_type = TRUNCATE_MIRROR_TYPE;
        //meta.mirror_session = TRUNCATE_MIRROR_SESSION; // This field is assigned outside to mirror the packet to the correct port.
        meta.packet_type = PKT_TYPE_MIRROR_TRUNCATE;
    }

    /* FetchRule action */
    action fetch_rule() {
        send_rdma_write();
    }

    apply {
        /* Compute payload len. Should be done in another action to avoid multiple-stages */
        if (hdr.udp.isValid()) {
            payload_len = hdr.ipv4.total_len - hdr.ipv4.minSizeInBytes() - hdr.udp.minSizeInBytes() +
                         hdr.next_fetch_info.minSizeInBytes() + hdr.packet_ue_key.minSizeInBytes() + hdr.packet_pdr_key.minSizeInBytes();
            //udp_packet();
        }
        remote_addr1_read_tbl.apply();
        remote_addr2_read_tbl.apply();
        add_addr_tbl.apply();
        //remote_key_read_tbl.apply();
        fetch_rule();
        mirror();
    }
}


control KeepFetchRule0(inout headers_t hdr, inout ig_metadata_t meta, 
                     in ingress_intrinsic_metadata_from_parser_t ig_prsr_md,
                     inout ingress_intrinsic_metadata_for_deparser_t ig_dprsr_md,
                     in bit<16> server_mac_addr_1,
                     in bit<32> server_mac_addr_2,   //, in bit<32> mem_addr_offset
                     in ipv4_addr_t server_ip_addr) {
    //bit<16> payload_len;
    bit<16> qp_idx;
    //bit<64> final_offset = 32w0x0 ++ mem_addr_offset;

    apply {
        qp_idx = hdr.next_fetch_info.current_server_idx;// << QP_POWER;
        //qp_idx = hdr.ib_bth.dst_qp;
        // if (hdr.udp.isValid()) {
        //     payload_len = hdr.ipv4.total_len - hdr.ipv4.minSizeInBytes() - hdr.udp.minSizeInBytes() +
        //     hdr.next_fetch_info.minSizeInBytes() + hdr.packet_ue_key.minSizeInBytes() + hdr.packet_pdr_key.minSizeInBytes();
        // }
        hdr.ethernet.dst_addr_1 = server_mac_addr_1;
        hdr.ethernet.dst_addr_2 = server_mac_addr_2;
        hdr.ethernet.src_addr = 0x000000000001;
        hdr.ipv4.src_addr = RDMA_IP;
        hdr.ipv4.dst_addr = server_ip_addr; 
        hdr.ipv4.ttl = 64;
        hdr.ipv4.flags = 0x2;
        hdr.ipv4.protocol = ipv4_protocol_t.UDP;
        // hdr.ipv4.total_len = hdr.ipv4.minSizeInBytes() + hdr.udp.minSizeInBytes() + 
        //                 hdr.ib_bth.minSizeInBytes() + hdr.ib_reth.minSizeInBytes() + 4;
        hdr.ipv4.total_len = hdr.ipv4.total_len; // compilation fails with this

        hdr.udp.setValid();
        hdr.udp.src_port = 0;
        hdr.udp.dst_port = UDP_PORT_ROCEV2;
        hdr.udp.checksum = 0;
        // hdr.udp.length = hdr.udp.minSizeInBytes() + hdr.ib_bth.minSizeInBytes() + 
        //                     hdr.ib_reth.minSizeInBytes() + 4;
        hdr.udp.length = hdr.udp.length; // compilation fails with this

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
        //hdr.ib_bth.dst_qp = (bit<24>) hdr.next_fetch_info.current_server_idx; // do not change the value here
        hdr.ib_bth.psn = (bit<24>) qp_idx;//(bit<24>) hdr.next_fetch_info.current_qp_idx;
        
        hdr.ib_reth.setValid();
        //hdr.ib_reth.addr = hdr.next_fetch_info.addr; // [root cause of the error]
        hdr.ib_reth.remote_key = 0;
        hdr.ib_reth.dma_len1 = 0;
        hdr.ib_reth.dma_len2 = hdr.udp.length - 28 - UE_FLOW_KEY_LEN - UE_FLOW_RULE_LEN - 3;// payload_len; // filled in egress 

        hdr.next_fetch_info.pdr_fetch_round_id = hdr.next_fetch_info.pdr_fetch_round_id + 1;
        //hdr.next_fetch_info.addr = hdr.next_fetch_info.addr + final_offset;
        //hdr.next_fetch_info.ints_fwd = (bit<32>) ig_prsr_md.global_tstamp;

        // mirror
        //meta.payload_addr = hdr.next_fetch_info.addr;
        meta.payload_len = hdr.udp.length - 28 - UE_FLOW_KEY_LEN - UE_FLOW_RULE_LEN - 3;//hdr.next_fetch_info.payload_len;// + UE_FLOW_KEY_LEN + UE_FLOW_RULE_LEN;
        meta.server_qp_index = (bit<16>) hdr.ib_bth.dst_qp + qp_idx; // inter-server qp offset
        meta.server_index = 0;// (bit<16>) hdr.ib_bth.dst_qp;//hdr.next_fetch_info.current_server_idx; // intra-server offset 
        meta.server_mac_addr_1 = server_mac_addr_1;
        meta.server_mac_addr_2 = server_mac_addr_2;
        meta.server_ip_addr = server_ip_addr;
        meta.rdma_remote_key = hdr.next_fetch_info.rdma_remote_key;
        meta.pdr_fetch_round_id = 3; // only used to signal the flow control

        ig_dprsr_md.mirror_type = TRUNCATE_MIRROR_TYPE;
        //meta.mirror_session = TRUNCATE_MIRROR_SESSION;
        meta.packet_type = PKT_TYPE_MIRROR_TRUNCATE;
        
        hdr.ib_aeth.setInvalid();
        hdr.ue_key.setInvalid();
        hdr.ue_flow_key.setInvalid();
        hdr.ue_flow_rule.setInvalid();
        hdr.lookup_resp_type.setInvalid();
        hdr.pdr0.setInvalid();
        hdr.pdr1.setInvalid();
        hdr.pdr2.setInvalid();
        hdr.pdr3.setInvalid();
        hdr.pdr4.setInvalid();
        hdr.ue.setInvalid();
    }
}

control KeepFetchRule1(inout headers_t hdr, inout ig_metadata_t meta, 
                     in ingress_intrinsic_metadata_from_parser_t ig_prsr_md,
                     inout ingress_intrinsic_metadata_for_deparser_t ig_dprsr_md,
                     in bit<16> server_mac_addr_1,
                     in bit<32> server_mac_addr_2,   //, in bit<32> mem_addr_offset
                     in ipv4_addr_t server_ip_addr) {
    //bit<16> payload_len;
    bit<16> qp_idx;
    //bit<64> final_offset = 32w0x0 ++ mem_addr_offset;

    apply {
        qp_idx = hdr.next_fetch_info.current_server_idx;// << QP_POWER;
        //qp_idx = hdr.ib_bth.dst_qp;
        // if (hdr.udp.isValid()) {
        //     payload_len = hdr.ipv4.total_len - hdr.ipv4.minSizeInBytes() - hdr.udp.minSizeInBytes() +
        //     hdr.next_fetch_info.minSizeInBytes() + hdr.packet_ue_key.minSizeInBytes() + hdr.packet_pdr_key.minSizeInBytes();
        // }
        hdr.ethernet.dst_addr_1 = server_mac_addr_1;
        hdr.ethernet.dst_addr_2 = server_mac_addr_2;
        hdr.ethernet.src_addr = 0x000000000001;
        hdr.ipv4.src_addr = RDMA_IP;
        hdr.ipv4.dst_addr = server_ip_addr; 
        hdr.ipv4.ttl = 64;
        hdr.ipv4.flags = 0x2;
        hdr.ipv4.protocol = ipv4_protocol_t.UDP;
        // hdr.ipv4.total_len = hdr.ipv4.minSizeInBytes() + hdr.udp.minSizeInBytes() + 
        //                 hdr.ib_bth.minSizeInBytes() + hdr.ib_reth.minSizeInBytes() + 4;
        hdr.ipv4.total_len = hdr.ipv4.total_len; // compilation fails with this

        // hdr.udp.setValid();
        hdr.udp.src_port = 0;
        hdr.udp.dst_port = UDP_PORT_ROCEV2;
        hdr.udp.checksum = 0;
        // hdr.udp.length = hdr.udp.minSizeInBytes() + hdr.ib_bth.minSizeInBytes() + 
        //                     hdr.ib_reth.minSizeInBytes() + 4;
        hdr.udp.length = hdr.udp.length; // compilation fails with this

        // hdr.ib_bth.setValid();
        hdr.ib_bth.opcode = ib_opcode_t.RDMA_WRITE; 
        hdr.ib_bth.se = 0;
        hdr.ib_bth.migration_req = 1;
        hdr.ib_bth.pad_count = 0;
        hdr.ib_bth.transport_version = 0;
        hdr.ib_bth.partition_key = 0xffff;
        hdr.ib_bth.reserved = 9;
        hdr.ib_bth.ack = 1;
        hdr.ib_bth.reserved2 = 0;
        //hdr.ib_bth.dst_qp = (bit<24>) hdr.next_fetch_info.current_server_idx; // do not change the value here
        hdr.ib_bth.psn = (bit<24>) qp_idx;//(bit<24>) hdr.next_fetch_info.current_qp_idx;
        
        hdr.ib_reth.setValid();
        //hdr.ib_reth.addr = hdr.next_fetch_info.addr; // [root cause of the error]
        hdr.ib_reth.remote_key = 0;
        hdr.ib_reth.dma_len1 = 0;
        hdr.ib_reth.dma_len2 = hdr.udp.length - 28 - UE_KEY_LEN - UE_RULE_LEN;// payload_len; // filled in egress 

        hdr.next_fetch_info.pdr_fetch_round_id = hdr.next_fetch_info.pdr_fetch_round_id + 1;
        //hdr.next_fetch_info.addr = hdr.next_fetch_info.addr + final_offset;
        //hdr.next_fetch_info.ints_fwd = (bit<32>) ig_prsr_md.global_tstamp;

        // mirror
        //meta.payload_addr = hdr.next_fetch_info.addr;
        meta.payload_len = hdr.udp.length - 28 - UE_KEY_LEN - UE_RULE_LEN;//hdr.next_fetch_info.payload_len;// + UE_FLOW_KEY_LEN + UE_FLOW_RULE_LEN;
        meta.server_qp_index = (bit<16>) hdr.ib_bth.dst_qp + qp_idx; // inter-server qp offset
        meta.server_index = 0;// (bit<16>) hdr.ib_bth.dst_qp;//hdr.next_fetch_info.current_server_idx; // intra-server offset 
        meta.server_mac_addr_1 = server_mac_addr_1;
        meta.server_mac_addr_2 = server_mac_addr_2;
        meta.server_ip_addr = server_ip_addr;
        meta.rdma_remote_key = hdr.next_fetch_info.rdma_remote_key;
        meta.pdr_fetch_round_id = 3; // only used to signal the flow control

        ig_dprsr_md.mirror_type = TRUNCATE_MIRROR_TYPE;
        //meta.mirror_session = TRUNCATE_MIRROR_SESSION;
        meta.packet_type = PKT_TYPE_MIRROR_TRUNCATE;
        
        hdr.ib_aeth.setInvalid();
        hdr.ue_key.setInvalid();
        hdr.ue_flow_key.setInvalid();
        hdr.ue_flow_rule.setInvalid();
        hdr.lookup_resp_type.setInvalid();
        hdr.pdr0.setInvalid();
        hdr.pdr1.setInvalid();
        hdr.pdr2.setInvalid();
        hdr.pdr3.setInvalid();
        hdr.pdr4.setInvalid();
        hdr.ue.setInvalid();
    }
}

control WriteBackStateData(inout headers_t hdr, inout ig_metadata_t meta,  
                     inout ingress_intrinsic_metadata_for_deparser_t ig_dprsr_md,
                     in bit<16> server_mac_addr_1,
                     in bit<32> server_mac_addr_2,
                     in ipv4_addr_t server_ip_addr) {
    bit<16> qp_idx;

    apply{
        qp_idx = hdr.next_fetch_info.current_server_idx;// << QP_POWER;
        //qp_idx = hdr.ib_bth.dst_qp;

        // original packets: rdma read response
        // mirrored packet as the original packet
        // using reserved field to identify at egress
        meta.payload_addr = hdr.next_fetch_info.addr; //(bit<64>) hdr.next_fetch_info.mem_offset + 
        // [not used] meta.payload_len = hdr.next_fetch_info.payload_len;// + UE_FLOW_KEY_LEN + UE_FLOW_RULE_LEN;
        meta.server_qp_index =  (bit<16>) hdr.ib_bth.dst_qp + qp_idx;//hdr.next_fetch_info.current_qp_idx;
        meta.server_index = 0; // (bit<16>) hdr.ib_bth.dst_qp; //hdr.next_fetch_info.current_server_idx;
        meta.server_mac_addr_1 = server_mac_addr_1;
        meta.server_mac_addr_2 = server_mac_addr_2;
        meta.server_ip_addr = server_ip_addr;
        meta.rdma_remote_key = hdr.next_fetch_info.rdma_remote_key;
        meta.pdr_fetch_round_id = 2; // 2 means mirrored packet for rdma write 
        ig_dprsr_md.mirror_type = WRITE_MIRROR_TYPE;
        //meta.mirror_session = WRITE_MIRROR_SESSION;
        meta.packet_type = PKT_TYPE_MIRROR_TRUNCATE;
    }
}

control ReadUeState(inout headers_t hdr, inout ig_metadata_t meta,  
                     inout ingress_intrinsic_metadata_for_deparser_t ig_dprsr_md,
                     in bit<16> server_mac_addr_1,
                     in bit<32> server_mac_addr_2,
                     in ipv4_addr_t server_ip_addr) {
    bit<16> qp_idx;

    apply{
        qp_idx = hdr.next_fetch_info.current_server_idx;// << QP_POWER;
        //qp_idx = hdr.ib_bth.dst_qp;

        // original packets: rdma read response
        // mirrored packet as the original packet
        // using reserved field to identify at egress
        // meta.payload_addr = hdr.next_fetch_info.addr; //(bit<64>) hdr.next_fetch_info.mem_offset + 
        // [not used] meta.payload_len = hdr.next_fetch_info.payload_len;// + UE_FLOW_KEY_LEN + UE_FLOW_RULE_LEN;
        meta.server_qp_index =  (bit<16>) hdr.ib_bth.dst_qp + qp_idx;//hdr.next_fetch_info.current_qp_idx;
        meta.server_index = 0; // (bit<16>) hdr.ib_bth.dst_qp; //hdr.next_fetch_info.current_server_idx;
        meta.server_mac_addr_1 = server_mac_addr_1;
        meta.server_mac_addr_2 = server_mac_addr_2;
        meta.server_ip_addr = server_ip_addr;
        meta.rdma_remote_key = hdr.next_fetch_info.rdma_remote_key;
        meta.pdr_fetch_round_id = 1; // 1 means rdma read of UE state data 
        ig_dprsr_md.mirror_type = WRITE_MIRROR_TYPE;
        //meta.mirror_session = WRITE_MIRROR_SESSION;
        meta.packet_type = PKT_TYPE_MIRROR_TRUNCATE;
    }
}


control WriteUeState(inout headers_t hdr, inout ig_metadata_t meta,  
                     inout ingress_intrinsic_metadata_for_deparser_t ig_dprsr_md,
                     in bit<16> server_mac_addr_1,
                     in bit<32> server_mac_addr_2,
                     in ipv4_addr_t server_ip_addr) {
    bit<16> qp_idx;

    apply{
        qp_idx = hdr.next_fetch_info.current_server_idx;// << QP_POWER;

        // original packets: rdma read response
        // mirrored packet as the original packet
        // using reserved field to identify at egress
        meta.payload_addr = hdr.next_fetch_info.addr; //(bit<64>) hdr.next_fetch_info.mem_offset + 
        // [not used] meta.payload_len = hdr.next_fetch_info.payload_len;// + UE_FLOW_KEY_LEN + UE_FLOW_RULE_LEN;
        meta.server_qp_index =  (bit<16>) hdr.ib_bth.dst_qp + qp_idx;//hdr.next_fetch_info.current_qp_idx;
        meta.server_index = 0; 
        meta.server_mac_addr_1 = server_mac_addr_1;
        meta.server_mac_addr_2 = server_mac_addr_2;
        meta.server_ip_addr = server_ip_addr;
        meta.rdma_remote_key = hdr.next_fetch_info.rdma_remote_key;
        meta.pdr_fetch_round_id = 4; // 4 means rdma write of UE state data 
        ig_dprsr_md.mirror_type = WRITE_MIRROR_TYPE;
        //meta.mirror_session = WRITE_MIRROR_SESSION;
        meta.packet_type = PKT_TYPE_MIRROR_TRUNCATE;
    }
}


// list of modification todo
// 1. change addr calculation in fetch_rule
// 2. change the first send to UE_FLOW table
// 3. change the response handler
// 4. add write back mechanism
// 5. change server
// 6. debug

#endif 
