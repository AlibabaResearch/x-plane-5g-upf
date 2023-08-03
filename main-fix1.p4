#define SWITCH_LOOPBACK_PIPE

#include <core.p4>
#include <tna.p4>

#include "include/headers_r.p4"
#include "include/registers.p4"

#include "parsers/ingress_parser.p4"
#include "parsers/egress_parser.p4"

#include "ingress_controls/fetch_rule.p4"
#include "egress_controls/construct_read.p4"
#include "ingress_controls/hash_collision_sol.p4"
#include "ingress_controls/pdr_process.p4"

/*paging*/
#include "ingress_controls/ingress_paging.p4"
#include "egress_controls/egress_paging.p4"

/* INGRESS */
control Ingress(inout headers_t hdr, inout ig_metadata_t meta, in ingress_intrinsic_metadata_t ig_intr_md,
                in ingress_intrinsic_metadata_from_parser_t ig_prsr_md,
                inout ingress_intrinsic_metadata_for_deparser_t ig_dprsr_md,
                inout ingress_intrinsic_metadata_for_tm_t ig_tm_md) {

    //PayloadSplit() payload_split;
	FetchRule() fetch_rule;
	KeepFetchRule0() keep_fetch_rule0;
	KeepFetchRule1() keep_fetch_rule1;
	ReadUeState() read_ue_state;
	WriteUeState() write_ue_state;
	//FetchRulePDR() fetch_rule_pdr;
	HashCollisionSol() hash_collision_sol;
	PDRMatch() pdr_match;
	WriteBackStateData() write_back_ue_flow;
	/*paging*/
	Paging_Push_Ingress() paging_push_ingress;
    Paging_Pop_Loop_Ingress() paging_pop_loop;

    bit<16> server_mac_addr_1;
    bit<32> server_mac_addr_2;
    ipv4_addr_t server_ip_addr;
    PortId_t server_port_idx;
    bit<16> current_server_idx;
    bit<16> current_qp_idx;
    bit<32> rdma_addr_hash;
    bit<32> addr_hash_offset;
	bit<32> server_hash_start_addr;
    Hash<bit<UE_FLOW_SIZE_POWER>>(HashAlgorithm_t.CRC16) hash_ue;
	Hash<bit<UE_FLOW_SIZE_POWER>>(HashAlgorithm_t.CRC16) hash_ue2;
	Hash<bit<SERVER_SIZE_POWER>>(HashAlgorithm_t.CRC16) hash_server;
	//Hash<bit<SERVER_SIZE_POWER>>(HashAlgorithm_t.CRC16) hash_fwd_port; //routing basing on five tuples
	Hash<bit<QP_POWER>>(HashAlgorithm_t.CRC16) hash_qp;
	//RDMA stack info
	bit<32> rdma_remote_key;
	//bit<32> addr_1; 
    //bit<32> addr_2;
	//bit<32> ue_flow_offset;

	/* concurrency control */
	//Hash<bit<CONCURRENCY_CONTROL_TABLE_SIZE_POWER>>(HashAlgorithm_t.CRC16) c_hash; //hash value for getting the concurrency control slot idx
	bit<CONCURRENCY_CONTROL_TABLE_SIZE_POWER> c_slot_idx;
	bit<1> c_slot_src_ip_matched;
	bit<1> c_slot_dst_ip_matched;
	bit<1> c_slot_src_port_matched;
	bit<1> c_slot_dst_port_matched;
	bit<1> c_slot_protocol_matched;
	bit<16> inflight_num;

	// inflight counter
	RegisterAction<bit<16>, _, bit<16>>(c_inflight_counter) c_inflight_inc = {
        void apply(inout bit<16> value, out bit<16> read_value) {
			read_value = value;
			value = value + 1;
        }
    };
    action c_inflight_inc_act() {
        inflight_num = c_inflight_inc.execute(c_slot_idx);
    }
	
    @stage(3)
    table c_inflight_inc_tbl {
		key = {}
		actions = {c_inflight_inc_act;}
		size = 1;
		default_action = c_inflight_inc_act;
	}
	// reset filled
	RegisterAction<bit<8>, _, bit<8>>(c_filled) c_filled_reset = {
        void apply(inout bit<8> value, out bit<8> read_value) {
            value = 0;
        }
    };
    action c_filled_reset_act() {
        c_filled_reset.execute(c_slot_idx);
    }
    @stage(5)
    table c_filled_reset_tbl {
		key = {}
		actions = {c_filled_reset_act;}
		size = 1;
		default_action = c_filled_reset_act;
	}
	/****** concurrency control end *****/


    /* store server information */
	RegisterAction<bit<16>, _, bit<16>>(server_port) server_port_write = {
		void apply(inout bit<16> value, out bit<16> read_value) {
			value = (bit<16>) ig_intr_md.ingress_port;
		}
	};

    action server_port_write_act() {
        server_port_write.execute(hdr.rdma_eth_info.server_id);
    }

    @stage(6)
    table server_port_write_tbl {
		key = {}
		actions = {server_port_write_act;}
		size = 1;
		default_action = server_port_write_act;
	}

	RegisterAction<bit<16>, _, PortId_t>(server_port) server_port_read = {
        void apply(inout bit<16> value, out PortId_t read_value) {
            read_value = (PortId_t) value;
        }
    };

    action server_port_read_act() {
        server_port_idx = server_port_read.execute(current_server_idx);
    }

    @stage(6)
    table server_port_read_tbl {
		key = {}
		actions = {server_port_read_act;}
		size = 1;
		default_action = server_port_read_act;
	}

	RegisterAction<ipv4_addr_t, _, ipv4_addr_t>(server_ip_address) server_ip_address_write = {
		void apply(inout ipv4_addr_t value, out ipv4_addr_t read_value) {
			value = hdr.rdma_eth_info.ip_address;
		}
	};

    action server_ip_write_act() {
        server_ip_address_write.execute(hdr.rdma_eth_info.server_id);
    }

    @stage(6)
    table server_ip_write_tbl {
		key = {}
		actions = {server_ip_write_act;}
		size = 1;
		default_action = server_ip_write_act;
	}

	RegisterAction<ipv4_addr_t, _, ipv4_addr_t>(server_ip_address) server_ip_address_read = {
        void apply(inout ipv4_addr_t value, out ipv4_addr_t read_value) {
            read_value = value;
        }
    };

	action server_ip_read_act() {
        server_ip_addr = server_ip_address_read.execute(current_server_idx);
    }

    @stage(6)
    table server_ip_read_tbl {
		key = {}
		actions = {server_ip_read_act;}
		size = 1;
		default_action = server_ip_read_act;
	}

	RegisterAction<bit<16>, _, bit<16>>(server_mac_address_1) server_mac_address_1_write = {
		void apply(inout bit<16> value, out bit<16> read_value) {
			value = hdr.rdma_eth_info.mac_address1;
		}
	};

	RegisterAction<bit<32>, _, bit<32>>(server_mac_address_2) server_mac_address_2_write = {
		void apply(inout bit<32> value, out bit<32> read_value) {
			value = hdr.rdma_eth_info.mac_address2;
		}
	};

	action server_mac_address_1_write_act() {
		server_mac_address_1_write.execute(hdr.rdma_eth_info.server_id);
    }

	@stage(7)
    table server_mac_address_1_write_tbl {
		key = {}
		actions = {server_mac_address_1_write_act;}
		size = 1;
		default_action = server_mac_address_1_write_act;
	}

	action server_mac_address_2_write_act() {
		server_mac_address_2_write.execute(hdr.rdma_eth_info.server_id);
    }


    @stage(7)
    table server_mac_address_2_write_tbl {
		key = {}
		actions = {server_mac_address_2_write_act;}
		size = 1;
		default_action = server_mac_address_2_write_act;
	}
	

	RegisterAction<bit<16>, _, bit<16>>(server_mac_address_1) server_mac_address_1_read = {
		void apply(inout bit<16> value, out bit<16> read_value) {
			read_value = value;
		}
	};

	RegisterAction<bit<32>, _, bit<32>>(server_mac_address_2) server_mac_address_2_read = {
		void apply(inout bit<32> value, out bit<32> read_value) {
			read_value = value;
		}
	};

	action server_mac_address_1_read_act() {
		server_mac_addr_1 = server_mac_address_1_read.execute(current_server_idx);
    }

    @stage(7)
    table server_mac_address_1_read_tbl {
		key = {}
		actions = {server_mac_address_1_read_act;}
		size = 1;
		default_action = server_mac_address_1_read_act;
	}

	action server_mac_address_2_read_act() {
		server_mac_addr_2 = server_mac_address_2_read.execute(current_server_idx);
    }

    @stage(7)
    table server_mac_address_2_read_tbl {
		key = {}
		actions = {server_mac_address_2_read_act;}
		size = 1;
		default_action = server_mac_address_2_read_act;
	}
    
	/* part of RDMA stack info */
	RegisterAction<bit<32>, _, bit<32>>(remote_address_1) remote_address_1_write = {
		void apply(inout bit<32> value, out bit<32> read_value) {
			value = hdr.rdma_mem_info.remote_address1;
		}
	};

	action remote_addr1_write_act() {
        remote_address_1_write.execute(hdr.rdma_mem_info.server_id);
    }

    @stage(7)
    table remote_addr1_write_tbl {
		key = {}
		actions = {remote_addr1_write_act;}
		size = 1;
		default_action = remote_addr1_write_act;
	}

	RegisterAction<bit<32>, _, bit<32>>(remote_address_2) remote_address_2_write = {
		void apply(inout bit<32> value, out bit<32> read_value) {
			value = hdr.rdma_mem_info.remote_address2;
		}
	};

	action remote_addr2_write_act() {
        remote_address_2_write.execute(hdr.rdma_mem_info.server_id);
    }

    @stage(7)
    table remote_addr2_write_tbl {
		key = {}
		actions = {remote_addr2_write_act;}
		size = 1;
		default_action = remote_addr2_write_act;
	}

	RegisterAction<bit<32>, _, bit<32>>(remote_key) remote_key_write = {
		void apply(inout bit<32> value, out bit<32> read_value) {
			value = hdr.rdma_mem_info.remote_key;
		}
	};

	action remote_key_write_act() {
        remote_key_write.execute(hdr.rdma_mem_info.server_id);
    }

    @stage(6)
    table remote_key_write_tbl {
		key = {}
		actions = {remote_key_write_act;}
		size = 1;
		default_action = remote_key_write_act;
	}

	RegisterAction<bit<32>, _, bit<32>>(remote_key) remote_key_read = {
		void apply(inout bit<32> value, out bit<32> read_value) {
			read_value = value;
		}
	};

    action remote_key_read_act() {
        rdma_remote_key = remote_key_read.execute(current_server_idx);
    }

    @stage(6)
    table remote_key_read_tbl {
		key = {}
		actions = {remote_key_read_act;}
		size = 1;
		default_action = remote_key_read_act;
	}

	/* remove rdma header */
	action rdma_resp_decap() {
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

	/* upf actions */
	action ul_gtpu_decap() {
		// [tmp - removed to reduce compiling time]
		// hdr.ib_aeth.setInvalid();
		// hdr.lookup_resp_type.setInvalid();
        // hdr.ue_key.setInvalid();
        // hdr.ue_flow_key.setInvalid();
        // hdr.ue_flow_rule.setInvalid();
        // hdr.ue.setInvalid();

        // hdr.ipv4.setInvalid();
        // hdr.udp.setInvalid();
        hdr.gtpu.setInvalid();  // - only truncate gtpu, the other fields are removed in egress
		// [mark: first-step test]
        //hdr.gtpu_options.setInvalid();
        //hdr.gtpu_ext_psc.setInvalid();
    }

    /* server hash management */
    action set_server_id(bit<16> server_idx, bit<32> start_hash) {
    	// calculate the offset of the hash
    	current_server_idx = server_idx;
		server_hash_start_addr = start_hash;
    }

	Random<bit<32>>() random_qp_idx;
	//Random<bit<8>>() random_qp_idx2;

	/*----------- concurrency control -------------*/
	// todo
	/*----------- concurrency control end-------------*/

	// [test] - routing table
	PortId_t fwd_port;
    // [td]
	action fwd_0() {
        //fwd_port = 172;
		ig_tm_md.ucast_egress_port = 144;
    }
	action fwd_1() {
        //fwd_port = 188;
		ig_tm_md.ucast_egress_port = 152;
    }
	action fwd_2() {
        //fwd_port = 164;
		ig_tm_md.ucast_egress_port = 160;
    }
	action fwd_3() {
        //fwd_port = 180;
		ig_tm_md.ucast_egress_port = 168;
    }
	action fwd_4() {
        //fwd_port = 172;
		ig_tm_md.ucast_egress_port = 172;//164;
    }
	action fwd_5() {
        //fwd_port = 5;
		ig_tm_md.ucast_egress_port = 188;//180;
    }
	action fwd_6() {
        //fwd_port = 6;
		ig_tm_md.ucast_egress_port = 184;
    }
	action fwd_7() {
        //fwd_port = 7;
		ig_tm_md.ucast_egress_port = 188;
    }

	//bit<SERVER_SIZE_POWER> fwd_hash;
	table compute_fwd_port {
        key = {
            hdr.packet_pdr_key.inet_port: exact;
        }
        actions = {
            fwd_0;
            fwd_1;
            fwd_2;
			fwd_3;
			fwd_4;
			fwd_5;
			fwd_6;
			fwd_7;
        }
        size = 8; // to config
        const entries = {
			20000: fwd_0();
            20001: fwd_1();
            20002: fwd_2();
            20003: fwd_3();
			20004: fwd_4();
            20005: fwd_5();
			20006: fwd_6();
            20007: fwd_7();
        }
    }


    apply {

		if (hdr.rdma_info.isValid()) {
			
			/* RDMA stack is moved to egress */
			if (hdr.rdma_qp_info.isValid()) {
                //store_rdma_qp_info.apply(hdr);
				//enabled_qp_write.execute(hdr.rdma_qp_info.index);
				//qp_write.execute(hdr.rdma_qp_info.index);
            }
			else if (hdr.rdma_mem_info.isValid()) {
				remote_addr1_write_tbl.apply();
				remote_addr2_write_tbl.apply();
				remote_key_write_tbl.apply();
            }
			else if (hdr.rdma_eth_info.isValid())  {
                server_port_write_tbl.apply();
				server_mac_address_1_write_tbl.apply();
				server_mac_address_2_write_tbl.apply();
				server_ip_write_tbl.apply();
            }
			ig_tm_md.ucast_egress_port = SINGLE_SERVER_PORT; // transfer to egress
			
		}
		else if (hdr.ipv4.isValid() && hdr.gtpu.isValid() && !hdr.ib_bth.isValid()) {	

			bit<32> ue_flow_offset = hash_ue.get({
				hdr.ipv4.src_addr,
				hdr.ipv4.dst_addr,
				hdr.udp.src_port,
				hdr.udp.dst_port,
				IpProtocol.UDP
			});

			//bit<8> rand_idx2 = random_qp_idx2.get(); //used for selecting rule addr
			/* 0. check concurrency control */
			// c_slot_idx = c_hash.get({ // UDP packet only for now
			// 	hdr.ipv4.src_addr,
			// 	hdr.ipv4.dst_addr,
			// 	hdr.udp.src_port,
			// 	hdr.udp.dst_port,
			// 	IpProtocol.UDP				
			// });

			/* 1. see if hot entries hit */
			// only consider uplink traffic in our first-step test
			//if (!hot_entries_ul.apply().hit) {
				c_inflight_inc_tbl.apply();
				if (inflight_num == 0) c_filled_reset_tbl.apply();

				/* 2. access remote rdma storage */
				// get server information
				
				//ue flow table offset
				addr_hash_offset = ue_flow_offset & UE_FLOW_SIZE_MASK;
				// current_server_idx = 0;
				current_server_idx = (bit<16>) hash_server.get({
					hdr.ipv4.src_addr
				});
				current_qp_idx = (bit<16>) hash_qp.get({
					hdr.ipv4.src_addr,
					hdr.ipv4.dst_addr,
					hdr.udp.src_port,
					hdr.udp.dst_port,
					IpProtocol.UDP
				}); //(bit<16>) hash_to_qp.get({addr_hash_offset});//rand_idx;// + 2; 
				
				// hash_cal();
				//server_mac_addr_1 = 0xb859;
				//server_mac_addr_2 = 0x9ff080a9;
				server_mac_address_1_read_tbl.apply();
				server_mac_address_2_read_tbl.apply();
				//server_ip_addr = 0xc0a8191a;
				server_ip_read_tbl.apply();
				server_port_read_tbl.apply();
				remote_key_read_tbl.apply();

				if (rdma_remote_key == 0 || ig_intr_md.ingress_port < 100) {
					ig_dprsr_md.drop_ctl = 0x1;
				}
				else {
					fetch_rule.apply(hdr, meta, ig_prsr_md, ig_dprsr_md, ig_tm_md, server_mac_addr_1, server_mac_addr_2, 
										server_ip_addr, addr_hash_offset, current_server_idx, current_qp_idx,
										rdma_remote_key); 
					meta.mirror_session = (MirrorId_t) server_port_idx;
					// hdr.ib_bth.reserved = (bit<8>) current_qp_idx;
					//hdr.next_fetch_info.mem_offset = addr_hash_offset;
					// hdr.next_fetch_info.ints_fwd = ig_prsr_md.global_tstamp[17:2];
					ig_tm_md.ucast_egress_port = server_port_idx; //SINGLE_SERVER_PORT;//
				}
			//}
        }  
		else if (hdr.ib_bth.isValid() && hdr.ib_bth.opcode == ib_opcode_t.RDMA_READ_RESPONSE) {
			
			// latency test
			//hdr.next_fetch_info.ets_fwd = ig_prsr_md.global_tstamp[17:2];// [recover]

			server_mac_addr_1 = hdr.ethernet.src_addr[47:32];
			server_mac_addr_2 = hdr.ethernet.src_addr[31:0];
			server_ip_addr = hdr.ipv4.src_addr;
			server_port_idx = ig_intr_md.ingress_port;
			//bit<32> ue_offset = random_qp_idx.get();
			bit<32> ue_offset = hash_ue2.get({
				hdr.packet_pdr_key.ue_addr
			});
			addr_hash_offset = ue_offset & UE_SIZE_MASK;

			// [test] choose the forwarding port
			compute_fwd_port.apply(); // routing: sending each flow to a random port

			if (hdr.next_fetch_info.isValid()) {

			/*paging*/
			if(hdr.next_fetch_info.has_value != 0xff){
				ig_tm_md.ucast_egress_port = server_port_idx; // [paging todo: using a designated server for buffer?]
				paging_pop_loop.apply(hdr,meta,server_mac_addr_1,server_mac_addr_2,ig_dprsr_md,ig_prsr_md, ig_tm_md,server_ip_addr); 
			}
			else if(hdr.ue.idle > 0){
				ig_tm_md.ucast_egress_port = server_port_idx;	
				paging_push_ingress.apply(hdr,meta,ig_dprsr_md ,ig_tm_md ,server_mac_addr_1,server_mac_addr_2,server_ip_addr);
			}

			else if (hdr.lookup_resp_type.resp_type == LookupRespType.UE_FLOW) {
				// check if key matches [we skip it for the test]
				if (hdr.packet_ue_key.teid == 0) { //(hdr.ue_flow_key.ue_addr == 123) {
					//rdma_resp_decap();
					ul_gtpu_decap();
					// ig_tm_md.ucast_egress_port = fwd_port; // send to a random port in our test
					// writing back state data [td]
					// querying the ue table [td-delayed]
					read_ue_state.apply(hdr, meta, ig_dprsr_md, server_mac_addr_1, server_mac_addr_2, server_ip_addr);
					// bit<64> final_offset = 32w0x0 ++ addr_hash_offset;
					// hdr.next_fetch_info.addr = hdr.next_fetch_info.addr + final_offset;
					// meta.payload_addr = hdr.next_fetch_info.addr;
					// meta.mirror_session = (MirrorId_t) server_port_idx;

					/* remove the rdma header to avoid outstand window release
					   the slot is occupied by ue read */
					//hdr.ib_bth.setInvalid();

					// remove additional headers
					hdr.lookup_resp_type.setInvalid();
					hdr.ue_flow_key.setInvalid();
					hdr.ue_flow_rule.setInvalid();
					hdr.packet_ue_key.setInvalid();
					hdr.packet_pdr_key.setInvalid();
					//hdr.next_fetch_info.ints_fwd = (bit<32>) ig_prsr_md.global_tstamp - hdr.next_fetch_info.ints_fwd;
				}
				else {
					// query ue table
					//server_mac_addr_1 = 0xb859;
					//server_mac_addr_2 = 0x9ff080a9;//server_mac_address_2_read.execute(hdr.next_fetch_info.current_server_idx);
					//server_ip_addr = 0xc0a8191a;
					/**/
					keep_fetch_rule0.apply(hdr, meta, ig_prsr_md, ig_dprsr_md, server_mac_addr_1, server_mac_addr_2, server_ip_addr); //, addr_hash_offset);
					// bit<64> final_offset = 32w0x0 ++ addr_hash_offset;
					// hdr.next_fetch_info.addr = hdr.next_fetch_info.addr + final_offset;
					// meta.payload_addr = hdr.next_fetch_info.addr;
					// meta.mirror_session = (MirrorId_t) server_port_idx;
					/**/
					ig_tm_md.ucast_egress_port = server_port_idx;//SINGLE_SERVER_PORT;
				}
				bit<64> final_offset = 32w0x0 ++ addr_hash_offset;
				hdr.next_fetch_info.addr = hdr.next_fetch_info.addr + final_offset;
				meta.payload_addr = hdr.next_fetch_info.addr;
				meta.mirror_session = (MirrorId_t) server_port_idx;
				hdr.ib_bth.reserved = (bit<8>) hdr.next_fetch_info.current_server_idx;
			}
			else if (hdr.lookup_resp_type.resp_type == LookupRespType.UE) {
				// todo: UE rule processing logic 
				// check if key matches
				if (true) { //(hdr.ue_key.src_addr == hdr.packet_ue_key.src_addr) {
					// todo: ue action, e.g. count (not included in the first-step test)
					if (hdr.packet_ue_key.teid > 1) {//hdr.ue.pdr_exits) {
						// rdma_addr_hash = hash.get({
						// 	hdr.ipv4.src_addr//hdr.gtpu.teid//, [mark: first-step test todo: use a random value]
						// 	//hdr.gtpu_ext_psc.qfi,
						// 	//hdr.inner_ipv4.src_addr 
						// }) << ENTRY_SLOT_LEN_SHIFT;
						// addr_hash_offset = rdma_addr_hash & 0x003ff000; 
						// current_qp_idx = (bit<16>) hash_to_qp.get({addr_hash_offset});

						// start next round of retrieving pdr
						//server_mac_addr_1 = 0xb859;//server_mac_address_1_read.execute(hdr.next_fetch_info.current_server_idx);//meta.current_server_idx);//(hdr.next_fetch_info.current_server_idx);
						//server_mac_addr_2 = 0x9ff080a9;//server_mac_address_2_read.execute(hdr.next_fetch_info.current_server_idx);
						//server_ip_addr = 0xc0a8191a;
						//server_port_idx = server_port_read.execute(hdr.next_fetch_info.current_server_idx);
						// // construct read and write to fetch rules from remote storage
						//fetch_rule_pdr.apply(hdr, meta, ig_dprsr_md, ig_tm_md, server_mac_addr_1, server_mac_addr_2, server_ip_addr, hdr.next_fetch_info.current_server_idx, hdr.next_fetch_info.current_qp_idx);
						// fetch_rule.apply(hdr, meta, ig_dprsr_md, ig_tm_md, server_mac_addr_1, server_mac_addr_2, server_ip_addr, 0, 0, 0);
						keep_fetch_rule1.apply(hdr, meta, ig_prsr_md, ig_dprsr_md, server_mac_addr_1, server_mac_addr_2, server_ip_addr);//, 0);
						meta.payload_addr = hdr.next_fetch_info.addr;
						meta.mirror_session = (MirrorId_t) server_port_idx;
						ig_tm_md.ucast_egress_port = server_port_idx;//SINGLE_SERVER_PORT;
					}
					else {
						// for the first-step test we simply decap gtpu if lookup finishes
						//rdma_resp_decap();
						ul_gtpu_decap();
						//ig_tm_md.ucast_egress_port = fwd_port; // send to a random port in our test
						
						// remove additional headers
						hdr.lookup_resp_type.setInvalid();
						hdr.ue_key.setInvalid();
						hdr.ue.setInvalid();
						hdr.packet_ue_key.setInvalid();
						hdr.packet_pdr_key.setInvalid();
						//hdr.next_fetch_info.ints_fwd = (bit<32>) ig_prsr_md.global_tstamp - hdr.next_fetch_info.ints_fwd;

					}
					// [td] todo: add concurrency control
					// hdr.ue.counter = hdr.ue.counter + 1;
					// write back updated counter
					// todo: add a function for writing back - delayed, since write is not the bottleneck
				}
				hdr.ib_bth.reserved = (bit<8>) hdr.next_fetch_info.current_server_idx;
				// if (!ue_matched) {
				// 	hash_collision_sol.apply(hdr, ig_dprsr_md);
				// }
			}
			else if (hdr.lookup_resp_type.resp_type == LookupRespType.PDR) {
				// todo: PDR matching logic
				// no need to check for key as we already check for UE table
				bit<8> pdr_matched;
				pdr_match.apply(hdr, pdr_matched); //0: match failed, 1: match success, 2: max round exceeded
				if (pdr_matched == 0) {
					// start next round of retrieving pdr
					//server_mac_addr_1 = 0xb859;//server_mac_address_1_read.execute(hdr.next_fetch_info.current_server_idx);//meta.current_server_idx);//(hdr.next_fetch_info.current_server_idx);
					//server_mac_addr_2 = 0x9ff080a9;//server_mac_address_2_read.execute(hdr.next_fetch_info.current_server_idx);
					//server_ip_addr = 0xc0a8191a;
					//server_port_idx = server_port_read.execute(hdr.next_fetch_info.current_server_idx);
					// // construct read and write to fetch rules from remote storage
							
					keep_fetch_rule1.apply(hdr, meta, ig_prsr_md, ig_dprsr_md, server_mac_addr_1, server_mac_addr_2, server_ip_addr);//, 0);
					meta.payload_addr = hdr.next_fetch_info.addr;
					meta.mirror_session = (MirrorId_t) server_port_idx;
					ig_tm_md.ucast_egress_port = server_port_idx;//SINGLE_SERVER_PORT;
				} 
				else if (pdr_matched == 1) {
					// write back to ue flow table
					// write_back_ue_flow.apply(hdr, meta, ig_dprsr_md, server_mac_addr_1, server_mac_addr_2, server_ip_addr);
					// ul_gtpu_decap();
					// [this if logic is not used in the test]
				}
				else {
					// [td] add decap logic here
					// write back to ue flow table [for test - logic error here]
					write_back_ue_flow.apply(hdr, meta, ig_dprsr_md, server_mac_addr_1, server_mac_addr_2, server_ip_addr);
					meta.mirror_session = (MirrorId_t) server_port_idx;
					// default action logic - send to port 140 to check the throughput
					hdr.ib_bth.reserved = (bit<8>) hdr.next_fetch_info.current_server_idx;// = 0 hdr.ib_bth.dst_qp;// + (bit<8>) (hdr.next_fetch_info.current_server_idx << QP_POWER);//hdr.next_fetch_info.current_qp_idx;
					ul_gtpu_decap();
					//hdr.next_fetch_info.ets_fwd = (bit<32>) ig_prsr_md.global_tstamp;
					//ig_tm_md.ucast_egress_port = 164; // destination port

					// remove additional headers
					hdr.lookup_resp_type.setInvalid();
					hdr.ue_key.setInvalid();
					hdr.pdr0.setInvalid();
					hdr.pdr1.setInvalid();
					hdr.pdr2.setInvalid();
					hdr.pdr3.setInvalid();
					hdr.pdr4.setInvalid();
					hdr.packet_ue_key.setInvalid();
					hdr.packet_pdr_key.setInvalid();
					//hdr.next_fetch_info.ints_fwd = (bit<32>) ig_prsr_md.global_tstamp - hdr.next_fetch_info.ints_fwd;

				}
			}
			}
			else{
				ig_tm_md.ucast_egress_port = ig_intr_md.ingress_port;
			}
		}
		
    }
}


/* EGRESS */
control Egress(inout headers_t hdr, inout eg_metadata_t meta, in egress_intrinsic_metadata_t eg_intr_md,
               in egress_intrinsic_metadata_from_parser_t eg_prsr_md,
               inout egress_intrinsic_metadata_for_deparser_t eg_dprsr_md,
               inout egress_intrinsic_metadata_for_output_port_t eg_oport_md) {

		ConstructRead() construct_read;
		ConstructWrite() construct_write;
		/*paging*/
		Paging_Counter_Write() paging_counter;
   		Paging_Packet_Write() paging_packet;
		Paging_Pop_Loop_Egress() paging_pop_loop_egress;
    	Paging_Pop_Loop_Clear_Mirror() paging_pop_loop_clear_mirror;

		bit<24> qp_idx;
		//bit<24> server_idx;
		bit<32> outstand_exceed;
		bit<32> outstand_n_value;
		/*paging*/
		bit<64> buffer_offset;

        /* The egress logic contains the RDMA stack */

        /* RDMA stack information */
        RegisterAction<bit<32>, _, bit<32>>(outstand_n) outstand_n_write = {
			void apply(inout bit<32> value, out bit<32> read_value) {
				value = 0;
			}
		};

		action outstand_n_write_act() {
			outstand_n_write.execute(hdr.rdma_qp_info.index);;
		}

		@stage(4)
		table outstand_n_write_tbl {
			key = {}
			actions = {outstand_n_write_act;}
			size = 1;
			default_action = outstand_n_write_act;
		}

		// read outstand n value
		RegisterAction<bit<32>, _, bit<32>>(outstand_n) outstand_n_read = {
			void apply(inout bit<32> value, out bit<32> read_value) {
				/*paging*/
				if(hdr.ib_bth.opcode == ib_opcode_t.BUFFER_PACKET){
					read_value = 0;
					value = value - 1;
				} else{
					read_value = value;
				}
			}
		};

		action outstand_n_read_act() {
			outstand_n_value = outstand_n_read.execute(qp_idx);
		}

		@stage(4)
		table outstand_n_read_tbl {
			key = {}
			actions = {outstand_n_read_act;}
			size = 1;
			default_action = outstand_n_read_act;
		}


		RegisterAction<bit<32>, _, bit<32>>(outstand_n) outstand_n_inc = {
			void apply(inout bit<32> value, out bit<32> read_value) {
				if (meta.mirror_truncate.pdr_fetch_round_id > 1) read_value = 0;
				else if (value >= OUTSTAND_WINDOW_SIZE) {
					value = OUTSTAND_WINDOW_SIZE;
					read_value = 1;
				} else {
					value = value + 1;
					read_value = 0;
				}
			}
		};

		action outstand_n_inc_act() {
			outstand_exceed = outstand_n_inc.execute(qp_idx);
		}

		@stage(4)
		table outstand_n_inc_tbl {
			key = {}
			actions = {outstand_n_inc_act;}
			size = 1;
			default_action = outstand_n_inc_act;
		}

		RegisterAction<bit<32>, _, bit<32>>(outstand_n) outstand_n_dec = {
			void apply(inout bit<32> value, out bit<32> read_value) {
				if (value > 0) {
					value = value - 1;
				} 
			}   
		};

		action outstand_n_dec_act() {
			outstand_n_dec.execute(qp_idx);//(hdr.ib_bth.dst_qp);
		}

		@stage(4)
		table outstand_n_dec_tbl {
			key = {}
			actions = {outstand_n_dec_act;}
			size = 1;
			default_action = outstand_n_dec_act;
		}

		/* qp2 register is used for PSN */
		RegisterAction<bit<32>, _, bit<32>>(qp2) qp_write2 = {
			void apply(inout bit<32> value, out bit<32> read_value) {
				value = hdr.rdma_qp_info.dst_qp;
			}
		};

		action qp_write2_act() {
			qp_write2.execute(hdr.rdma_qp_info.index);
		}

		@stage(11)
		table qp_write2_tbl {
			key = {}
			actions = {qp_write2_act;}
			size = 1;
			default_action = qp_write2_act;
		}

	    RegisterAction<bit<32>, _, bit<24>>(seq_n) seq_n_inc = {
			void apply(inout bit<32> value, out bit<24> read_value) {
				read_value = value[23:0];
				if (value >= 0x00ffffff) {
					value = 0x0;
				} else {
					value = value + 1;
				}
			}
		};

		action seq_n_inc_act() {
			hdr.ib_bth.psn = seq_n_inc.execute(qp_idx);
		}

		@stage(11)
		table seq_n_inc_tbl {
			key = {}
			actions = {seq_n_inc_act;}
			size = 1;
			default_action = seq_n_inc_act;
		}

		@stage(11)
		table seq_n_inc_tbl2 {
			key = {}
			actions = {seq_n_inc_act;}
			size = 1;
			default_action = seq_n_inc_act;
		}

		@stage(11)
		table seq_n_inc_tbl4 {
			key = {}
			actions = {seq_n_inc_act;}
			size = 1;
			default_action = seq_n_inc_act;
		}

		/* seq_n is used for storing qp id */
		RegisterAction<bit<32>, _, bit<32>>(seq_n) seq_n_write = {
			void apply(inout bit<32> value, out bit<32> read_value) {
				value = 0;//hdr.rdma_qp_info.dst_qp;
			}
		};
		
		RegisterAction<bit<32>, _, bit<24>>(qp2) qp_read2 = {
			void apply(inout bit<32> value, out bit<24> read_value) {
				read_value = value[23:0];
			}
		};

		action qp_read2_act() {
			//qp_write2.execute(hdr.rdma_qp_info.index);
			hdr.ib_bth.dst_qp = qp_read2.execute(qp_idx);
		}

		@stage(11)
		table qp_read2_tbl {
			key = {}
			actions = {qp_read2_act;}
			size = 1;
			default_action = qp_read2_act;
		}

		@stage(11)
		table qp_read3_tbl {
			key = {}
			actions = {qp_read2_act;}
			size = 1;
			default_action = qp_read2_act;
		}

		apply {
			if (hdr.rdma_qp_info.isValid()) {
				seq_n_write.execute(hdr.rdma_qp_info.index);
				//qp_write2.execute(hdr.rdma_qp_info.index);
				qp_write2_tbl.apply();
				//outstand_n_write.execute(hdr.rdma_qp_info.index);
				outstand_n_write_tbl.apply();
				eg_dprsr_md.drop_ctl = 0x1;
			} else if (hdr.rdma_mem_info.isValid()) {
				// r2emote_address_1_write.execute(0);//hdr.rdma_mem_info.server_id);
				// r2emote_address_2_write.execute(0);//hdr.rdma_mem_info.server_id);
				// r2emote_key_write.execute(0);//hdr.rdma_mem_info.server_id);
                eg_dprsr_md.drop_ctl = 0x1;
			} else if (meta.mirror_truncate.isValid()) {
				qp_idx = (bit<24>) meta.mirror_truncate.server_qp_index;// + meta.mirror_truncate.server_index);
				qp_read3_tbl.apply();

				/*paging*/
				outstand_exceed = 0;
				if (meta.mirror_truncate.payload_len == IB_MIRROR_BUFFER_TYPE.BUFFER_COUNTER) {
					//Counter Write
					paging_counter.apply(hdr,meta);
				}
				else if(meta.mirror_truncate.payload_len == IB_MIRROR_BUFFER_TYPE.BUFFER_CLEAR) {
					paging_pop_loop_clear_mirror.apply(hdr ,meta);
				}
				else if (meta.mirror_truncate.pdr_fetch_round_id == 2) {
					construct_write.apply(hdr, meta);
					//server_idx = hdr.ib_bth.dst_qp;
					//hdr.ib_bth.dst_qp = qp_read2.execute(qp_idx);
					//qp_read4_tbl.apply();
					//hdr.ib_bth.psn = seq_n_inc.execute(qp_idx);
					seq_n_inc_tbl4.apply();
				}
				else {
					/* Cloned packet, convert it to RDMA read */
					// if (meta.mirror_truncate.pdr_fetch_round_id == 3) construct_read_ue_state.apply(hdr, meta); // read ue state
					// else 
					construct_read.apply(hdr, meta);
					//server_idx = hdr.ib_bth.dst_qp;				
					/* Outstand read control */
					//bit<32> exceed = outstand_n_inc.execute(qp_idx);
					//[debug] if (meta.mirror_truncate.pdr_fetch_round_id == 0) 
					outstand_n_inc_tbl.apply();
					if (outstand_exceed == 0) {
						//hdr.ib_bth.psn = seq_n_inc.execute(qp_idx);
						seq_n_inc_tbl.apply();
					}
					else {
						eg_dprsr_md.drop_ctl = 0x1;
					}
					hdr.icrc.setValid();
					// if (rkey == 0) { // the RDMA server has not yet started, drop the request
					// 	;//eg_dprsr_md.drop_ctl = 0x1;
					// }	
				}
			}
			else if (hdr.ib_bth.isValid()) {
				/*paging*/
				if (hdr.ib_bth.opcode == ib_opcode_t.RDMA_WRITE || hdr.ib_bth.opcode == ib_opcode_t.BUFFER_PACKET || hdr.ib_bth.opcode == ib_opcode_t.BUFFER_REPLAY) {
					qp_idx = hdr.ib_bth.psn + hdr.ib_bth.dst_qp;

					outstand_n_read_tbl.apply();
					if (outstand_n_value < OUTSTAND_WINDOW_SIZE || hdr.next_fetch_info.pdr_fetch_round_id > 0) {
					/*paging*/
					if(hdr.ib_bth.opcode == ib_opcode_t.BUFFER_PACKET) {
                        //idle
                        //paging_packet.apply(hdr,meta);
                        hdr.ipv4.total_len = hdr.ipv4.total_len + hdr.ib_reth.dma_len2;
                        hdr.udp.length = hdr.udp.length + hdr.ib_reth.dma_len2;
                    }
                    else if(hdr.ib_bth.opcode == ib_opcode_t.BUFFER_REPLAY) {
                        //paging_pop_loop_egress.apply(hdr);
                    }
					else if(hdr.ib_bth.opcode == ib_opcode_t.RDMA_WRITE) {
						if (hdr.next_fetch_info.pdr_fetch_round_id == 1) {
							hdr.ib_reth.addr = hdr.next_fetch_info.addr + UE_KEY_LEN + UE_RULE_LEN; //[root cause of the error]
							hdr.ib_reth.remote_key = hdr.next_fetch_info.rdma_remote_key;
							hdr.ib_reth.dma_len1 = 0;
							hdr.ib_reth.dma_len2 = hdr.udp.length - 28 - UE_FLOW_KEY_LEN - UE_FLOW_RULE_LEN - 3;//hdr.next_fetch_info.payload_len;  
							hdr.next_fetch_info.addr = hdr.next_fetch_info.addr + PDR_TABLE_OFFSET;
							hdr.next_fetch_info.mem_offset = hdr.next_fetch_info.mem_offset - PDR_TABLE_OFFSET; // keep the sum of the two addr equal to ue flow addr
						}
						else if (hdr.next_fetch_info.pdr_fetch_round_id == 0) { // ue_flow table
							// add offset
							hdr.ib_reth.addr = hdr.ib_reth.addr +  UE_FLOW_TABLE_OFFSET + UE_FLOW_KEY_LEN + UE_FLOW_RULE_LEN;
							//hdr.next_fetch_info.addr = hdr.next_fetch_info.addr; // ue addr start
						} 
						else {
							hdr.ib_reth.addr = hdr.next_fetch_info.addr + UE_KEY_LEN + UE_RULE_LEN; //[root cause of the error]
							hdr.ib_reth.remote_key = hdr.next_fetch_info.rdma_remote_key;
							hdr.ib_reth.dma_len1 = 0;
							hdr.ib_reth.dma_len2 = hdr.udp.length - 28 - UE_KEY_LEN - UE_RULE_LEN;//hdr.next_fetch_info.payload_len;  
							hdr.next_fetch_info.addr = hdr.next_fetch_info.addr + PDR_TABLE_OFFSET;
							hdr.next_fetch_info.mem_offset = hdr.next_fetch_info.mem_offset - PDR_TABLE_OFFSET; // keep the sum of the two addr equal to ue flow addr
						}
						hdr.ipv4.total_len = 60 + hdr.ib_reth.dma_len2;
						hdr.udp.length = 40 + hdr.ib_reth.dma_len2;
					}

					qp_read2_tbl.apply();
					//hdr.ib_bth.psn = seq_n_inc.execute(qp_idx);
					seq_n_inc_tbl2.apply();
					
					}
					else {
						eg_dprsr_md.drop_ctl = 0x1;
					}
				}
				else if (hdr.ib_bth.opcode == ib_opcode_t.RDMA_READ_RESPONSE) {
					// outstand_n_dec.execute(hdr.ib_bth.dst_qp);
					qp_idx = hdr.ib_bth.dst_qp;//(bit<24>) hdr.ib_bth.reserved + hdr.ib_bth.dst_qp;
					outstand_n_dec_tbl.apply();
					// if (hdr.ib_bth.reserved == 0){
					// 	eg_dprsr_md.drop_ctl = 0x1;
					// }
					//eg_dprsr_md.drop_ctl = 0x1;
				}
			}
		}
}


Pipeline(IngressParser(),
         Ingress(),
         IngressDeparser(),
         EgressParser(),
         Egress(),
         EgressDeparser()) pipe_ex;

Switch(pipe_ex) main;
