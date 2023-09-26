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

	FetchRule() fetch_rule;
	KeepFetchRule0() keep_fetch_rule0;
	KeepFetchRule1() keep_fetch_rule1;
	WriteFlowState() write_flow_state;
	HashCollisionSol() hash_collision_sol;
	PDRMatch() pdr_match;
	WriteFlowTable() write_flow_table;
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
	Hash<bit<QP_POWER>>(HashAlgorithm_t.CRC16) hash_qp;

	bit<16> lst_ue_id;
	bit<16> lst_flow_id;
	bit<16> lst_ue_key;
	bit<16> lst_flow_key;
	Hash<bit<16>>(HashAlgorithm_t.CRC16) hash_lst_ue;
	Hash<bit<16>>(HashAlgorithm_t.CRC16) hash_lst_flow;
	
	//RDMA stack info
	bit<32> rdma_remote_key;
	bit<32> addr_1; 
    bit<32> addr_2;

    /* store server information */
	RegisterAction<bit<16>, _, PortId_t>(server_port) server_port_op = {
		void apply(inout bit<16> value, out PortId_t read_value) {
			read_value = (PortId_t) value;
			if (hdr.rdma_eth_info.isValid()) value = (bit<16>) ig_intr_md.ingress_port;
		}
	};

	action server_port_act() {
		server_port_idx = server_port_op.execute(current_server_idx);
    }

	RegisterAction<ipv4_addr_t, _, ipv4_addr_t>(server_ip_address) server_ip_address_op = {
		void apply(inout ipv4_addr_t value, out ipv4_addr_t read_value) {
			read_value = value;
			if (hdr.rdma_eth_info.isValid()) value = hdr.rdma_eth_info.ip_address;
		}
	};

	action server_ip_act() {
        server_ip_addr = server_ip_address_op.execute(current_server_idx);
    }


	RegisterAction<bit<16>, _, bit<16>>(server_mac_address_1) server_mac_address_1_op = {
		void apply(inout bit<16> value, out bit<16> read_value) {
			read_value = value;
			if (hdr.rdma_eth_info.isValid()) value = hdr.rdma_eth_info.mac_address1;
		}
	};

	RegisterAction<bit<32>, _, bit<32>>(server_mac_address_2) server_mac_address_2_op = {
		void apply(inout bit<32> value, out bit<32> read_value) {
			read_value = value;
			if (hdr.rdma_eth_info.isValid()) value = hdr.rdma_eth_info.mac_address2;
		}
	};

	action server_mac1_act() {
		server_mac_addr_1 = server_mac_address_1_op.execute(current_server_idx);
    }

	action server_mac2_act() {
		server_mac_addr_2 = server_mac_address_2_op.execute(current_server_idx);
    }

	RegisterAction<bit<32>, _, bit<32>>(remote_key) remote_key_op = {
		void apply(inout bit<32> value, out bit<32> read_value) {
			read_value = value;
			if (hdr.rdma_mem_info.isValid()) value = hdr.rdma_mem_info.remote_key;
		}
	};

    action remote_key_act() {
        rdma_remote_key = remote_key_op.execute(current_server_idx);
    }

	RegisterAction<bit<32>, _, bit<32>>(remote_address_1) remote_address_1_op = {
		void apply(inout bit<32> value, out bit<32> read_value) {
			read_value = value;
			if (hdr.rdma_mem_info.isValid()) value = hdr.rdma_mem_info.remote_address1;
		}
	};

	action remote_addr1_act() {
        addr_1 = remote_address_1_op.execute(current_server_idx);
    }

	RegisterAction<bit<32>, _, bit<32>>(remote_address_2) remote_address_2_op = {
		void apply(inout bit<32> value, out bit<32> read_value) {
			read_value = value;
			if (hdr.rdma_mem_info.isValid()) value = hdr.rdma_mem_info.remote_address2;
		}
	};

	action remote_addr2_act() {
        addr_2 = remote_address_2_op.execute(current_server_idx);
    }

	table server_port_tbl {
		key = {}
		actions = {server_port_act;}
		size = 1;
		default_action = server_port_act;
	}

	table server_ip_tbl {
		key = {}
		actions = {server_ip_act;}
		size = 1;
		default_action = server_ip_act;
	}

	table server_mac1_tbl {
		key = {}
		actions = {server_mac1_act;}
		size = 1;
		default_action = server_mac1_act;
	}

	table server_mac2_tbl {
		key = {}
		actions = {server_mac2_act;}
		size = 1;
		default_action = server_mac2_act;
	}

	table remote_key_tbl {
		key = {}
		actions = {remote_key_act;}
		size = 1;
		default_action = remote_key_act;
	}

	table remote_addr1_tbl {
		key = {}
		actions = {remote_addr1_act;}
		size = 1;
		default_action = remote_addr1_act;
	}

	table remote_addr2_tbl {
		key = {}
		actions = {remote_addr2_act;}
		size = 1;
		default_action = remote_addr2_act;
	}

	bool idle_lst_flow;
	bool write_lst_flow;
	bool idle_lst_ue;
	bool write_lst_ue;
	RegisterAction<bit<32>, _, bool>(c_inflight_flow) lst_flow_inc_op = {
		void apply(inout bit<32> value, out bool read_value) {
			if (value == 0) read_value = true;
			else read_value = false;
			value = value + 1;
		}
	};

	RegisterAction<bit<32>, _, bool>(c_inflight_ue) lst_ue_inc_op = {
		void apply(inout bit<32> value, out bool read_value) {
			if (value == 0) read_value = true;
			else read_value = false;
			value = value + 1;
		}
	};

	RegisterAction<bit<32>, _, bool>(c_inflight_flow) lst_flow_dec_op = {
		void apply(inout bit<32> value, out bool read_value) {
			if (value == 1) {
				read_value = true;
				value = value - 1;
			} 
			else if (value > 0) {
				value = value - 1;
				read_value = false;
			}
		}
	};

	RegisterAction<bit<32>, _, bool>(c_inflight_ue) lst_ue_dec_op = {
		void apply(inout bit<32> value, out bool read_value) {
			if (value == 1) {
				read_value = true;
				value = value - 1;
			} 
			else if (value > 0) {
				value = value - 1;
				read_value = false;
			}
		}
	};

	action lst_flow_inc_act() {
		idle_lst_flow = lst_flow_inc_op.execute(lst_flow_key);
	}

	action lst_ue_inc_act() {
		idle_lst_ue = lst_ue_inc_op.execute(lst_ue_key);
	}

	action lst_flow_dec_act() {
		write_lst_flow = lst_flow_dec_op.execute(lst_flow_key);
	}

	action lst_ue_dec_act() {
		write_lst_ue = lst_ue_dec_op.execute(lst_ue_key);
	}
	
	@stage(3)
	table lst_flow_inc_tbl {
		key = {}
		actions = {lst_flow_inc_act;}
		size = 1;
		default_action = lst_flow_inc_act;
	}

	@stage(3)
	table lst_ue_inc_tbl {
		key = {}
		actions = {lst_ue_inc_act;}
		size = 1;
		default_action = lst_ue_inc_act;
	}

	@stage(3)
	table lst_flow_dec_tbl {
		key = {}
		actions = {lst_flow_dec_act;}
		size = 1;
		default_action = lst_flow_dec_act;
	}

	@stage(3)
	table lst_ue_dec_tbl {
		key = {}
		actions = {lst_ue_dec_act;}
		size = 1;
		default_action = lst_ue_dec_act;
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

	/* lst data operation */
	bit<32> counter_tmp;
	RegisterAction<bit<32>, _, bit<32>>(c_counter) c_counter_op = {
        void apply(inout bit<32> value, out bit<32> read_value) {
			if (value == 0) {
				value = hdr.ue_flow_rule.counter + 1;
			}
			else {
				value = value + 1;
			}
			read_value = value;
        }
    };

	RegisterAction<bit<32>, _, bit<32>>(c_counter) c_counter_set = {
		void apply(inout bit<32> value, out bit<32> read_value) {
			value = 0;
		}
	};

	action c_counter_set_act() {
		c_counter_set.execute(lst_flow_key);
	}

    action c_counter_act() {
        counter_tmp = c_counter_op.execute(lst_flow_key);
    }

	table c_counter_set_tbl{
        key = {}
        actions = {c_counter_set_act;}
        size = 1;
        default_action = c_counter_set_act;
    }

    table c_counter_tbl{
        key = {}
        actions = {c_counter_act;}
        size = 1;
        default_action = c_counter_act;
    }

	bool collided_flow;
	RegisterAction<bit<16>, _, bool>(c_lst_flow_key) c_lst_flow_key_check_op = {
		void apply(inout bit<16> value, out bool read_value) {
			if (!idle_lst_flow) {
				if (value == lst_flow_key) read_value = false;
				else read_value = true;
			}
			else {
				value = lst_flow_key;
				read_value = false;
			}
		}
	};

	action c_lst_flow_key_check_act() {
		collided_flow = c_lst_flow_key_check_op.execute(lst_flow_key);
	}

	/* upf actions */
	action ul_gtpu_decap() {
        hdr.gtpu.setInvalid();  // - only truncate gtpu, the other fields are removed in egress
    }

	// [test] - routing table
	PortId_t fwd_port;
	action fwd_0() {
		ig_tm_md.ucast_egress_port = 144;
    }
	action fwd_1() {
		ig_tm_md.ucast_egress_port = 152;
    }
	action fwd_2() {
		ig_tm_md.ucast_egress_port = 160;
    }
	action fwd_3() {
		ig_tm_md.ucast_egress_port = 168;
    }
	action fwd_4() {
		ig_tm_md.ucast_egress_port = 172;
    }
	action fwd_5() {
		ig_tm_md.ucast_egress_port = 188;
    }
	action fwd_6() {
		ig_tm_md.ucast_egress_port = 184;
    }
	action fwd_7() {
		ig_tm_md.ucast_egress_port = 188;
    }

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
        size = 8; 
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

		if (hdr.rdma_mem_info.isValid()) {
			current_server_idx = hdr.rdma_mem_info.server_id;
		}
		else if (hdr.rdma_eth_info.isValid()) {
			current_server_idx = hdr.rdma_eth_info.server_id;
		}
		else {
			current_server_idx = (bit<16>) hash_server.get({
				hdr.ipv4.src_addr
			});
		}
		current_qp_idx = (bit<16>) hash_qp.get({
			hdr.ipv4.src_addr,
			hdr.ipv4.dst_addr,
			hdr.udp.src_port,
			hdr.udp.dst_port,
			IpProtocol.UDP
		}); 
		lst_ue_key = hash_lst_ue.get({
				hdr.ipv4.src_addr
		});
		lst_flow_key = hash_lst_flow.get({
			hdr.ipv4.src_addr,
			hdr.ipv4.dst_addr,
			hdr.udp.src_port,
			hdr.udp.dst_port,
			IpProtocol.UDP
		}); 
		lst_ue_id = hash_lst_ue.get({
				hdr.ipv4.src_addr
		}) & CONCURRENCY_CONTROL_TABLE_MASK;
		lst_flow_id = hash_lst_flow.get({
			hdr.ipv4.src_addr,
			hdr.ipv4.dst_addr,
			hdr.udp.src_port,
			hdr.udp.dst_port,
			IpProtocol.UDP
		}) & CONCURRENCY_CONTROL_TABLE_MASK; 

		server_port_tbl.apply();
		server_ip_tbl.apply();
		server_mac1_tbl.apply();
		server_mac2_tbl.apply();
		remote_key_tbl.apply();
		remote_addr1_tbl.apply();
		remote_addr2_tbl.apply();

		// flow lst access
		if (hdr.ipv4.isValid() && hdr.gtpu.isValid() && !hdr.ib_bth.isValid()) {
			if (rdma_remote_key > 0 && ig_intr_md.ingress_port > 100) {
				lst_flow_inc_tbl.apply();
				c_lst_flow_key_check_act();
			}
		}
		else if (hdr.lookup_resp_type.isValid() && hdr.lookup_resp_type.resp_type == LookupRespType.UE_FLOW) {
			lst_flow_dec_tbl.apply();
		}
		// ue lst access
		if (hdr.lookup_resp_type.isValid() && hdr.lookup_resp_type.resp_type == LookupRespType.UE_FLOW) {
			lst_ue_inc_tbl.apply();
		}
		else if (hdr.lookup_resp_type.isValid() && hdr.lookup_resp_type.resp_type == LookupRespType.UE) {
			lst_ue_dec_tbl.apply();
		}

		if (hdr.rdma_qp_info.isValid()) {
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

			/* access remote rdma storage */				
			//flow table offset
			addr_hash_offset = ue_flow_offset & UE_FLOW_SIZE_MASK;
			if (rdma_remote_key == 0 || ig_intr_md.ingress_port < 100) {
				ig_dprsr_md.drop_ctl = 0x1;
			}
			else if (collided_flow) {
				ig_tm_md.ucast_egress_port = SOFT_UPF_PORT;
			}
			else {
				if (idle_lst_flow) c_counter_set_tbl.apply();

				fetch_rule.apply(hdr, meta, ig_prsr_md, ig_dprsr_md, ig_tm_md, server_mac_addr_1, server_mac_addr_2, 
									server_ip_addr, addr_hash_offset, current_server_idx, current_qp_idx,
									addr_1, addr_2, rdma_remote_key); 
				meta.mirror_session = (MirrorId_t) server_port_idx;
				// hdr.next_fetch_info.ints_fwd = ig_prsr_md.global_tstamp[17:2];
				ig_tm_md.ucast_egress_port = server_port_idx; //SINGLE_SERVER_PORT;//
			}

        }  
		else if (hdr.ib_bth.isValid() && hdr.ib_bth.opcode == ib_opcode_t.RDMA_READ_RESPONSE) {
			
			// latency test
			//hdr.next_fetch_info.ets_fwd = ig_prsr_md.global_tstamp[17:2];// [marker for latency test]
			server_mac_addr_1 = hdr.ethernet.src_addr[47:32];
			server_mac_addr_2 = hdr.ethernet.src_addr[31:0];
			server_ip_addr = hdr.ipv4.src_addr;
			server_port_idx = ig_intr_md.ingress_port;
			bit<32> ue_offset = hash_ue2.get({
				hdr.packet_pdr_key.ue_addr
			});
			addr_hash_offset = ue_offset & UE_SIZE_MASK;

			compute_fwd_port.apply(); // routing: sending each flow to a random port

			if (hdr.next_fetch_info.isValid()) {

			if (hdr.lookup_resp_type.resp_type == LookupRespType.UE_FLOW) {
				if (hdr.packet_ue_key.teid == 0) { // teid == 0 marks an entry match in test
					ul_gtpu_decap();
					c_counter_tbl.apply();
					if (write_lst_flow) write_flow_state.apply(hdr, meta, ig_dprsr_md, server_mac_addr_1, server_mac_addr_2, server_ip_addr);
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
					keep_fetch_rule0.apply(hdr, meta, ig_prsr_md, ig_dprsr_md, server_mac_addr_1, server_mac_addr_2, server_ip_addr); //, addr_hash_offset);
					ig_tm_md.ucast_egress_port = server_port_idx;//SINGLE_SERVER_PORT;
				}
				bit<64> final_offset = 32w0x0 ++ addr_hash_offset;
				hdr.next_fetch_info.addr = hdr.next_fetch_info.addr + final_offset;
				meta.payload_addr = hdr.next_fetch_info.addr;
				meta.mirror_session = (MirrorId_t) server_port_idx;
				hdr.ib_bth.reserved = (bit<8>) hdr.next_fetch_info.current_server_idx;
			}
			else if (hdr.lookup_resp_type.resp_type == LookupRespType.UE) {
				if (true) { 
					if (hdr.packet_ue_key.teid > 1) {
						keep_fetch_rule1.apply(hdr, meta, ig_prsr_md, ig_dprsr_md, server_mac_addr_1, server_mac_addr_2, server_ip_addr);//, 0);
						meta.payload_addr = hdr.next_fetch_info.addr;
						meta.mirror_session = (MirrorId_t) server_port_idx;
						ig_tm_md.ucast_egress_port = server_port_idx;//SINGLE_SERVER_PORT;
					}
					else {
						ul_gtpu_decap();
						// remove additional headers
						hdr.lookup_resp_type.setInvalid();
						hdr.ue_key.setInvalid();
						hdr.ue.setInvalid();
						hdr.packet_ue_key.setInvalid();
						hdr.packet_pdr_key.setInvalid();
					}
				}
				hdr.ib_bth.reserved = (bit<8>) hdr.next_fetch_info.current_server_idx;
			}
			else if (hdr.lookup_resp_type.resp_type == LookupRespType.PDR) {
				bit<8> pdr_matched;
				pdr_match.apply(hdr, pdr_matched); //0: match failed, 1: match success, 2: max round exceeded
				if (pdr_matched == 0) {
					keep_fetch_rule1.apply(hdr, meta, ig_prsr_md, ig_dprsr_md, server_mac_addr_1, server_mac_addr_2, server_ip_addr);//, 0);
					meta.payload_addr = hdr.next_fetch_info.addr;
					meta.mirror_session = (MirrorId_t) server_port_idx;
					ig_tm_md.ucast_egress_port = server_port_idx;//SINGLE_SERVER_PORT;
				} 
				else if (pdr_matched == 1) {
					// [this if logic is not used in the test]
				}
				else {
					write_flow_table.apply(hdr, meta, ig_dprsr_md, server_mac_addr_1, server_mac_addr_2, server_ip_addr);
					meta.mirror_session = (MirrorId_t) server_port_idx;
					hdr.ib_bth.reserved = (bit<8>) hdr.next_fetch_info.current_server_idx;
					ul_gtpu_decap();

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
			/*paging*/
			else if(hdr.next_fetch_info.has_value != 0xff){
				ig_tm_md.ucast_egress_port = server_port_idx; 
				paging_pop_loop.apply(hdr,meta,server_mac_addr_1,server_mac_addr_2,ig_dprsr_md,ig_prsr_md, ig_tm_md,server_ip_addr, write_lst_ue); 
			}
			else if(hdr.ue.idle > 0){
				ig_tm_md.ucast_egress_port = server_port_idx;	
				paging_push_ingress.apply(hdr,meta,ig_dprsr_md ,ig_tm_md ,server_mac_addr_1,server_mac_addr_2,server_ip_addr, write_lst_ue);
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
		bit<32> outstand_exceed;
		bit<32> outstand_n_value;
		/*paging*/
		bit<64> buffer_offset;
		/*registr op flag*/
		bit<1> inc_seq;

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
			outstand_n_dec.execute(qp_idx);
		}

		@stage(4)
		table outstand_n_dec_tbl {
			key = {}
			actions = {outstand_n_dec_act;}
			size = 1;
			default_action = outstand_n_dec_act;
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

		/* seq_n is used for storing qp id */
		RegisterAction<bit<32>, _, bit<32>>(seq_n) seq_n_write = {
			void apply(inout bit<32> value, out bit<32> read_value) {
				value = 0;
			}
		};


		RegisterAction<bit<32>, _, bit<24>>(qp2) qp_op = {
			void apply(inout bit<32> value, out bit<24> read_value) {
				read_value = value[23:0];
				if (hdr.rdma_qp_info.isValid()) value = hdr.rdma_qp_info.dst_qp;
			}
		};

		action qp_act() {
			hdr.ib_bth.dst_qp = qp_op.execute(qp_idx);
		}

		table qp_tbl {
			key = {}
			actions = {qp_act;}
			size = 1;
			default_action = qp_act;
		}

		apply {
			if (hdr.rdma_qp_info.isValid()) qp_idx = (bit<24>) hdr.rdma_qp_info.index;
			else if (meta.mirror_truncate.isValid()) qp_idx = (bit<24>) meta.mirror_truncate.server_qp_index;
			else if (hdr.ib_bth.isValid()) {
				if (hdr.ib_bth.opcode == ib_opcode_t.RDMA_WRITE || hdr.ib_bth.opcode == ib_opcode_t.BUFFER_PACKET || hdr.ib_bth.opcode == ib_opcode_t.BUFFER_REPLAY) {
					qp_idx = hdr.ib_bth.psn + hdr.ib_bth.dst_qp;
				}
				else if (hdr.ib_bth.opcode == ib_opcode_t.RDMA_READ_RESPONSE) {
					qp_idx = hdr.ib_bth.dst_qp;
				}
			}
			qp_tbl.apply();

			if (hdr.rdma_qp_info.isValid()) {
				eg_dprsr_md.drop_ctl = 0x1;
			} else if (meta.mirror_truncate.isValid()) {
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
					// --- seq_n_inc_tbl4.apply();
					inc_seq = 1;
				}
				else {
					/* Cloned packet, convert it to RDMA read */
					construct_read.apply(hdr, meta);		
					/* Outstand read control */
					outstand_n_inc_tbl.apply();
					if (outstand_exceed == 0) {
						inc_seq = 1;
					}
					else {
						eg_dprsr_md.drop_ctl = 0x1;
					}
					hdr.icrc.setValid();
				}
			}
			else if (hdr.ib_bth.isValid()) {
				/*paging*/
				if (hdr.ib_bth.opcode == ib_opcode_t.RDMA_WRITE || hdr.ib_bth.opcode == ib_opcode_t.BUFFER_PACKET || hdr.ib_bth.opcode == ib_opcode_t.BUFFER_REPLAY) {
					outstand_n_read_tbl.apply();
					if (outstand_n_value < OUTSTAND_WINDOW_SIZE || hdr.next_fetch_info.pdr_fetch_round_id > 0) {
					/*paging*/
					if(hdr.ib_bth.opcode == ib_opcode_t.BUFFER_PACKET) {
                        //idle
                        paging_packet.apply(hdr,meta);
                        hdr.ipv4.total_len = hdr.ipv4.total_len + hdr.ib_reth.dma_len2;
                        hdr.udp.length = hdr.udp.length + hdr.ib_reth.dma_len2;
                    }
                    else if(hdr.ib_bth.opcode == ib_opcode_t.BUFFER_REPLAY) {
                        paging_pop_loop_egress.apply(hdr);
                    }
					else if(hdr.ib_bth.opcode == ib_opcode_t.RDMA_WRITE) {
						if (hdr.next_fetch_info.pdr_fetch_round_id == 1) {
							hdr.ib_reth.addr = hdr.next_fetch_info.addr + UE_KEY_LEN + UE_RULE_LEN; 
							hdr.ib_reth.remote_key = hdr.next_fetch_info.rdma_remote_key;
							hdr.ib_reth.dma_len1 = 0;
							hdr.ib_reth.dma_len2 = hdr.udp.length - 28 - UE_FLOW_KEY_LEN - UE_FLOW_RULE_LEN - 3;
							hdr.next_fetch_info.addr = hdr.next_fetch_info.addr + PDR_TABLE_OFFSET;
							hdr.next_fetch_info.mem_offset = hdr.next_fetch_info.mem_offset - PDR_TABLE_OFFSET; 
						}
						else if (hdr.next_fetch_info.pdr_fetch_round_id == 0) { 
							// add offset
							hdr.ib_reth.addr = hdr.ib_reth.addr +  UE_FLOW_TABLE_OFFSET + UE_FLOW_KEY_LEN + UE_FLOW_RULE_LEN;
						} 
						else {
							hdr.ib_reth.addr = hdr.next_fetch_info.addr + UE_KEY_LEN + UE_RULE_LEN; 
							hdr.ib_reth.remote_key = hdr.next_fetch_info.rdma_remote_key;
							hdr.ib_reth.dma_len1 = 0;
							hdr.ib_reth.dma_len2 = hdr.udp.length - 28 - UE_KEY_LEN - UE_RULE_LEN;
							hdr.next_fetch_info.addr = hdr.next_fetch_info.addr + PDR_TABLE_OFFSET;
							hdr.next_fetch_info.mem_offset = hdr.next_fetch_info.mem_offset - PDR_TABLE_OFFSET; // keep the sum of the two addr equal to ue flow addr
						}
						hdr.ipv4.total_len = 60 + hdr.ib_reth.dma_len2;
						hdr.udp.length = 40 + hdr.ib_reth.dma_len2;
					}
					inc_seq = 1;
					}
					else {
						eg_dprsr_md.drop_ctl = 0x1;
					}
				}
				else if (hdr.ib_bth.opcode == ib_opcode_t.RDMA_READ_RESPONSE) {
					outstand_n_dec_tbl.apply();
				}
			}
			if (inc_seq==1) seq_n_inc_act();
		}
}


Pipeline(IngressParser(),
         Ingress(),
         IngressDeparser(),
         EgressParser(),
         Egress(),
         EgressDeparser()) pipe_ex;

Switch(pipe_ex) main;
