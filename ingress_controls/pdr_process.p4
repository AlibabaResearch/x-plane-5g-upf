#ifndef _PDR_MATCH_
#define _PDR_MATCH_

#include "../include/configuration.p4"
//#include "../ingress_controls/fetch_rule.p4"

control PDRMatch(inout headers_t hdr, inout bit<8> pdr_match_code) {
    Hash<bit<CONCURRENCY_CONTROL_TABLE_SIZE_POWER>>(HashAlgorithm_t.CRC16) c_hash; 
    bit<CONCURRENCY_CONTROL_TABLE_SIZE_POWER> slot_idx = c_hash.get({ // UDP packet only for now
				hdr.ipv4.src_addr,
				hdr.ipv4.dst_addr,
				hdr.udp.src_port,
				hdr.udp.dst_port,
				IpProtocol.UDP				
	});
    /* Step1: define the state data that require concurrency control here */
    bit<32> fetched_counter;
	bit<32> fetched_meter_token;
	bit<32> fetched_buffer_counter;

    /* Step2: define the state data operations here */
    /* each operation requires two cases: using fecthed data or using stored data */
    /* Note that the operation has to be wrapped in RegisterAction */
    // 1. counter
    RegisterAction<bit<32>, _, bit<32>>(c_counter) c_counter_fetched_op = {
        void apply(inout bit<32> value, out bit<32> read_value) {
            value = fetched_counter + 1; 
        }
    };
    RegisterAction<bit<32>, _, bit<32>>(c_counter) c_counter_stored_op = {
        void apply(inout bit<32> value, out bit<32> read_value) {
            value = value + 1; 
        }
    };
    action c_counter_fetched_op_act() {
        c_counter_fetched_op.execute(slot_idx);
    }
    action c_counter_stored_op_act() {
        c_counter_stored_op.execute(slot_idx);
    }
    @stage(9)
    table c_counter_fetched_op_tbl {
		key = {}
		actions = {c_counter_fetched_op_act;}
		size = 1;
		default_action = c_counter_fetched_op_act;
	}
    @stage(9)
    table c_counter_stored_op_tbl {
		key = {}
		actions = {c_counter_stored_op_act;}
		size = 1;
		default_action = c_counter_stored_op_act;
	}

    // 2. meter_token 
    RegisterAction<bit<32>, _, bit<32>>(c_meter_token) c_meter_token_fetched_op = {
        void apply(inout bit<32> value, out bit<32> read_value) {
            value = fetched_meter_token + 1; //todo
        }
    };
    RegisterAction<bit<32>, _, bit<32>>(c_meter_token) c_meter_token_stored_op = {
        void apply(inout bit<32> value, out bit<32> read_value) {
            value = value + 1; 
        }
    };
    action c_meter_token_fetched_op_act() {
        c_meter_token_fetched_op.execute(slot_idx);
    }
    action c_meter_token_stored_op_act() {
        c_meter_token_stored_op.execute(slot_idx);
    }
    @stage(9)
    table c_meter_token_fetched_op_tbl {
		key = {}
		actions = {c_meter_token_fetched_op_act;}
		size = 1;
		default_action = c_meter_token_fetched_op_act;
	}
    @stage(9)
    table c_meter_token_stored_op_tbl {
		key = {}
		actions = {c_meter_token_stored_op_act;}
		size = 1;
		default_action = c_meter_token_stored_op_act;
	}

    // 3. buffer_counter
    RegisterAction<bit<32>, _, bit<32>>(c_buffer_counter) c_buffer_counter_fetched_op = {
        void apply(inout bit<32> value, out bit<32> read_value) {
            value = fetched_buffer_counter + 1; //todo
        }
    };
    RegisterAction<bit<32>, _, bit<32>>(c_buffer_counter) c_buffer_counter_stored_op = {
        void apply(inout bit<32> value, out bit<32> read_value) {
            value = value + 1; 
        }
    };
    action c_buffer_counter_fetched_op_act() {
        c_buffer_counter_fetched_op.execute(slot_idx);
    }
    action c_buffer_counter_stored_op_act() {
        c_buffer_counter_stored_op.execute(slot_idx);
    }
    @stage(9)
    table c_buffer_counter_fetched_op_tbl {
		key = {}
		actions = {c_buffer_counter_fetched_op_act;}
		size = 1;
		default_action = c_buffer_counter_fetched_op_act;
	}
    @stage(9)
    table c_buffer_counter_stored_op_tbl {
		key = {}
		actions = {c_buffer_counter_stored_op_act;}
		size = 1;
		default_action = c_buffer_counter_stored_op_act;
	}
    /***** state data operation end *****/

    /* check and inc filled flag */
    bit<8> filled;
    RegisterAction<bit<8>, _, bit<8>>(c_filled) c_filled_check = {
        void apply(inout bit<8> value, out bit<8> read_value) {
            read_value = value;
            if (value == 0) {
                value = 1;
            }
        }
    };
    action c_filled_check_act() {
        filled = c_filled_check.execute(slot_idx);
    }
    @stage(5)
    table c_filled_check_tbl {
		key = {}
		actions = {c_filled_check_act;}
		size = 1;
		default_action = c_filled_check_act;
	}

    /* dec inflight counter */
    bit<16> inflight_num;
    RegisterAction<bit<16>, _, bit<16>>(c_inflight_counter) c_inflight_dec = {
        void apply(inout bit<16> value, out bit<16> read_value) {
            if (value > 0) {
                value = value - 1;
            }
            read_value = value;
        }
    };
    action c_inflight_dec_act() {
        inflight_num = c_inflight_dec.execute(slot_idx);
    }
    @stage(3)
    table c_inflight_dec_tbl {
		key = {}
		actions = {c_inflight_dec_act;}
		size = 1;
		default_action = c_inflight_dec_act;
	}

    /* release the occupied flag */
    RegisterAction<bit<8>, _, bit<8>>(c_occupied) c_occupied_reset = {
        void apply(inout bit<8> value, out bit<8> read_value) {
            value = 0;
        }
    };
    action c_occupied_reset_act() {
        c_occupied_reset.execute(slot_idx);
    }
	// todo @stage
    table c_occupied_reset_tbl {
		key = {}
		actions = {c_occupied_reset_act;}
		size = 1;
		default_action = c_occupied_reset_act;
	}

    apply { 
        // pdr0 
        // todo: redefine the ignored field value
        bool pdr_matched = false; 
        if (hdr.pdr0.qfi == 0 || hdr.pdr0.qfi == hdr.packet_pdr_key.qfi) {
            if (hdr.pdr0.ue_port == 0 || hdr.pdr0.ue_port == hdr.packet_pdr_key.ue_port) {
                if (hdr.pdr0.inet_port == 0 || hdr.pdr0.inet_port == hdr.packet_pdr_key.inet_port) {
                    if (hdr.pdr0.ue_addr == 0 || hdr.pdr0.ue_addr == hdr.packet_pdr_key.ue_addr) {
                        if (hdr.pdr0.inet_addr == 0 || hdr.pdr0.inet_addr == hdr.packet_pdr_key.inet_addr) {
                            pdr_matched = true;
                            // execute pdr actions
                            // far
                            if (hdr.pdr0.needs_dropping) {
                                ;
                            }
                            else {
                                ;// fwd the packet
                            }
                            // bar
                            if (hdr.pdr0.needs_buffering) {

                            }
                            // urr
                            fetched_buffer_counter = 0;
                            fetched_counter = 0;
                            fetched_meter_token = 0;

                        }
                    }
                }
            }
        }
        // pdr1
        if (!pdr_matched) {
            if (hdr.pdr1.qfi == 0 || hdr.pdr1.qfi == hdr.packet_pdr_key.qfi) {
                if (hdr.pdr1.ue_port == 0 || hdr.pdr1.ue_port == hdr.packet_pdr_key.ue_port) {
                    if (hdr.pdr1.inet_port == 0 || hdr.pdr1.inet_port == hdr.packet_pdr_key.inet_port) {
                        if (hdr.pdr1.ue_addr == 0 || hdr.pdr1.ue_addr == hdr.packet_pdr_key.ue_addr) {
                            if (hdr.pdr1.inet_addr == 0 || hdr.pdr1.inet_addr == hdr.packet_pdr_key.inet_addr) {
                                pdr_matched = true;
                                fetched_buffer_counter = 0;
                                fetched_counter = 0;
                                fetched_meter_token = 0;
                            }
                        }
                    }
                }
            }
        }
        // pdr2
        if (!pdr_matched) {
            if (hdr.pdr2.qfi == 0 || hdr.pdr2.qfi == hdr.packet_pdr_key.qfi) {
                if (hdr.pdr2.ue_port == 0 || hdr.pdr2.ue_port == hdr.packet_pdr_key.ue_port) {
                    if (hdr.pdr2.inet_port == 0 || hdr.pdr2.inet_port == hdr.packet_pdr_key.inet_port) {
                        if (hdr.pdr2.ue_addr == 0 || hdr.pdr2.ue_addr == hdr.packet_pdr_key.ue_addr) {
                            if (hdr.pdr2.inet_addr == 0 || hdr.pdr2.inet_addr == hdr.packet_pdr_key.inet_addr) {
                                pdr_matched = true;
                                fetched_buffer_counter = 0;
                                fetched_counter = 0;
                                fetched_meter_token = 0;
                            }
                        }
                    }
                }
            }
        }
        // pdr3
        if (!pdr_matched) {
            if (hdr.pdr3.qfi == 0 || hdr.pdr3.qfi == hdr.packet_pdr_key.qfi) {
                if (hdr.pdr3.ue_port == 0 || hdr.pdr3.ue_port == hdr.packet_pdr_key.ue_port) {
                    if (hdr.pdr3.inet_port == 0 || hdr.pdr3.inet_port == hdr.packet_pdr_key.inet_port) {
                        if (hdr.pdr3.ue_addr == 0 || hdr.pdr3.ue_addr == hdr.packet_pdr_key.ue_addr) {
                            if (hdr.pdr3.inet_addr == 0 || hdr.pdr3.inet_addr == hdr.packet_pdr_key.inet_addr) {
                                pdr_matched = true;
                                fetched_buffer_counter = 0;
                                fetched_counter = 0;
                                fetched_meter_token = 0;
                            }
                        }
                    }
                }
            }
        }
        // pdr4
        if (!pdr_matched) {
            if (hdr.pdr4.qfi == 0 || hdr.pdr4.qfi == hdr.packet_pdr_key.qfi) {
                if (hdr.pdr4.ue_port == 0 || hdr.pdr4.ue_port == hdr.packet_pdr_key.ue_port) {
                    if (hdr.pdr4.inet_port == 0 || hdr.pdr4.inet_port == hdr.packet_pdr_key.inet_port) {
                        if (hdr.pdr4.ue_addr == 0 || hdr.pdr4.ue_addr == hdr.packet_pdr_key.ue_addr) {
                            if (hdr.pdr4.inet_addr == 0 || hdr.pdr4.inet_addr == hdr.packet_pdr_key.inet_addr) {
                                pdr_matched = true;
                                fetched_buffer_counter = 0;
                                fetched_counter = 0;
                                fetched_meter_token = 0;
                            }
                        }
                    }
                }
            }
        }
        // end (5 pdrs each round for the first-step test)

        /* operate on state data */
        c_inflight_dec_tbl.apply();
        c_filled_check_tbl.apply();
        /* Step3: call the defined actions here */
        if (filled == 0) {
            c_counter_fetched_op_tbl.apply();
            c_meter_token_fetched_op_tbl.apply();
            c_buffer_counter_fetched_op_tbl.apply();
            // write back to header
        }
        else {
            c_counter_stored_op_tbl.apply();
            c_meter_token_stored_op_tbl.apply();
            c_buffer_counter_stored_op_tbl.apply();
            // write back to header
        }

        // if (inflight_num == 0) {
        //     write_back_to_hdr();
        // }
        
        /* [only for the first step test] force each packet to go through MAX_NUM_FETCH of iterations*/
        if (hdr.next_fetch_info.pdr_fetch_round_id == hdr.packet_ue_key.teid) {
            pdr_match_code = 2;
        }
        else {
            pdr_match_code = 0;
        }

        // write to ue flow table


        /* 
        bool pdr_used_up = false;
        if (!pdr_matched) {
            if (hdr.pdr4.qfi == 0) if (hdr.pdr4.ue_port == 0) if (hdr.pdr4.inet_port == 0) if (hdr.pdr4.ue_addr == 0) if (hdr.pdr4.inet_addr == 0) pdr_used_up = true;
        }
        if (pdr_matched) pdr_match_code = 1;
        else if (hdr.next_fetch_info.pdr_fetch_round_id == MAX_NUM_FETCH || pdr_used_up) pdr_match_code = 2;
        else pdr_match_code = 0;
        */
        
    }
}

#endif 
