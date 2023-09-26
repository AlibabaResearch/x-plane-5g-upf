#ifndef _CONCURRENCY_CONTROL_
#define _CONCURRENCY_CONTROL_

control ConcurrencyControl(inout headers_t hdr , in bit<16> slot_idx, 
                           inout bit<32> sd_counter, inout bit<32> sd_meter_token, inout bit<32> sd_buffer_counter) {
    
    bit<8> filled;

    // check and inc filled flag
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

    //@stage(9)
    table c_filled_check_tbl {
		key = {}
		actions = {c_filled_check_act;}
		size = 1;
		default_action = c_filled_check_act;
	}

    /* state data operation */
    // 1. counter
    RegisterAction<bit<32>, _, bit<32>>(c_counter) c_counter_read = {
        void apply(inout bit<32> value, out bit<32> read_value) {
            read_value = value;
        }
    };
    RegisterAction<bit<32>, _, bit<32>>(c_counter) c_counter_write = {
        void apply(inout bit<32> value, out bit<32> read_value) {
            value = sd_counter; 
        }
    };
    action c_counter_read_act() {
        sd_counter = c_counter_read.execute(slot_idx);
    }
    action c_counter_write_act() {
        c_counter_write.execute(slot_idx);
    }
    @stage(6)
    table c_counter_read_tbl {
		key = {}
		actions = {c_counter_read_act;}
		size = 1;
		default_action = c_counter_read_act;
	}
    @stage(6)
    table c_counter_write_tbl {
		key = {}
		actions = {c_counter_write_act;}
		size = 1;
		default_action = c_counter_write_act;
	}

    // 2. meter_token 
    RegisterAction<bit<32>, _, bit<32>>(c_meter_token) c_meter_token_read = {
        void apply(inout bit<32> value, out bit<32> read_value) {
            read_value = value;
        }
    };
    RegisterAction<bit<32>, _, bit<32>>(c_meter_token) c_meter_token_write = {
        void apply(inout bit<32> value, out bit<32> read_value) {
            value = sd_meter_token; 
        }
    };
    action c_meter_token_read_act() {
        sd_meter_token = c_meter_token_read.execute(slot_idx);
    }
    action c_meter_token_write_act() {
        c_meter_token_write.execute(slot_idx);
    }
    @stage(6)
    table c_meter_token_read_tbl {
		key = {}
		actions = {c_meter_token_read_act;}
		size = 1;
		default_action = c_meter_token_read_act;
	}
    @stage(6)
    table c_meter_token_write_tbl {
		key = {}
		actions = {c_meter_token_write_act;}
		size = 1;
		default_action = c_meter_token_write_act;
	}


    // 3. buffer_counter
    RegisterAction<bit<32>, _, bit<32>>(c_buffer_counter) c_buffer_counter_read = {
        void apply(inout bit<32> value, out bit<32> read_value) {
            read_value = value;
        }
    };
    RegisterAction<bit<32>, _, bit<32>>(c_buffer_counter) c_buffer_counter_write = {
        void apply(inout bit<32> value, out bit<32> read_value) {
            value = sd_buffer_counter; 
        }
    };
    action c_buffer_counter_read_act() {
        sd_buffer_counter = c_buffer_counter_read.execute(slot_idx);
    }
    action c_buffer_counter_write_act() {
        c_buffer_counter_write.execute(slot_idx);
    }
    @stage(6)
    table c_buffer_counter_read_tbl {
		key = {}
		actions = {c_buffer_counter_read_act;}
		size = 1;
		default_action = c_buffer_counter_read_act;
	}
    @stage(6)
    table c_buffer_counter_write_tbl {
		key = {}
		actions = {c_buffer_counter_write_act;}
		size = 1;
		default_action = c_buffer_counter_write_act;
	}
    
    apply {

        c_filled_check_tbl.apply();
        if (filled == 0) {
            // store the fetched state data (write)
            c_counter_write_tbl.apply();
            c_meter_token_write_tbl.apply();
            c_buffer_counter_write_tbl.apply();
        }
        else {
            // return cached state data (read)
            c_counter_read_tbl.apply();
            c_meter_token_read_tbl.apply();
            c_buffer_counter_read_tbl.apply();
        }

    }
}


#endif 
