// ============================================================================
//  testbench.sv  --  UVM environment for the AES-128 encryptor (LEFT pane)
// ----------------------------------------------------------------------------
//  Architecture: interface + transaction + sequences + driver + monitor +
//                agent + scoreboard (with bit-exact AES-128 reference model) +
//                functional coverage + env + test.
//
//  Everything lives in this one file at compilation-unit scope so it pastes
//  straight into the EDA Playground "testbench" pane. No external files / no
//  $readmemh are required: stimulus is constrained-random + directed corners,
//  and the golden result is computed in-line by the reference model.
//
//  How to run on EDA Playground (exact steps are in the chat reply).
// ============================================================================

`timescale 1ns / 1ps
`include "uvm_macros.svh"
import uvm_pkg::*;

// ----------------------------------------------------------------------------
//  DUT interface
// ----------------------------------------------------------------------------
interface aes_if(input logic clk);
  logic         nreset;
  logic         data_v_i;
  logic [127:0] data_i;
  logic [127:0] key_i;
  logic         res_v_o;
  logic [127:0] res_o;

  // Drive stimulus on the clock edge, sample DUT outputs on the clock edge.
  clocking drv_cb @(posedge clk);
    default input #1step output #1;
    output nreset, data_v_i, data_i, key_i;
    input  res_v_o, res_o;
  endclocking

  clocking mon_cb @(posedge clk);
    default input #1step;
    input nreset, data_v_i, data_i, key_i, res_v_o, res_o;
  endclocking
endinterface

// ----------------------------------------------------------------------------
//  Transaction
// ----------------------------------------------------------------------------
// Pattern selectors are used to bias constrained-random generation and to close
// transaction-level functional coverage. The scoreboard always checks the
// actual data/key/result values, not the pattern selector.
typedef enum int unsigned {
  AES_PATTERN_RANDOM,
  AES_PATTERN_ALL_ZERO,
  AES_PATTERN_ALL_ONE,
  AES_PATTERN_SAME_BYTE,
  AES_PATTERN_ALT_A5,
  AES_PATTERN_ALT_5A,
  AES_PATTERN_BYTE_RAMP,
  AES_PATTERN_WALKING_ONE,
  AES_PATTERN_WALKING_ZERO
} aes_pattern_e;

class aes_item extends uvm_sequence_item;
  rand bit [127:0] data;        // plaintext driven to DUT
  rand bit [127:0] key;         // AES-128 cipher key driven to DUT
       bit [127:0] result;      // ciphertext captured from DUT by monitor
       int unsigned latency;    // cycles from input valid to output valid

  rand aes_pattern_e data_pattern;
  rand aes_pattern_e key_pattern;
  rand int unsigned  data_bit_pos;
  rand int unsigned  key_bit_pos;
  rand bit [7:0]     data_same_byte;
  rand bit [7:0]     key_same_byte;

  constraint c_bit_pos {
    data_bit_pos inside {[0:127]};
    key_bit_pos  inside {[0:127]};
  }

  // Prevent SAME_BYTE from collapsing into other vector classes.
  constraint c_same_byte_values {
    !(data_same_byte inside {8'h00, 8'hff, 8'ha5, 8'h5a});
    !(key_same_byte  inside {8'h00, 8'hff, 8'ha5, 8'h5a});
  }

  // Constrained-random distribution:
  // - RANDOM gives broad AES state/key-space exploration.
  // - Directed-like weighted patterns make the coverage bins reachable during
  //   short EDA Playground runs.
  constraint c_pattern_dist {
    data_pattern dist {
      AES_PATTERN_RANDOM       := 60,
      AES_PATTERN_ALL_ZERO     := 4,
      AES_PATTERN_ALL_ONE      := 4,
      AES_PATTERN_SAME_BYTE    := 6,
      AES_PATTERN_ALT_A5       := 4,
      AES_PATTERN_ALT_5A       := 4,
      AES_PATTERN_BYTE_RAMP    := 6,
      AES_PATTERN_WALKING_ONE  := 6,
      AES_PATTERN_WALKING_ZERO := 6
    };

    key_pattern dist {
      AES_PATTERN_RANDOM       := 60,
      AES_PATTERN_ALL_ZERO     := 4,
      AES_PATTERN_ALL_ONE      := 4,
      AES_PATTERN_SAME_BYTE    := 6,
      AES_PATTERN_ALT_A5       := 4,
      AES_PATTERN_ALT_5A       := 4,
      AES_PATTERN_BYTE_RAMP    := 6,
      AES_PATTERN_WALKING_ONE  := 6,
      AES_PATTERN_WALKING_ZERO := 6
    };
  }

  constraint c_data_pattern {
    if (data_pattern == AES_PATTERN_ALL_ZERO)
      data == 128'h0000_0000_0000_0000_0000_0000_0000_0000;
    else if (data_pattern == AES_PATTERN_ALL_ONE)
      data == 128'hffff_ffff_ffff_ffff_ffff_ffff_ffff_ffff;
    else if (data_pattern == AES_PATTERN_SAME_BYTE)
      data == {16{data_same_byte}};
    else if (data_pattern == AES_PATTERN_ALT_A5)
      data == 128'ha5a5_a5a5_a5a5_a5a5_a5a5_a5a5_a5a5_a5a5;
    else if (data_pattern == AES_PATTERN_ALT_5A)
      data == 128'h5a5a_5a5a_5a5a_5a5a_5a5a_5a5a_5a5a_5a5a;
    else if (data_pattern == AES_PATTERN_BYTE_RAMP)
      data == 128'h0f0e_0d0c_0b0a_0908_0706_0504_0302_0100;
    else if (data_pattern == AES_PATTERN_WALKING_ONE)
      data == (128'h1 << data_bit_pos);
    else if (data_pattern == AES_PATTERN_WALKING_ZERO)
      data == ~(128'h1 << data_bit_pos);
  }

  constraint c_key_pattern {
    if (key_pattern == AES_PATTERN_ALL_ZERO)
      key == 128'h0000_0000_0000_0000_0000_0000_0000_0000;
    else if (key_pattern == AES_PATTERN_ALL_ONE)
      key == 128'hffff_ffff_ffff_ffff_ffff_ffff_ffff_ffff;
    else if (key_pattern == AES_PATTERN_SAME_BYTE)
      key == {16{key_same_byte}};
    else if (key_pattern == AES_PATTERN_ALT_A5)
      key == 128'ha5a5_a5a5_a5a5_a5a5_a5a5_a5a5_a5a5_a5a5;
    else if (key_pattern == AES_PATTERN_ALT_5A)
      key == 128'h5a5a_5a5a_5a5a_5a5a_5a5a_5a5a_5a5a_5a5a;
    else if (key_pattern == AES_PATTERN_BYTE_RAMP)
      key == 128'h0f0e_0d0c_0b0a_0908_0706_0504_0302_0100;
    else if (key_pattern == AES_PATTERN_WALKING_ONE)
      key == (128'h1 << key_bit_pos);
    else if (key_pattern == AES_PATTERN_WALKING_ZERO)
      key == ~(128'h1 << key_bit_pos);
  }

  `uvm_object_utils_begin(aes_item)
    `uvm_field_int(data,    UVM_ALL_ON)
    `uvm_field_int(key,     UVM_ALL_ON)
    `uvm_field_int(result,  UVM_ALL_ON)
    `uvm_field_int(latency, UVM_ALL_ON)
  `uvm_object_utils_end

  function new(string name = "aes_item");
    super.new(name);
  endfunction
endclass

// ----------------------------------------------------------------------------
//  Sequences
// ----------------------------------------------------------------------------
// Constrained-random traffic.
// Each transaction is randomized using the constraints inside aes_item.
// The distribution intentionally mixes ordinary random AES blocks with
// corner-like patterns to improve functional coverage closure.
class aes_rand_seq extends uvm_sequence #(aes_item);
  `uvm_object_utils(aes_rand_seq)

  rand int unsigned n = 500;   // number of constrained-random transactions

  constraint c_n_reasonable {
    n inside {[50:2000]};
  }

  function new(string name = "aes_rand_seq");
    super.new(name);
  endfunction

  task body();
    aes_item tr;

    `uvm_info(get_type_name(),
      $sformatf("Starting constrained-random AES sequence with %0d transactions", n),
      UVM_LOW)

    repeat (n) begin
      tr = aes_item::type_id::create("tr");
      start_item(tr);
      if (!tr.randomize())
        `uvm_error(get_type_name(), "randomize() failed")
      finish_item(tr);
    end
  endtask
endclass

// Directed coverage-closure sequence.
// Runs before constrained-random traffic. It includes human-readable AES corner
// cases plus a deterministic 7 x 7 plaintext/key class sweep so that the
// transaction-level cross coverage reaches 100% without relying on luck.
class aes_corner_seq extends uvm_sequence #(aes_item);
  `uvm_object_utils(aes_corner_seq)

  function new(string name = "aes_corner_seq");
    super.new(name);
  endfunction

  function automatic bit [127:0] make_class_vector(int unsigned cls,
                                                   int unsigned salt = 0);
    int unsigned pos;
    pos = salt % 128;

    case (cls)
      0: return 128'h0000_0000_0000_0000_0000_0000_0000_0000; // all-zero
      1: return 128'hffff_ffff_ffff_ffff_ffff_ffff_ffff_ffff; // all-one
      2: return {16{8'h3c}};                                  // same-byte
      3: return (128'h1 << pos);                               // walking-one
      4: return ~(128'h1 << pos);                              // walking-zero
      5: return 128'ha5a5_a5a5_a5a5_a5a5_a5a5_a5a5_a5a5_a5a5; // alternating
      default:
         return 128'h0f0e_0d0c_0b0a_0908_0706_0504_0302_0100; // mixed/ramp
    endcase
  endfunction

  task send(bit [127:0] d, bit [127:0] k, string label = "directed");
    aes_item tr = aes_item::type_id::create(label);
    start_item(tr);
    if (!tr.randomize() with {
      data == d;
      key  == k;
      data_pattern == AES_PATTERN_RANDOM;
      key_pattern  == AES_PATTERN_RANDOM;
    })
      `uvm_error(get_type_name(), "directed randomize() failed")
    finish_item(tr);
  endtask

  task body();
    `uvm_info(get_type_name(), "Starting directed AES corner and coverage-closure sequence", UVM_LOW)

    // Basic whole-vector corner cases.
    send(128'h0000_0000_0000_0000_0000_0000_0000_0000,
         128'h0000_0000_0000_0000_0000_0000_0000_0000,
         "all_zero_plain_all_zero_key");

    send(128'hffff_ffff_ffff_ffff_ffff_ffff_ffff_ffff,
         128'hffff_ffff_ffff_ffff_ffff_ffff_ffff_ffff,
         "all_one_plain_all_one_key");

    send(128'h0000_0000_0000_0000_0000_0000_0000_0000,
         128'hffff_ffff_ffff_ffff_ffff_ffff_ffff_ffff,
         "all_zero_plain_all_one_key");

    send(128'hffff_ffff_ffff_ffff_ffff_ffff_ffff_ffff,
         128'h0000_0000_0000_0000_0000_0000_0000_0000,
         "all_one_plain_all_zero_key");

    // Repeated-byte class, intentionally not 00/ff/a5/5a.
    send({16{8'h3c}}, {16{8'hc3}}, "same_byte_plain_key");

    // Alternating-bit stress patterns.
    send(128'ha5a5_a5a5_a5a5_a5a5_a5a5_a5a5_a5a5_a5a5,
         128'h5a5a_5a5a_5a5a_5a5a_5a5a_5a5a_5a5a_5a5a,
         "alternating_a5_5a");

    send(128'h5a5a_5a5a_5a5a_5a5a_5a5a_5a5a_5a5a_5a5a,
         128'ha5a5_a5a5_a5a5_a5a5_a5a5_a5a5_a5a5_a5a5,
         "alternating_5a_a5");

    // Walking-one and walking-zero vectors.
    send(128'h0000_0000_0000_0000_0000_0000_0000_0001,
         128'hffff_ffff_ffff_ffff_ffff_ffff_ffff_fffe,
         "walking_one_plain_walking_zero_key");

    send(128'hffff_ffff_ffff_ffff_ffff_ffff_ffff_fffe,
         128'h0000_0000_0000_0000_0000_0000_0000_0001,
         "walking_zero_plain_walking_one_key");

    // Byte-ramp / mixed patterns. Byte 0 is in [7:0].
    send(128'h0f0e_0d0c_0b0a_0908_0706_0504_0302_0100,
         128'h0f0e_0d0c_0b0a_0908_0706_0504_0302_0100,
         "byte_ramp_plain_key");

    // FIPS-style AES-128 known-answer input ordering:
    // plaintext bytes: 00 11 22 ... ff
    // key bytes      : 00 01 02 ... 0f
    send(128'hffee_ddcc_bbaa_9988_7766_5544_3322_1100,
         128'h0f0e_0d0c_0b0a_0908_0706_0504_0302_0100,
         "fips_style_plain_key");

    // Existing fixed ASCII-style pattern retained from the original TB.
    send(128'h6f77_5420_656e_694e_2065_6e4f_2002_7754,
         128'h7546_2067_6e75_4b20_2079_6d20_7374_6168,
         "ascii_style_pattern");

    // Coverage-closure sweep for the 7 x 7 plaintext/key vector-class cross.
    // Class index mapping used by aes_coverage.vector_class():
    // 0 all-zero, 1 all-one, 2 same-byte, 3 walking-one,
    // 4 walking-zero, 5 alternating, 6 mixed/random.
    for (int data_cls = 0; data_cls < 7; data_cls++) begin
      for (int key_cls = 0; key_cls < 7; key_cls++) begin
        send(make_class_vector(data_cls, data_cls*17 + key_cls),
             make_class_vector(key_cls,  key_cls*19  + data_cls),
             $sformatf("coverage_cross_data%0d_key%0d", data_cls, key_cls));
      end
    end
  endtask
endclass

// ----------------------------------------------------------------------------
//  Driver
// ----------------------------------------------------------------------------
class aes_driver extends uvm_driver #(aes_item);
  `uvm_component_utils(aes_driver)
  virtual aes_if vif;

  function new(string name, uvm_component parent);
    super.new(name, parent);
  endfunction

  function void build_phase(uvm_phase phase);
    super.build_phase(phase);
    if (!uvm_config_db#(virtual aes_if)::get(this, "", "vif", vif))
      `uvm_fatal(get_type_name(), "virtual interface not set")
  endfunction

  task run_phase(uvm_phase phase);
    // Idle the bus until reset is released.
    vif.drv_cb.data_v_i <= 1'b0;
    vif.drv_cb.data_i   <= '0;
    vif.drv_cb.key_i    <= '0;
    wait (vif.nreset === 1'b1);
    @(vif.drv_cb);

    forever begin
      aes_item tr;
      seq_item_port.get_next_item(tr);

      // Present plaintext + key for exactly one cycle.
      vif.drv_cb.data_v_i <= 1'b1;
      vif.drv_cb.data_i   <= tr.data;
      vif.drv_cb.key_i    <= tr.key;
      @(vif.drv_cb);

      // Deassert valid; the DUT now iterates internally.
      vif.drv_cb.data_v_i <= 1'b0;
      vif.drv_cb.data_i   <= '0;
      vif.drv_cb.key_i    <= '0;

      // Serialize: the core has a single datapath, so wait for the result
      // before launching the next transaction.
      do @(vif.drv_cb); while (vif.drv_cb.res_v_o !== 1'b1);

      seq_item_port.item_done();
    end
  endtask
endclass

// ----------------------------------------------------------------------------
//  Monitor
// ----------------------------------------------------------------------------
class aes_monitor extends uvm_monitor;
  `uvm_component_utils(aes_monitor)
  virtual aes_if vif;
  uvm_analysis_port #(aes_item) ap;

  function new(string name, uvm_component parent);
    super.new(name, parent);
    ap = new("ap", this);
  endfunction

  function void build_phase(uvm_phase phase);
    super.build_phase(phase);
    if (!uvm_config_db#(virtual aes_if)::get(this, "", "vif", vif))
      `uvm_fatal(get_type_name(), "virtual interface not set")
  endfunction

  task run_phase(uvm_phase phase);
    forever begin
      aes_item tr;
      bit [127:0] d, k;
      int unsigned latency_count;

      // Capture the input transaction when valid is asserted.
      // Portable form: avoid @(clocking_block iff condition) because some
      // online simulators are stricter with clocking-block event syntax.
      do begin
        @(vif.mon_cb);
      end while (vif.mon_cb.data_v_i !== 1'b1);

      d = vif.mon_cb.data_i;
      k = vif.mon_cb.key_i;

      // Measure latency from accepted input valid to output valid.
      latency_count = 0;
      do begin
        @(vif.mon_cb);
        latency_count++;
      end while (vif.mon_cb.res_v_o !== 1'b1);

      tr = aes_item::type_id::create("tr");
      tr.data    = d;
      tr.key     = k;
      tr.result  = vif.mon_cb.res_o;
      tr.latency = latency_count;

      ap.write(tr);
    end
  endtask
endclass

// ----------------------------------------------------------------------------
//  Agent
// ----------------------------------------------------------------------------
class aes_agent extends uvm_agent;
  `uvm_component_utils(aes_agent)
  aes_driver                    drv;
  aes_monitor                   mon;
  uvm_sequencer #(aes_item)     seqr;

  function new(string name, uvm_component parent);
    super.new(name, parent);
  endfunction

  function void build_phase(uvm_phase phase);
    super.build_phase(phase);
    mon = aes_monitor::type_id::create("mon", this);
    if (get_is_active() == UVM_ACTIVE) begin
      drv  = aes_driver::type_id::create("drv", this);
      seqr = uvm_sequencer#(aes_item)::type_id::create("seqr", this);
    end
  endfunction

  function void connect_phase(uvm_phase phase);
    super.connect_phase(phase);
    if (get_is_active() == UVM_ACTIVE)
      drv.seq_item_port.connect(seqr.seq_item_export);
  endfunction
endclass

// ----------------------------------------------------------------------------
//  Functional coverage
// ----------------------------------------------------------------------------
class aes_coverage extends uvm_subscriber #(aes_item);
  `uvm_component_utils(aes_coverage)

  // Publish-ready coverage target. The test is designed to reach this target
  // using directed coverage-closure traffic plus constrained-random traffic.
  real coverage_target = 90.0;

  // Byte-level sample variables. write() samples this covergroup once per byte
  // position so all 16 plaintext/key/ciphertext bytes are covered compactly.
  int unsigned sampled_byte_index;
  bit [7:0]    sampled_data_byte;
  bit [7:0]    sampled_key_byte;
  bit [7:0]    sampled_result_byte;

  // Transaction-level sample variables.
  int unsigned sampled_data_class;
  int unsigned sampled_key_class;
  int unsigned sampled_latency;
  bit          sampled_cipher_nonzero;
  bit          sampled_cipher_changed_from_plain;

  // Byte-level coverage over all AES 128-bit buses.
  covergroup cg_byte;
    option.per_instance = 1;
    option.name         = "aes_byte_value_coverage";

    cp_byte_index : coverpoint sampled_byte_index {
      bins byte_pos[] = {[0:15]};
    }

    cp_plain_byte : coverpoint sampled_data_byte {
      bins zero = {8'h00};
      bins ones = {8'hff};
      bins low  = {[8'h01:8'h3f]};
      bins mid  = {[8'h40:8'hbf]};
      bins high = {[8'hc0:8'hfe]};
    }

    cp_key_byte : coverpoint sampled_key_byte {
      bins zero = {8'h00};
      bins ones = {8'hff};
      bins low  = {[8'h01:8'h3f]};
      bins mid  = {[8'h40:8'hbf]};
      bins high = {[8'hc0:8'hfe]};
    }

    cp_cipher_byte : coverpoint sampled_result_byte {
      bins zero = {8'h00};
      bins ones = {8'hff};
      bins low  = {[8'h01:8'h3f]};
      bins mid  = {[8'h40:8'hbf]};
      bins high = {[8'hc0:8'hfe]};
    }

    x_byte_plain  : cross cp_byte_index, cp_plain_byte;
    x_byte_key    : cross cp_byte_index, cp_key_byte;
    x_byte_cipher : cross cp_byte_index, cp_cipher_byte;
  endgroup

  // Transaction-level coverage with only achievable/meaningful bins.
  // Impossible ciphertext classes and invalid latency bins are intentionally not
  // counted toward the target. This avoids fake coverage holes and makes the
  // 90% target realistic and technically honest.
  covergroup cg_txn;
    option.per_instance = 1;
    option.name         = "aes_transaction_coverage";

    cp_plain_class : coverpoint sampled_data_class {
      bins all_zero     = {0};
      bins all_one      = {1};
      bins same_byte    = {2};
      bins walking_one  = {3};
      bins walking_zero = {4};
      bins alternating  = {5};
      bins mixed        = {6};
    }

    cp_key_class : coverpoint sampled_key_class {
      bins all_zero     = {0};
      bins all_one      = {1};
      bins same_byte    = {2};
      bins walking_one  = {3};
      bins walking_zero = {4};
      bins alternating  = {5};
      bins mixed        = {6};
    }

    // The monitor measures cycles from accepted input valid to result valid.
    // Only the legal latency window is a coverage goal. Other values are errors
    // or out-of-scope behavior, so they are ignored for coverage scoring.
    cp_latency : coverpoint sampled_latency {
      bins legal_iterative_latency = {[8:20]};

      // Riviera-PRO / EDA Playground compatibility:
      // Do not use "ignore_bins ... = default;" here.
      // Some Riviera versions reject default ignore bins in covergroups.
      ignore_bins shorter_than_valid = {[0:7]};
      ignore_bins longer_than_valid  = {[21:1000000]};
    }

    // Ciphertext is already covered byte-by-byte in cg_byte. These transaction
    // checks only prove that the accelerator produced non-trivial output.
    cp_cipher_nonzero : coverpoint sampled_cipher_nonzero {
      bins nonzero = {1'b1};
      ignore_bins zero_cipher = {1'b0};
    }

    cp_cipher_changed_from_plain : coverpoint sampled_cipher_changed_from_plain {
      bins changed = {1'b1};
      ignore_bins unchanged = {1'b0};
    }

    x_plain_key_class : cross cp_plain_class, cp_key_class;
  endgroup

  function new(string name, uvm_component parent);
    super.new(name, parent);
    cg_byte = new();
    cg_txn  = new();
  endfunction

  // Classify full 128-bit vectors into coverage categories:
  // 0 all-zero, 1 all-one, 2 repeated-byte, 3 walking-one,
  // 4 walking-zero, 5 alternating A5/5A, 6 mixed/random.
  function automatic int unsigned vector_class(bit [127:0] v);
    bit same_byte;
    bit [7:0] b0;

    if (v == 128'h0000_0000_0000_0000_0000_0000_0000_0000)
      return 0;

    if (v == 128'hffff_ffff_ffff_ffff_ffff_ffff_ffff_ffff)
      return 1;

    if ($onehot(v))
      return 3;

    if ($onehot(~v))
      return 4;

    if ((v == 128'ha5a5_a5a5_a5a5_a5a5_a5a5_a5a5_a5a5_a5a5) ||
        (v == 128'h5a5a_5a5a_5a5a_5a5a_5a5a_5a5a_5a5a_5a5a))
      return 5;

    b0 = v[7:0];
    same_byte = 1'b1;
    for (int i = 1; i < 16; i++) begin
      if (v[8*i +: 8] != b0)
        same_byte = 1'b0;
    end
    if (same_byte)
      return 2;

    return 6;
  endfunction

  function void write(aes_item t);
    sampled_data_class                = vector_class(t.data);
    sampled_key_class                 = vector_class(t.key);
    sampled_latency                   = t.latency;
    sampled_cipher_nonzero            = (t.result != 128'h0);
    sampled_cipher_changed_from_plain = (t.result != t.data);
    cg_txn.sample();

    for (int i = 0; i < 16; i++) begin
      sampled_byte_index  = i;
      sampled_data_byte   = t.data  [8*i +: 8];
      sampled_key_byte    = t.key   [8*i +: 8];
      sampled_result_byte = t.result[8*i +: 8];
      cg_byte.sample();
    end
  endfunction

  function real total_coverage();
    return (cg_byte.get_coverage() + cg_txn.get_coverage()) / 2.0;
  endfunction

  function void report_phase(uvm_phase phase);
    real byte_cov;
    real txn_cov;
    real total_cov;

    super.report_phase(phase);

    byte_cov  = cg_byte.get_coverage();
    txn_cov   = cg_txn.get_coverage();
    total_cov = total_coverage();

    `uvm_info(get_type_name(),
      $sformatf("COVERAGE SUMMARY: byte_cov=%0.2f%% txn_cov=%0.2f%% total_cov=%0.2f%% target=%0.2f%%",
                byte_cov, txn_cov, total_cov, coverage_target),
      UVM_NONE)

    if (total_cov < coverage_target) begin
      `uvm_warning(get_type_name(),
        $sformatf("Coverage target not reached: total_cov=%0.2f%% target=%0.2f%%. Increase aes_rand_seq.n or add directed cases.",
                  total_cov, coverage_target))
    end
    else begin
      `uvm_info(get_type_name(), "Coverage target reached", UVM_NONE)
    end
  endfunction
endclass

// ----------------------------------------------------------------------------
//  Scoreboard (with bit-exact AES-128 reference model)
// ----------------------------------------------------------------------------
class aes_scoreboard extends uvm_subscriber #(aes_item);
  `uvm_component_utils(aes_scoreboard)
  int unsigned n_pass = 0;
  int unsigned n_fail = 0;

  function new(string name, uvm_component parent);
    super.new(name, parent);
  endfunction

  // -- AES-128 reference model (matches the DUT byte mapping exactly) --------
  // S-box lookup table (Rijndael).
  function automatic bit [7:0] rm_sbox(bit [7:0] b);
    bit [7:0] sb [0:255] = '{
      8'h63,8'h7c,8'h77,8'h7b,8'hf2,8'h6b,8'h6f,8'hc5,8'h30,8'h01,8'h67,8'h2b,8'hfe,8'hd7,8'hab,8'h76,
      8'hca,8'h82,8'hc9,8'h7d,8'hfa,8'h59,8'h47,8'hf0,8'had,8'hd4,8'ha2,8'haf,8'h9c,8'ha4,8'h72,8'hc0,
      8'hb7,8'hfd,8'h93,8'h26,8'h36,8'h3f,8'hf7,8'hcc,8'h34,8'ha5,8'he5,8'hf1,8'h71,8'hd8,8'h31,8'h15,
      8'h04,8'hc7,8'h23,8'hc3,8'h18,8'h96,8'h05,8'h9a,8'h07,8'h12,8'h80,8'he2,8'heb,8'h27,8'hb2,8'h75,
      8'h09,8'h83,8'h2c,8'h1a,8'h1b,8'h6e,8'h5a,8'ha0,8'h52,8'h3b,8'hd6,8'hb3,8'h29,8'he3,8'h2f,8'h84,
      8'h53,8'hd1,8'h00,8'hed,8'h20,8'hfc,8'hb1,8'h5b,8'h6a,8'hcb,8'hbe,8'h39,8'h4a,8'h4c,8'h58,8'hcf,
      8'hd0,8'hef,8'haa,8'hfb,8'h43,8'h4d,8'h33,8'h85,8'h45,8'hf9,8'h02,8'h7f,8'h50,8'h3c,8'h9f,8'ha8,
      8'h51,8'ha3,8'h40,8'h8f,8'h92,8'h9d,8'h38,8'hf5,8'hbc,8'hb6,8'hda,8'h21,8'h10,8'hff,8'hf3,8'hd2,
      8'hcd,8'h0c,8'h13,8'hec,8'h5f,8'h97,8'h44,8'h17,8'hc4,8'ha7,8'h7e,8'h3d,8'h64,8'h5d,8'h19,8'h73,
      8'h60,8'h81,8'h4f,8'hdc,8'h22,8'h2a,8'h90,8'h88,8'h46,8'hee,8'hb8,8'h14,8'hde,8'h5e,8'h0b,8'hdb,
      8'he0,8'h32,8'h3a,8'h0a,8'h49,8'h06,8'h24,8'h5c,8'hc2,8'hd3,8'hac,8'h62,8'h91,8'h95,8'he4,8'h79,
      8'he7,8'hc8,8'h37,8'h6d,8'h8d,8'hd5,8'h4e,8'ha9,8'h6c,8'h56,8'hf4,8'hea,8'h65,8'h7a,8'hae,8'h08,
      8'hba,8'h78,8'h25,8'h2e,8'h1c,8'ha6,8'hb4,8'hc6,8'he8,8'hdd,8'h74,8'h1f,8'h4b,8'hbd,8'h8b,8'h8a,
      8'h70,8'h3e,8'hb5,8'h66,8'h48,8'h03,8'hf6,8'h0e,8'h61,8'h35,8'h57,8'hb9,8'h86,8'hc1,8'h1d,8'h9e,
      8'he1,8'hf8,8'h98,8'h11,8'h69,8'hd9,8'h8e,8'h94,8'h9b,8'h1e,8'h87,8'he9,8'hce,8'h55,8'h28,8'hdf,
      8'h8c,8'ha1,8'h89,8'h0d,8'hbf,8'he6,8'h42,8'h68,8'h41,8'h99,8'h2d,8'h0f,8'hb0,8'h54,8'hbb,8'h16};
    return sb[b];
  endfunction

  // xtime (multiply by 2 in GF(2^8)).
  function automatic bit [7:0] rm_xtime(bit [7:0] a);
    return (a[7]) ? ((a << 1) ^ 8'h1b) : (a << 1);
  endfunction

  // GF multiply.
  function automatic bit [7:0] rm_gmul(bit [7:0] a, bit [7:0] b);
    bit [7:0] r = 0;
    bit [7:0] aa = a;
    for (int i = 0; i < 8; i++) begin
      if (b[i]) r ^= aa;
      aa = rm_xtime(aa);
    end
    return r;
  endfunction

  // Full AES-128 encrypt. state[r][c] = byte (4*c+r) = in[8*(4*c+r) +: 8].
  function automatic bit [127:0] rm_aes128(bit [127:0] data, bit [127:0] key);
    bit [7:0] st  [0:3][0:3];
    bit [7:0] w   [0:43][0:3];
    bit [7:0] tmp [0:3];
    bit [7:0] col [0:3];
    bit [7:0] tb;
    bit [7:0] rcon [0:9] = '{8'h01,8'h02,8'h04,8'h08,8'h10,8'h20,8'h40,8'h80,8'h1b,8'h36};
    bit [127:0] res;

    // load state and first 4 key words (one word per column)
    for (int c = 0; c < 4; c++)
      for (int r = 0; r < 4; r++) begin
        st[r][c]   = data[8*(4*c+r) +: 8];
        w[c][r]    = key [8*(4*c+r) +: 8];
      end

    // key expansion
    for (int i = 4; i < 44; i++) begin
      for (int j = 0; j < 4; j++) tmp[j] = w[i-1][j];
      if (i % 4 == 0) begin
        tb = tmp[0]; tmp[0] = tmp[1]; tmp[1] = tmp[2]; tmp[2] = tmp[3]; tmp[3] = tb; // RotWord
        for (int j = 0; j < 4; j++) tmp[j] = rm_sbox(tmp[j]);                        // SubWord
        tmp[0] ^= rcon[i/4 - 1];
      end
      for (int j = 0; j < 4; j++) w[i][j] = w[i-4][j] ^ tmp[j];
    end

    // initial AddRoundKey
    for (int c = 0; c < 4; c++)
      for (int r = 0; r < 4; r++) st[r][c] ^= w[c][r];

    // rounds 1..9
    for (int rnd = 1; rnd <= 9; rnd++) begin
      // SubBytes
      for (int r = 0; r < 4; r++)
        for (int c = 0; c < 4; c++) st[r][c] = rm_sbox(st[r][c]);
      // ShiftRows (row r rotated left by r)
      for (int r = 1; r < 4; r++) begin
        bit [7:0] row [0:3];
        for (int c = 0; c < 4; c++) row[c] = st[r][c];
        for (int c = 0; c < 4; c++) st[r][c] = row[(c+r)%4];
      end
      // MixColumns
      for (int c = 0; c < 4; c++) begin
        for (int r = 0; r < 4; r++) col[r] = st[r][c];
        st[0][c] = rm_gmul(col[0],2) ^ rm_gmul(col[1],3) ^ col[2]              ^ col[3];
        st[1][c] = col[0]            ^ rm_gmul(col[1],2) ^ rm_gmul(col[2],3)   ^ col[3];
        st[2][c] = col[0]            ^ col[1]            ^ rm_gmul(col[2],2)   ^ rm_gmul(col[3],3);
        st[3][c] = rm_gmul(col[0],3) ^ col[1]            ^ col[2]              ^ rm_gmul(col[3],2);
      end
      // AddRoundKey
      for (int c = 0; c < 4; c++)
        for (int r = 0; r < 4; r++) st[r][c] ^= w[rnd*4 + c][r];
    end

    // final round (no MixColumns)
    for (int r = 0; r < 4; r++)
      for (int c = 0; c < 4; c++) st[r][c] = rm_sbox(st[r][c]);
    for (int r = 1; r < 4; r++) begin
      bit [7:0] row [0:3];
      for (int c = 0; c < 4; c++) row[c] = st[r][c];
      for (int c = 0; c < 4; c++) st[r][c] = row[(c+r)%4];
    end
    for (int c = 0; c < 4; c++)
      for (int r = 0; r < 4; r++) st[r][c] ^= w[40 + c][r];

    // pack result back to DUT byte order
    res = '0;
    for (int c = 0; c < 4; c++)
      for (int r = 0; r < 4; r++) res[8*(4*c+r) +: 8] = st[r][c];
    return res;
  endfunction
  // --------------------------------------------------------------------------

  function void write(aes_item t);
    bit [127:0] expected = rm_aes128(t.data, t.key);
    if (t.result === expected) begin
      n_pass++;
      `uvm_info(get_type_name(),
        $sformatf("PASS  data=%032h key=%032h res=%032h", t.data, t.key, t.result),
        UVM_HIGH)
    end
    else begin
      n_fail++;
      `uvm_error(get_type_name(),
        $sformatf("MISMATCH data=%032h key=%032h dut=%032h exp=%032h",
                  t.data, t.key, t.result, expected))
    end
  endfunction

  function void report_phase(uvm_phase phase);
    if (n_fail == 0)
      `uvm_info(get_type_name(),
        $sformatf("SCOREBOARD: ALL %0d TRANSACTIONS PASSED", n_pass), UVM_NONE)
    else
      `uvm_error(get_type_name(),
        $sformatf("SCOREBOARD: %0d PASS, %0d FAIL", n_pass, n_fail))
  endfunction
endclass

// ----------------------------------------------------------------------------
//  Environment
// ----------------------------------------------------------------------------
class aes_env extends uvm_env;
  `uvm_component_utils(aes_env)
  aes_agent      agent;
  aes_scoreboard sb;
  aes_coverage   cov;

  function new(string name, uvm_component parent);
    super.new(name, parent);
  endfunction

  function void build_phase(uvm_phase phase);
    super.build_phase(phase);
    agent = aes_agent::type_id::create("agent", this);
    sb    = aes_scoreboard::type_id::create("sb", this);
    cov   = aes_coverage::type_id::create("cov", this);
  endfunction

  function void connect_phase(uvm_phase phase);
    super.connect_phase(phase);
    agent.mon.ap.connect(sb.analysis_export);
    agent.mon.ap.connect(cov.analysis_export);
  endfunction
endclass

// ----------------------------------------------------------------------------
//  Test
// ----------------------------------------------------------------------------
class aes_test extends uvm_test;
  `uvm_component_utils(aes_test)
  aes_env env;

  function new(string name, uvm_component parent);
    super.new(name, parent);
  endfunction

  function void build_phase(uvm_phase phase);
    super.build_phase(phase);
    env = aes_env::type_id::create("env", this);
  endfunction

  task run_phase(uvm_phase phase);
    aes_corner_seq corner = aes_corner_seq::type_id::create("corner");
    aes_rand_seq   rseq   = aes_rand_seq::type_id::create("rseq");

    phase.raise_objection(this);
    phase.phase_done.set_drain_time(this, 100ns);

    `uvm_info(get_type_name(), "AES UVM test started", UVM_LOW)

    // Directed coverage closure first. This deterministically hits all
    // plaintext/key vector-class cross bins.
    corner.start(env.agent.seqr);

    // Constrained-random traffic then fills byte-value/range coverage on all
    // plaintext, key, and ciphertext byte positions.
    rseq.n = 500;
    rseq.start(env.agent.seqr);

    `uvm_info(get_type_name(), "AES UVM test completed", UVM_LOW)

    phase.drop_objection(this);
  endtask
endclass

// ----------------------------------------------------------------------------
//  Top: clock, reset, DUT, config, run_test
// ----------------------------------------------------------------------------
module testbench_top;
  bit clk = 0;
  always #5 clk = ~clk;            // 100 MHz

  aes_if vif(clk);

  // DUT (defined in design.sv, right pane)
  aes dut(
    .clk      (vif.clk),
    .nreset   (vif.nreset),
    .data_v_i (vif.data_v_i),
    .data_i   (vif.data_i),
    .key_i    (vif.key_i),
    .res_v_o  (vif.res_v_o),
    .res_o    (vif.res_o)
  );

  // ------------------------------------------------------------
  // Waveform dump for EPWave / Riviera-PRO
  // Dumps only AES input/output interface signals
  // ------------------------------------------------------------
  initial begin
    $dumpfile("dump.vcd");

    // Clock and reset
    $dumpvars(0, testbench_top.clk);
    $dumpvars(0, testbench_top.vif.nreset);

    // DUT inputs
    $dumpvars(0, testbench_top.vif.data_v_i);
    $dumpvars(0, testbench_top.vif.data_i);
    $dumpvars(0, testbench_top.vif.key_i);

    // DUT outputs
    $dumpvars(0, testbench_top.vif.res_v_o);
    $dumpvars(0, testbench_top.vif.res_o);
  end

  // Active-low reset pulse
  initial begin
    vif.nreset = 1'b0;
    repeat (4) @(posedge clk);
    vif.nreset = 1'b1;
  end

  initial begin
    uvm_config_db#(virtual aes_if)::set(null, "*", "vif", vif);

    // The required UVM test is aes_test.
    // EDA Playground command line should also use:
    //   +UVM_TESTNAME=aes_test
    run_test("aes_test");
  end

  // Safety watchdog
  initial begin
    #2_000_000;
    `uvm_fatal("TIMEOUT", "Simulation watchdog expired")
  end
endmodule
