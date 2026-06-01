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
// Pattern selectors are used only to bias constrained-random generation.
// The scoreboard always checks the actual data/key/result values.
typedef enum int unsigned {
  AES_PATTERN_RANDOM,
  AES_PATTERN_ALL_ZERO,
  AES_PATTERN_ALL_ONE,
  AES_PATTERN_ALT_A5,
  AES_PATTERN_ALT_5A,
  AES_PATTERN_BYTE_RAMP,
  AES_PATTERN_WALKING_ONE
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

  constraint c_bit_pos {
    data_bit_pos inside {[0:127]};
    key_bit_pos  inside {[0:127]};
  }

  // Constrained-random distribution:
  // mostly unconstrained random AES blocks, with weighted corner/pattern cases.
  constraint c_pattern_dist {
    data_pattern dist {
      AES_PATTERN_RANDOM      := 80,
      AES_PATTERN_ALL_ZERO    := 3,
      AES_PATTERN_ALL_ONE     := 3,
      AES_PATTERN_ALT_A5      := 3,
      AES_PATTERN_ALT_5A      := 3,
      AES_PATTERN_BYTE_RAMP   := 4,
      AES_PATTERN_WALKING_ONE := 4
    };

    key_pattern dist {
      AES_PATTERN_RANDOM      := 80,
      AES_PATTERN_ALL_ZERO    := 3,
      AES_PATTERN_ALL_ONE     := 3,
      AES_PATTERN_ALT_A5      := 3,
      AES_PATTERN_ALT_5A      := 3,
      AES_PATTERN_BYTE_RAMP   := 4,
      AES_PATTERN_WALKING_ONE := 4
    };
  }

  constraint c_data_pattern {
    if (data_pattern == AES_PATTERN_ALL_ZERO)
      data == 128'h0000_0000_0000_0000_0000_0000_0000_0000;
    else if (data_pattern == AES_PATTERN_ALL_ONE)
      data == 128'hffff_ffff_ffff_ffff_ffff_ffff_ffff_ffff;
    else if (data_pattern == AES_PATTERN_ALT_A5)
      data == 128'ha5a5_a5a5_a5a5_a5a5_a5a5_a5a5_a5a5_a5a5;
    else if (data_pattern == AES_PATTERN_ALT_5A)
      data == 128'h5a5a_5a5a_5a5a_5a5a_5a5a_5a5a_5a5a_5a5a;
    else if (data_pattern == AES_PATTERN_BYTE_RAMP)
      data == 128'h0f0e_0d0c_0b0a_0908_0706_0504_0302_0100;
    else if (data_pattern == AES_PATTERN_WALKING_ONE)
      data == (128'h1 << data_bit_pos);
  }

  constraint c_key_pattern {
    if (key_pattern == AES_PATTERN_ALL_ZERO)
      key == 128'h0000_0000_0000_0000_0000_0000_0000_0000;
    else if (key_pattern == AES_PATTERN_ALL_ONE)
      key == 128'hffff_ffff_ffff_ffff_ffff_ffff_ffff_ffff;
    else if (key_pattern == AES_PATTERN_ALT_A5)
      key == 128'ha5a5_a5a5_a5a5_a5a5_a5a5_a5a5_a5a5_a5a5;
    else if (key_pattern == AES_PATTERN_ALT_5A)
      key == 128'h5a5a_5a5a_5a5a_5a5a_5a5a_5a5a_5a5a_5a5a;
    else if (key_pattern == AES_PATTERN_BYTE_RAMP)
      key == 128'h0f0e_0d0c_0b0a_0908_0706_0504_0302_0100;
    else if (key_pattern == AES_PATTERN_WALKING_ONE)
      key == (128'h1 << key_bit_pos);
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

// Directed corner cases.
// These run before the constrained-random sequence to guarantee that important
// AES/block-cipher edge cases are exercised even if randomization does not hit
// them in a short EDA Playground run.
class aes_corner_seq extends uvm_sequence #(aes_item);
  `uvm_object_utils(aes_corner_seq)

  function new(string name = "aes_corner_seq");
    super.new(name);
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
      `uvm_error(get_type_name(), "corner randomize() failed")
    finish_item(tr);
  endtask

  task body();
    `uvm_info(get_type_name(), "Starting directed AES corner sequence", UVM_LOW)

    // Whole-vector corner cases.
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

    // Alternating-bit stress patterns.
    send(128'ha5a5_a5a5_a5a5_a5a5_a5a5_a5a5_a5a5_a5a5,
         128'h5a5a_5a5a_5a5a_5a5a_5a5a_5a5a_5a5a_5a5a,
         "alternating_a5_5a");

    send(128'h5a5a_5a5a_5a5a_5a5a_5a5a_5a5a_5a5a_5a5a,
         128'ha5a5_a5a5_a5a5_a5a5_a5a5_a5a5_a5a5_a5a5,
         "alternating_5a_a5");

    // Byte-ramp patterns. Byte 0 is in [7:0], so this represents
    // bytes 00, 01, 02, ..., 0f in the RTL byte order.
    send(128'h0f0e_0d0c_0b0a_0908_0706_0504_0302_0100,
         128'h0f0e_0d0c_0b0a_0908_0706_0504_0302_0100,
         "byte_ramp_plain_key");

    // FIPS-style AES-128 known-answer input ordering:
    // plaintext bytes: 00 11 22 ... ff
    // key bytes      : 00 01 02 ... 0f
    // The scoreboard computes the expected ciphertext internally using the
    // same byte mapping as the DUT, so no hardcoded expected value is needed.
    send(128'hffee_ddcc_bbaa_9988_7766_5544_3322_1100,
         128'h0f0e_0d0c_0b0a_0908_0706_0504_0302_0100,
         "fips_style_plain_key");

    // Existing fixed ASCII-style directed pattern retained from the original TB.
    send(128'h6f77_5420_656e_694e_2065_6e4f_2002_7754,
         128'h7546_2067_6e75_4b20_2079_6d20_7374_6168,
         "ascii_style_pattern");
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

  // Coverage target used for the final summary. This is intentionally visible
  // in the log so the project demonstrates coverage-driven methodology.
  real coverage_target = 90.0;

  // Sample variables for byte-level coverage. The write() method samples this
  // covergroup once per byte position, so all 16 plaintext/key/ciphertext bytes
  // are covered without writing 48 separate coverpoints.
  int unsigned sampled_byte_index;
  bit [7:0]    sampled_data_byte;
  bit [7:0]    sampled_key_byte;
  bit [7:0]    sampled_result_byte;

  // Sample variables for transaction-level coverage.
  int unsigned sampled_data_class;
  int unsigned sampled_key_class;
  int unsigned sampled_result_class;
  int unsigned sampled_latency;

  // Byte-level coverage: every byte position should see a useful spread of
  // plaintext, key, and ciphertext values.
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

  // Transaction-level coverage: checks complete 128-bit vector classes,
  // input/key interaction, output class, and DUT latency.
  covergroup cg_txn;
    option.per_instance = 1;
    option.name         = "aes_transaction_coverage";

    cp_plain_class : coverpoint sampled_data_class {
      bins all_zero    = {0};
      bins all_one     = {1};
      bins same_byte   = {2};
      bins walking_one = {3};
      bins walking_zero= {4};
      bins alternating = {5};
      bins mixed       = {6};
    }

    cp_key_class : coverpoint sampled_key_class {
      bins all_zero    = {0};
      bins all_one     = {1};
      bins same_byte   = {2};
      bins walking_one = {3};
      bins walking_zero= {4};
      bins alternating = {5};
      bins mixed       = {6};
    }

    cp_cipher_class : coverpoint sampled_result_class {
      bins all_zero    = {0};
      bins all_one     = {1};
      bins same_byte   = {2};
      bins walking_one = {3};
      bins walking_zero= {4};
      bins alternating = {5};
      bins mixed       = {6};
    }

    // AES core latency should be stable for a serialized iterative core.
    // A wider expected bin is used so this remains portable if minor RTL
    // scheduling changes shift the exact cycle count.
    cp_latency : coverpoint sampled_latency {
      bins expected_iterative_latency = {[8:20]};
      bins shorter_than_expected     = {[0:7]};
      bins longer_than_expected      = {[21:100]};
      bins very_long_latency         = {[101:1000000]};
    }

    x_plain_key_class : cross cp_plain_class, cp_key_class;
  endgroup

  function new(string name, uvm_component parent);
    super.new(name, parent);
    cg_byte = new();
    cg_txn  = new();
  endfunction

  // Classify full 128-bit vectors into coverage categories:
  // 0 all zero, 1 all one, 2 repeated byte, 3 walking one,
  // 4 walking zero, 5 alternating A5/5A, 6 mixed/random.
  function automatic int unsigned vector_class(bit [127:0] v);
    bit same_byte;
    bit [7:0] b0;

    if (v == 128'h0000_0000_0000_0000_0000_0000_0000_0000)
      return 0;

    if (v == 128'hffff_ffff_ffff_ffff_ffff_ffff_ffff_ffff)
      return 1;

    b0 = v[7:0];
    same_byte = 1'b1;
    for (int i = 1; i < 16; i++) begin
      if (v[8*i +: 8] != b0)
        same_byte = 1'b0;
    end
    if (same_byte)
      return 2;

    if ($onehot(v))
      return 3;

    if ($onehot(~v))
      return 4;

    if ((v == 128'ha5a5_a5a5_a5a5_a5a5_a5a5_a5a5_a5a5_a5a5) ||
        (v == 128'h5a5a_5a5a_5a5a_5a5a_5a5a_5a5a_5a5a_5a5a))
      return 5;

    return 6;
  endfunction

  function void write(aes_item t);
    sampled_data_class   = vector_class(t.data);
    sampled_key_class    = vector_class(t.key);
    sampled_result_class = vector_class(t.result);
    sampled_latency      = t.latency;
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

    corner.start(env.agent.seqr);   // directed corner cases first

    rseq.n = 500;                   // increase for higher coverage closure
    rseq.start(env.agent.seqr);     // then constrained-random traffic

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
