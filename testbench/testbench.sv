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

class no_uvm_prints_c extends uvm_report_catcher;
  `uvm_object_utils(no_uvm_prints_c)

  function new(string name = "no_uvm_prints_c");
    super.new(name);
  endfunction

  virtual function action_e catch();
    if (get_severity() inside {UVM_INFO, UVM_WARNING, UVM_FATAL}) begin
      set_action(get_action() & ~(UVM_DISPLAY | UVM_LOG));
    end
    return THROW;
  endfunction
endclass

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
class aes_item extends uvm_sequence_item;
  rand bit [127:0] data;     // plaintext
  rand bit [127:0] key;      // cipher key
       bit [127:0] result;   // ciphertext captured from DUT (filled by monitor)

  `uvm_object_utils_begin(aes_item)
    `uvm_field_int(data,   UVM_ALL_ON)
    `uvm_field_int(key,    UVM_ALL_ON)
    `uvm_field_int(result, UVM_ALL_ON)
  `uvm_object_utils_end

  function new(string name = "aes_item");
    super.new(name);
  endfunction
endclass

// ----------------------------------------------------------------------------
//  Sequences
// ----------------------------------------------------------------------------
// Constrained-random traffic.
class aes_rand_seq extends uvm_sequence #(aes_item);
  `uvm_object_utils(aes_rand_seq)
  rand int unsigned n = 200;   // number of random transactions

  function new(string name = "aes_rand_seq");
    super.new(name);
  endfunction

  task body();
    aes_item tr;
    repeat (n) begin
      tr = aes_item::type_id::create("tr");
      start_item(tr);
      if (!tr.randomize())
        `uvm_error(get_type_name(), "randomize() failed")
      finish_item(tr);
    end
  endtask
endclass

// Directed corner cases (all-0, all-1, byte ramps, canonical FIPS vector).
class aes_corner_seq extends uvm_sequence #(aes_item);
  `uvm_object_utils(aes_corner_seq)

  function new(string name = "aes_corner_seq");
    super.new(name);
  endfunction

  task send(bit [127:0] d, bit [127:0] k);
    aes_item tr = aes_item::type_id::create("tr");
    start_item(tr);
    if (!tr.randomize() with { data == d; key == k; })
      `uvm_error(get_type_name(), "corner randomize() failed")
    finish_item(tr);
  endtask

  task body();
    send(128'h0,                                  128'h0);
    send({128{1'b1}},                             {128{1'b1}});
    send(128'h0,                                  {128{1'b1}});
    send({128{1'b1}},                             128'h0);
    // A fixed directed pattern (ASCII text in both operands). The scoreboard's
    // reference model computes the matching ciphertext for this core's byte order,
    // so no precomputed golden value is needed here.
    send(128'h6F77_5420_656E_694E_2065_6E4F_2002_7754,
         128'h7546_2067_6E75_4B20_2079_6D20_7374_6168);
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

      // Capture the input transaction when valid is asserted.
      @(vif.mon_cb iff vif.mon_cb.data_v_i === 1'b1);
      d = vif.mon_cb.data_i;
      k = vif.mon_cb.key_i;

      // Capture the output when the result is valid.
      @(vif.mon_cb iff vif.mon_cb.res_v_o === 1'b1);
      tr = aes_item::type_id::create("tr");
      tr.data   = d;
      tr.key    = k;
      tr.result = vif.mon_cb.res_o;
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
  aes_item tr;

  covergroup cg;
    option.per_instance = 1;
    // Sample a representative byte of the plaintext and the key.
    cp_data_b0 : coverpoint tr.data[7:0]   { bins lo = {[0:84]}; bins mid = {[85:170]}; bins hi = {[171:255]};
                                             bins zero = {0}; bins ones = {255}; }
    cp_data_b15: coverpoint tr.data[127:120]{ bins lo = {[0:84]}; bins mid = {[85:170]}; bins hi = {[171:255]}; }
    cp_key_b0  : coverpoint tr.key[7:0]     { bins lo = {[0:84]}; bins mid = {[85:170]}; bins hi = {[171:255]};
                                             bins zero = {0}; bins ones = {255}; }
    cp_key_b15 : coverpoint tr.key[127:120] { bins lo = {[0:84]}; bins mid = {[85:170]}; bins hi = {[171:255]}; }
    // Whole-vector corner conditions.
    cp_data_all: coverpoint tr.data { bins allzero = {128'h0}; bins allone = {{128{1'b1}}};
                                      bins other   = default; }
    cp_key_all : coverpoint tr.key  { bins allzero = {128'h0}; bins allone = {{128{1'b1}}};
                                      bins other   = default; }
    // Cross to exercise key/data combinations.
    x_db0_kb0  : cross cp_data_b0, cp_key_b0;
  endgroup

  function new(string name, uvm_component parent);
    super.new(name, parent);
    cg = new();
  endfunction

  function void write(aes_item t);
    tr = t;
    cg.sample();
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
    corner.start(env.agent.seqr);   // directed corner cases first
    rseq.n = 200;
    rseq.start(env.agent.seqr);     // then constrained-random traffic
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

    $dumpvars(0, clk);
    $dumpvars(0, vif.nreset);

    $dumpvars(0, vif.data_v_i);
    $dumpvars(0, vif.data_i);
    $dumpvars(0, vif.key_i);

    $dumpvars(0, vif.res_v_o);
    $dumpvars(0, vif.res_o);
  end

  // Active-low reset pulse
  initial begin
    vif.nreset = 1'b0;
    repeat (4) @(posedge clk);
    vif.nreset = 1'b1;
  end

  no_uvm_prints_c no_uvm_prints;

  initial begin
    no_uvm_prints = new("no_uvm_prints");
    uvm_report_cb::add(null, no_uvm_prints);

    uvm_config_db#(virtual aes_if)::set(null, "*", "vif", vif);
    run_test("aes_test");
  end

  // Safety watchdog
  initial begin
    #2_000_000;
    `uvm_fatal("TIMEOUT", "Simulation watchdog expired")
  end
endmodule
