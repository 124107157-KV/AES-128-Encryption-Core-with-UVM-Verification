// ============================================================================
//  design.sv  --  AES-128 encryption RTL core (EDA Playground RIGHT pane)
// ----------------------------------------------------------------------------
//  Purpose:
//    Open-source style AES-128 encryption block used as the DUT for a complete
//    SystemVerilog/UVM verification environment.
//
//  Source / attribution:
//    If this RTL was copied or adapted from an external open-source AES core,
//    keep the original copyright notice, author name, repository URL, and
//    license text here. Do not remove upstream attribution.
//
//    Original source     : <ADD_ORIGINAL_AES_RTL_REPOSITORY_URL_HERE>
//    Original author(s)  : <ADD_AUTHOR_NAME_OR_PROJECT_NAME_HERE>
//    Original license    : <ADD_LICENSE_NAME_HERE>
//    Local modifications : Concatenated into one EDA Playground file and used
//                          with the UVM verification environment.
//
//  AES behavior:
//    - AES-128 encryption only.
//    - 128-bit plaintext input and 128-bit key input.
//    - 128-bit ciphertext output.
//    - Implements SubBytes, ShiftRows, MixColumns, AddRoundKey, and key schedule.
//    - Final AES round excludes MixColumns, as required by AES-128.
//    - One-cycle input-valid handshake through data_v_i.
//    - One-cycle output-valid indication through res_v_o.
//
//  Byte mapping used by this RTL and the reference model:
//     plaintext byte k  ->  data_i[8*k +: 8]   (byte 0 in bits [7:0])
//     state[row][col]   =  byte (4*col + row)
//     ciphertext byte k ->  res_o [8*k +: 8]
//
//  Latency:
//     Assert data_v_i for one clk cycle with data_i/key_i stable. The DUT then
//     iterates internally and pulses res_v_o for one cycle when res_o is valid.
// ============================================================================

`timescale 1ns / 1ps

// ----------------------------------------------------------------------------
//  S-box (combinational, Boyar-Peralta) -- from sbox.v
// ----------------------------------------------------------------------------
module sbox(
    input  [7:0] data_i,
    output [7:0] data_o
    );

    wire[0:7] s, x;
    wire [21:1] y;
    wire [67:0] t;
    wire [17:0] z;

    assign x = data_i;

    assign y[14] = x[3]  ^ x[5];
    assign y[13] = x[0]  ^ x[6];
    assign y[9]  = x[0]  ^ x[3];
    assign y[8]  = x[0]  ^ x[5];
    assign t[0]  = x[1]  ^ x[2];
    assign y[1]  = t[0]  ^ x[7];
    assign y[4]  = y[1]  ^ x[3];
    assign y[12] = y[13] ^ y[14];
    assign y[2]  = y[1]  ^ x[0];
    assign y[5]  = y[1]  ^ x[6];
    assign y[3]  = y[5]  ^ y[8];
    assign t[1]  = x[4]  ^ y[12];
    assign y[15] = t[1]  ^ x[5];
    assign y[20] = t[1]  ^ x[1];
    assign y[6]  = y[15] ^ x[7];
    assign y[10] = y[15] ^ t[0];
    assign y[11] = y[20] ^ y[9];
    assign y[7]  = x[7]  ^ y[11];
    assign y[17] = y[10] ^ y[11];
    assign y[19] = y[10] ^ y[8];
    assign y[16] = t[0]  ^ y[11];
    assign y[21] = y[13] ^ y[16];
    assign y[18] = x[0]  ^ y[16];

    assign t[2]  = y[12] & y[15];
    assign t[3]  = y[3]  & y[6];
    assign t[4]  = t[3]  ^ t[2];
    assign t[5]  = y[4]  & x[7];
    assign t[6]  = t[5]  ^ t[2];
    assign t[7]  = y[13] & y[16];
    assign t[8]  = y[5]  & y[1];
    assign t[9]  = t[8]  ^ t[7];
    assign t[10] = y[2]  & y[7];
    assign t[11] = t[10] ^ t[7];
    assign t[12] = y[9]  & y[11];
    assign t[13] = y[14] & y[17];
    assign t[14] = t[13] ^ t[12];
    assign t[15] = y[8]  & y[10];
    assign t[16] = t[15] ^ t[12];
    assign t[17] = t[4]  ^ t[14];
    assign t[18] = t[6]  ^ t[16];
    assign t[19] = t[9]  ^ t[14];
    assign t[20] = t[11] ^ t[16];
    assign t[21] = t[17] ^ y[20];
    assign t[22] = t[18] ^ y[19];
    assign t[23] = t[19] ^ y[21];
    assign t[24] = t[20] ^ y[18];

    assign t[25] = t[21] ^ t[22];
    assign t[26] = t[21] & t[23];
    assign t[27] = t[24] ^ t[26];
    assign t[28] = t[25] & t[27];
    assign t[29] = t[28] ^ t[22];
    assign t[30] = t[23] ^ t[24];
    assign t[31] = t[22] ^ t[26];
    assign t[32] = t[31] & t[30];
    assign t[33] = t[32] ^ t[24];
    assign t[34] = t[23] ^ t[33];
    assign t[35] = t[27] ^ t[33];
    assign t[36] = t[24] & t[35];
    assign t[37] = t[36] ^ t[34];
    assign t[38] = t[27] ^ t[36];
    assign t[39] = t[29] & t[38];
    assign t[40] = t[25] ^ t[39];

    assign t[41] = t[40] ^ t[37];
    assign t[42] = t[29] ^ t[33];
    assign t[43] = t[29] ^ t[40];
    assign t[44] = t[33] ^ t[37];
    assign t[45] = t[42] ^ t[41];
    assign z[0]  = t[44] & y[15];
    assign z[1]  = t[37] & y[6];
    assign z[2]  = t[33] & x[7];
    assign z[3]  = t[43] & y[16];
    assign z[4]  = t[40] & y[1];
    assign z[5]  = t[29] & y[7];
    assign z[6]  = t[42] & y[11];
    assign z[7]  = t[45] & y[17];
    assign z[8]  = t[41] & y[10];
    assign z[9]  = t[44] & y[12];
    assign z[10] = t[37] & y[3];
    assign z[11] = t[33] & y[4];
    assign z[12] = t[43] & y[13];
    assign z[13] = t[40] & y[5];
    assign z[14] = t[29] & y[2];
    assign z[15] = t[42] & y[9];
    assign z[16] = t[45] & y[14];
    assign z[17] = t[41] & y[8];

    assign t[46] = z[15] ^ z[16];
    assign t[47] = z[10] ^ z[11];
    assign t[48] = z[5]  ^ z[13];
    assign t[49] = z[9]  ^ z[10];
    assign t[50] = z[2]  ^ z[12];
    assign t[51] = z[2]  ^ z[5];
    assign t[52] = z[7]  ^ z[8];
    assign t[53] = z[0]  ^ z[3];
    assign t[54] = z[6]  ^ z[7];
    assign t[55] = z[16] ^ z[17];
    assign t[56] = z[12] ^ t[48];
    assign t[57] = t[50] ^ t[53];
    assign t[58] = z[4]  ^ t[46];
    assign t[59] = z[3]  ^ t[54];
    assign t[60] = t[46] ^ t[57];
    assign t[61] = z[14] ^ t[57];
    assign t[62] = t[52] ^ t[58];
    assign t[63] = t[49] ^ t[58];
    assign t[64] = z[4]  ^ t[59];
    assign t[65] = t[61] ^ t[62];
    assign t[66] = z[1]  ^ t[63];
    assign s[0]  = t[59] ^ t[63];
    assign s[6]  = ~t[56] ^ t[62];
    assign s[7]  = ~t[48] ^ t[60];
    assign t[67] = t[64]  ^ t[65];
    assign s[3]  = t[53]  ^ t[66];
    assign s[4]  = t[51]  ^ t[66];
    assign s[5]  = t[47]  ^ t[65];
    assign s[1]  = ~t[64] ^ s[3];
    assign s[2]  = ~t[55] ^ t[67];

    assign data_o = s;
endmodule

// ----------------------------------------------------------------------------
//  MixColumns helpers + mixw -- from mixw.v
// ----------------------------------------------------------------------------
module aes_gm2(
    input  [7:0] op_i,
    output [7:0] gm2_o
    );
    assign gm2_o = {op_i[6 : 0], 1'b0} ^ (8'h1b & {8{op_i[7]}});
endmodule

module aes_gm3(
    input  [7:0] op_i,
    output [7:0] gm3_o
    );
    wire [7:0] gm2;
    aes_gm2 m_gm2(.op_i(op_i), .gm2_o(gm2));
    assign gm3_o = gm2 ^ op_i;
endmodule

module mixw(
    input  [31:0] w_i,
    output [31:0] mixw_o
    );
    wire [7:0] b0, b1, b2, b3;
    wire [7:0] mb0, mb1, mb2, mb3;
    wire [7:0] gm2_b0, gm3_b1;
    wire [7:0] gm2_b1, gm3_b2;
    wire [7:0] gm2_b2, gm3_b3;
    wire [7:0] gm2_b3, gm3_b0;

    assign b3 = w_i[31 : 24];
    assign b2 = w_i[23 : 16];
    assign b1 = w_i[15 : 8];
    assign b0 = w_i[07 : 0];

    aes_gm2 m0_gm2(.op_i(b0), .gm2_o(gm2_b0));
    aes_gm3 m0_gm3(.op_i(b1), .gm3_o(gm3_b1));
    aes_gm2 m1_gm2(.op_i(b1), .gm2_o(gm2_b1));
    aes_gm3 m1_gm3(.op_i(b2), .gm3_o(gm3_b2));
    aes_gm2 m2_gm2(.op_i(b2), .gm2_o(gm2_b2));
    aes_gm3 m2_gm3(.op_i(b3), .gm3_o(gm3_b3));
    aes_gm3 m3_gm3(.op_i(b0), .gm3_o(gm3_b0));
    aes_gm2 m3_gm2(.op_i(b3), .gm2_o(gm2_b3));

    assign mb0 = gm2_b0  ^ gm3_b1  ^ b2      ^ b3;
    assign mb1 = b0      ^ gm2_b1  ^ gm3_b2  ^ b3;
    assign mb2 = b0      ^ b1      ^ gm2_b2  ^ gm3_b3;
    assign mb3 = gm3_b0  ^ b1      ^ b2      ^ gm2_b3;

    assign mixw_o = {mb3, mb2, mb1, mb0};
endmodule

// ----------------------------------------------------------------------------
//  Key schedule -- from ks.v
// ----------------------------------------------------------------------------
module aes_key_first_col(
    input  wire [31:0] key_w3_i,
    input  wire [7:0]  key_rcon_i,
    output wire [31:0] key_w3_next_o,
    output wire [7:0]  key_rcon_o
    );

    wire [31:0] key_rot;
    wire [31:0] key_sbox;
    wire [31:0] key_xor;
    wire [7:0]  rcon_next;
    wire [7:0]  debug_rcon_next;
    wire        rcon_overflow;

    assign key_rot[31:24] = key_w3_i[7:0];
    assign key_rot[23:16] = key_w3_i[31:24];
    assign key_rot[15:8]  = key_w3_i[23:16];
    assign key_rot[7:0]   = key_w3_i[15:8];

    genvar i;
    generate
        for(i=0; i<4; i=i+1) begin : loop_gen_key_sbox
            sbox m_key_sbox(
                .data_i(key_rot[(i*8)+7:(i*8)]),
                .data_o(key_sbox[(i*8)+7:(i*8)])
            );
        end
    endgenerate

    assign key_xor         = { key_sbox[31:8], key_sbox[7:0] ^ key_rcon_i };
    assign rcon_overflow   = key_rcon_i[7];
    assign rcon_next[7:0]  = { key_rcon_i[6:0], 1'b0} ;
    assign debug_rcon_next = ( {8{ rcon_overflow}} & 8'h1b )
                           | ( {8{~rcon_overflow}} & rcon_next);

    assign key_w3_next_o   = key_xor;
    assign key_rcon_o[7:0] = debug_rcon_next[7:0];
endmodule

module ks(
    input  wire [127:0] key_i,
    input  wire [7:0]   key_rcon_i,
    output wire [127:0] key_next_o,
    output wire [7:0]   key_rcon_o
    );
    wire [31:0] key_col[3:0];
    wire [31:0] key_col_w3;
    wire [31:0] key_col_next[3:0];
    wire [7:0]  key_rcon_next;

    genvar i;
    generate
        for(i=0; i<4; i=i+1) begin : loop_gen_key_col
            assign key_col[i] = key_i[(i*32)+31:(i*32)];
            assign key_next_o[(i*32)+31:(i*32)] = key_col_next[i];
        end
    endgenerate

    aes_key_first_col aes_key_w3(
        .key_w3_i(key_col[3]),
        .key_rcon_i(key_rcon_i),
        .key_w3_next_o(key_col_w3),
        .key_rcon_o(key_rcon_next)
    );
    assign key_col_next[0] = key_col[0] ^ key_col_w3;
    assign key_col_next[1] = key_col_next[0] ^ key_col[1];
    assign key_col_next[2] = key_col_next[1] ^ key_col[2];
    assign key_col_next[3] = key_col_next[2] ^ key_col[3];

    assign key_rcon_o = key_rcon_next;
endmodule

// ----------------------------------------------------------------------------
//  Top-level AES-128 encryptor -- from top.v  (DUT)
// ----------------------------------------------------------------------------
module aes(
    input clk,
    input nreset,

    input          data_v_i, // input valid
    input [127:0]  data_i,   // message to encode
    input [127:0]  key_i,    // key
    output         res_v_o,  // result valid
    output [127:0] res_o     // result
    );

    reg  [127:0] data_q;
    wire [127:0] data_next;

    reg  [3:0] fsm_q;
    wire [3:0] fsm_next;
    wire       fsm_en;
    wire       finished_v;
    wire       last_iter_v;
    wire       unused_fsm_sum_msb;

    wire [127:0] sub_bytes;
    wire [31:0]  sub_bytes_row[3:0];
    wire [127:0] shift_row;
    wire [31:0]  shift_row_row[3:0];
    wire [127:0] mix_columns;
    wire [127:0] round_key_next;
    wire [127:0] round_key;
    reg  [127:0] key_q;
    wire [127:0] key_next;
    wire [127:0] key_current;
    reg  [7:0]   key_rcon_q;
    wire [7:0]   key_rcon_next;
    wire [7:0]   key_rcon_current;

    assign fsm_en = |(fsm_q) | data_v_i;
    assign finished_v = fsm_q[3] & fsm_q[1] & fsm_q[0];
    assign {unused_fsm_sum_msb,fsm_next} = finished_v ? 5'b00000 : fsm_q + 4'b0001 ;
    assign last_iter_v = fsm_q[3] & fsm_q[1];

    always@(posedge clk)
    begin : fsm_dff
        if (!nreset)
            fsm_q <= 4'b0000;
        else
        if ( fsm_en )
            fsm_q <= fsm_next;
    end

    always @(posedge clk)
        begin : data_dff
         data_q <= data_next;
    end

    genvar sb_i;
    generate
        for (sb_i=0; sb_i<16; sb_i=sb_i+1) begin : loop_gen_sb_i
            sbox m_sbox(
                .data_i( data_q[(sb_i*8)+7:(sb_i*8)]),
                .data_o( sub_bytes[(sb_i*8)+7:(sb_i*8)])
                );
        end
    endgenerate

    genvar sr_r;
    generate
        for (sr_r=0; sr_r<4; sr_r=sr_r+1) begin : loop_gen_sr_r
            assign sub_bytes_row[sr_r] = { sub_bytes[3*32+8*sr_r+7:3*32+8*sr_r],
                                           sub_bytes[2*32+8*sr_r+7:2*32+8*sr_r],
                                           sub_bytes[32+8*sr_r+7:32+8*sr_r],
                                           sub_bytes[8*sr_r+7:8*sr_r] };
            assign { shift_row[3*32+8*sr_r+7:3*32+8*sr_r],
                     shift_row[2*32+8*sr_r+7:2*32+8*sr_r],
                     shift_row[1*32+8*sr_r+7:1*32+8*sr_r],
                     shift_row[0*32+8*sr_r+7:0*32+8*sr_r] } = shift_row_row[sr_r];
        end
    endgenerate

    assign shift_row_row[0]  =  sub_bytes_row[0];
    assign shift_row_row[3]  =  { sub_bytes_row[3][23:16], sub_bytes_row[3][15:8],  sub_bytes_row[3][7:0] ,  sub_bytes_row[3][31:24] };
    assign shift_row_row[2]  =  { sub_bytes_row[2][15:8],  sub_bytes_row[2][7:0],   sub_bytes_row[2][31:24], sub_bytes_row[2][23:16] };
    assign shift_row_row[1]  =  { sub_bytes_row[1][7:0] ,  sub_bytes_row[1][31:24], sub_bytes_row[1][23:16], sub_bytes_row[1][15:8] };

    genvar mc_c;
    generate
        for (mc_c=0; mc_c<4; mc_c=mc_c+1) begin : loop_gen_mc_c
            mixw m_mixw (
                .w_i(    shift_row[  mc_c*32+31:mc_c*32] ),
                .mixw_o( mix_columns[mc_c*32+31:mc_c*32])
            );
        end
    endgenerate

    assign round_key_next = data_v_i ? data_i :( last_iter_v ?  shift_row : mix_columns );
    assign round_key = round_key_next ^ key_current;
    assign data_next = round_key;

    assign key_current      = data_v_i ? key_i        : key_q;
    assign key_rcon_current = data_v_i ? 8'b0000_0001 : key_rcon_q;

    ks m_ks(
         .key_i     (key_current),
         .key_rcon_i(key_rcon_current),
         .key_next_o(key_next),
         .key_rcon_o(key_rcon_next)
                 );
     always @(posedge clk) begin
         if ( fsm_en ) begin : key_dff
            key_q      <= key_next;
            key_rcon_q <= key_rcon_next;
         end
     end

    assign res_v_o = finished_v;
    assign res_o   = data_q;
endmodule
