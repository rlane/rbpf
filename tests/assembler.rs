// Copyright 2017 Rich Lane <lanerl@gmail.com>
//
// Licensed under the Apache License, Version 2.0 <http://www.apache.org/licenses/LICENSE-2.0> or
// the MIT license <http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.
extern crate rbpf;

use rbpf::assembler::assemble;
use rbpf::ebpf;

fn insn(opc: u8, dst: u8, src: u8, off: i16, imm: i32) -> ebpf::Insn {
    ebpf::Insn {
        opc: opc,
        dst: dst,
        src: src,
        off: off,
        imm: imm,
    }
}

#[test]
fn test_empty() {
    assert_eq!(assemble(""), Ok(vec![]));
}

// Example for InstructionType::NoOperand.
#[test]
fn test_exit() {
    assert_eq!(assemble("exit"), Ok(vec![insn(ebpf::BPF_EXIT, 0, 0, 0, 0)]));
}

// Example for InstructionType::AluBinary.
#[test]
fn test_add64() {
    assert_eq!(assemble("add64 r1, r3"),
               Ok(vec![insn(ebpf::ADD64_REG, 1, 3, 0, 0)]));
    assert_eq!(assemble("add64 r1, 5"),
               Ok(vec![insn(ebpf::ADD64_IMM, 1, 0, 0, 5)]));
}

// Example for InstructionType::AluUnary.
#[test]
fn test_neg64() {
    assert_eq!(assemble("neg64 r1"),
               Ok(vec![insn(ebpf::NEG64, 1, 0, 0, 0)]));
}

// Example for InstructionType::Load.
#[test]
fn test_ldxw() {
    assert_eq!(assemble("ldxw r1, [r2+5]"),
               Ok(vec![insn(ebpf::LD_W_REG, 1, 2, 5, 0)]));
}

// Example for InstructionType::StoreImm.
#[test]
fn test_stw() {
    assert_eq!(assemble("stw [r2+5], 7"),
               Ok(vec![insn(ebpf::ST_W_IMM, 2, 0, 5, 7)]));
}

// Example for InstructionType::StoreReg.
#[test]
fn test_stxw() {
    assert_eq!(assemble("stxw [r2+5], r8"),
               Ok(vec![insn(ebpf::ST_W_REG, 2, 8, 5, 0)]));
}

// Example for InstructionType::JumpUnconditional.
#[test]
fn test_ja() {
    assert_eq!(assemble("ja +8"), Ok(vec![insn(ebpf::JA, 0, 0, 8, 0)]));
    assert_eq!(assemble("ja -3"), Ok(vec![insn(ebpf::JA, 0, 0, -3, 0)]));
}

// Example for InstructionType::JumpConditional.
#[test]
fn test_jeq() {
    assert_eq!(assemble("jeq r1, 4, +8"),
               Ok(vec![insn(ebpf::JEQ_IMM, 1, 0, 8, 4)]));
    assert_eq!(assemble("jeq r1, r3, +8"),
               Ok(vec![insn(ebpf::JEQ_REG, 1, 3, 8, 0)]));
}

// Example for InstructionType::Call.
#[test]
fn test_call() {
    assert_eq!(assemble("call 300"),
               Ok(vec![insn(ebpf::CALL, 0, 0, 0, 300)]));
}

// Example for InstructionType::Endian.
#[test]
fn test_be32() {
    assert_eq!(assemble("be32 r1"), Ok(vec![insn(ebpf::BE, 1, 0, 0, 32)]));
}

// Example for InstructionType::Load.
#[test]
fn test_ldxdw() {
    assert_eq!(assemble("ldxdw r1, [r2+3]"),
               Ok(vec![insn(ebpf::LD_DW_REG, 1, 2, 3, 0)]));
}

// Example for InstructionType::StoreImm.
#[test]
fn test_sth() {
    assert_eq!(assemble("sth [r1+2], 3"),
               Ok(vec![insn(ebpf::ST_H_IMM, 1, 0, 2, 3)]));
}

// Example for InstructionType::StoreReg.
#[test]
fn test_stxh() {
    assert_eq!(assemble("stxh [r1+2], r3"),
               Ok(vec![insn(ebpf::ST_H_REG, 1, 3, 2, 0)]));
}

// Test all supported AluBinary mnemonics.
#[test]
fn test_alu_binary() {
    assert_eq!(assemble("add r1, r2
                         sub r1, r2
                         mul r1, r2
                         div r1, r2
                         or r1, r2
                         and r1, r2
                         lsh r1, r2
                         rsh r1, r2
                         mod r1, r2
                         xor r1, r2
                         mov r1, r2
                         arsh r1, r2"),
               Ok(vec![insn(ebpf::ADD64_REG, 1, 2, 0, 0),
                       insn(ebpf::SUB64_REG, 1, 2, 0, 0),
                       insn(ebpf::MUL64_REG, 1, 2, 0, 0),
                       insn(ebpf::DIV64_REG, 1, 2, 0, 0),
                       insn(ebpf::OR64_REG, 1, 2, 0, 0),
                       insn(ebpf::AND64_REG, 1, 2, 0, 0),
                       insn(ebpf::LSH64_REG, 1, 2, 0, 0),
                       insn(ebpf::RSH64_REG, 1, 2, 0, 0),
                       insn(ebpf::MOD64_REG, 1, 2, 0, 0),
                       insn(ebpf::XOR64_REG, 1, 2, 0, 0),
                       insn(ebpf::MOV64_REG, 1, 2, 0, 0),
                       insn(ebpf::ARSH64_REG, 1, 2, 0, 0)]));

    assert_eq!(assemble("add r1, 2
                         sub r1, 2
                         mul r1, 2
                         div r1, 2
                         or r1, 2
                         and r1, 2
                         lsh r1, 2
                         rsh r1, 2
                         mod r1, 2
                         xor r1, 2
                         mov r1, 2
                         arsh r1, 2"),
               Ok(vec![insn(ebpf::ADD64_IMM, 1, 0, 0, 2),
                       insn(ebpf::SUB64_IMM, 1, 0, 0, 2),
                       insn(ebpf::MUL64_IMM, 1, 0, 0, 2),
                       insn(ebpf::DIV64_IMM, 1, 0, 0, 2),
                       insn(ebpf::OR64_IMM, 1, 0, 0, 2),
                       insn(ebpf::AND64_IMM, 1, 0, 0, 2),
                       insn(ebpf::LSH64_IMM, 1, 0, 0, 2),
                       insn(ebpf::RSH64_IMM, 1, 0, 0, 2),
                       insn(ebpf::MOD64_IMM, 1, 0, 0, 2),
                       insn(ebpf::XOR64_IMM, 1, 0, 0, 2),
                       insn(ebpf::MOV64_IMM, 1, 0, 0, 2),
                       insn(ebpf::ARSH64_IMM, 1, 0, 0, 2)]));

    assert_eq!(assemble("add64 r1, r2
                         sub64 r1, r2
                         mul64 r1, r2
                         div64 r1, r2
                         or64 r1, r2
                         and64 r1, r2
                         lsh64 r1, r2
                         rsh64 r1, r2
                         mod64 r1, r2
                         xor64 r1, r2
                         mov64 r1, r2
                         arsh64 r1, r2"),
               Ok(vec![insn(ebpf::ADD64_REG, 1, 2, 0, 0),
                       insn(ebpf::SUB64_REG, 1, 2, 0, 0),
                       insn(ebpf::MUL64_REG, 1, 2, 0, 0),
                       insn(ebpf::DIV64_REG, 1, 2, 0, 0),
                       insn(ebpf::OR64_REG, 1, 2, 0, 0),
                       insn(ebpf::AND64_REG, 1, 2, 0, 0),
                       insn(ebpf::LSH64_REG, 1, 2, 0, 0),
                       insn(ebpf::RSH64_REG, 1, 2, 0, 0),
                       insn(ebpf::MOD64_REG, 1, 2, 0, 0),
                       insn(ebpf::XOR64_REG, 1, 2, 0, 0),
                       insn(ebpf::MOV64_REG, 1, 2, 0, 0),
                       insn(ebpf::ARSH64_REG, 1, 2, 0, 0)]));

    assert_eq!(assemble("add64 r1, 2
                         sub64 r1, 2
                         mul64 r1, 2
                         div64 r1, 2
                         or64 r1, 2
                         and64 r1, 2
                         lsh64 r1, 2
                         rsh64 r1, 2
                         mod64 r1, 2
                         xor64 r1, 2
                         mov64 r1, 2
                         arsh64 r1, 2"),
               Ok(vec![insn(ebpf::ADD64_IMM, 1, 0, 0, 2),
                       insn(ebpf::SUB64_IMM, 1, 0, 0, 2),
                       insn(ebpf::MUL64_IMM, 1, 0, 0, 2),
                       insn(ebpf::DIV64_IMM, 1, 0, 0, 2),
                       insn(ebpf::OR64_IMM, 1, 0, 0, 2),
                       insn(ebpf::AND64_IMM, 1, 0, 0, 2),
                       insn(ebpf::LSH64_IMM, 1, 0, 0, 2),
                       insn(ebpf::RSH64_IMM, 1, 0, 0, 2),
                       insn(ebpf::MOD64_IMM, 1, 0, 0, 2),
                       insn(ebpf::XOR64_IMM, 1, 0, 0, 2),
                       insn(ebpf::MOV64_IMM, 1, 0, 0, 2),
                       insn(ebpf::ARSH64_IMM, 1, 0, 0, 2)]));

    assert_eq!(assemble("add32 r1, r2
                         sub32 r1, r2
                         mul32 r1, r2
                         div32 r1, r2
                         or32 r1, r2
                         and32 r1, r2
                         lsh32 r1, r2
                         rsh32 r1, r2
                         mod32 r1, r2
                         xor32 r1, r2
                         mov32 r1, r2
                         arsh32 r1, r2"),
               Ok(vec![insn(ebpf::ADD32_REG, 1, 2, 0, 0),
                       insn(ebpf::SUB32_REG, 1, 2, 0, 0),
                       insn(ebpf::MUL32_REG, 1, 2, 0, 0),
                       insn(ebpf::DIV32_REG, 1, 2, 0, 0),
                       insn(ebpf::OR32_REG, 1, 2, 0, 0),
                       insn(ebpf::AND32_REG, 1, 2, 0, 0),
                       insn(ebpf::LSH32_REG, 1, 2, 0, 0),
                       insn(ebpf::RSH32_REG, 1, 2, 0, 0),
                       insn(ebpf::MOD32_REG, 1, 2, 0, 0),
                       insn(ebpf::XOR32_REG, 1, 2, 0, 0),
                       insn(ebpf::MOV32_REG, 1, 2, 0, 0),
                       insn(ebpf::ARSH32_REG, 1, 2, 0, 0)]));

    assert_eq!(assemble("add32 r1, 2
                         sub32 r1, 2
                         mul32 r1, 2
                         div32 r1, 2
                         or32 r1, 2
                         and32 r1, 2
                         lsh32 r1, 2
                         rsh32 r1, 2
                         mod32 r1, 2
                         xor32 r1, 2
                         mov32 r1, 2
                         arsh32 r1, 2"),
               Ok(vec![insn(ebpf::ADD32_IMM, 1, 0, 0, 2),
                       insn(ebpf::SUB32_IMM, 1, 0, 0, 2),
                       insn(ebpf::MUL32_IMM, 1, 0, 0, 2),
                       insn(ebpf::DIV32_IMM, 1, 0, 0, 2),
                       insn(ebpf::OR32_IMM, 1, 0, 0, 2),
                       insn(ebpf::AND32_IMM, 1, 0, 0, 2),
                       insn(ebpf::LSH32_IMM, 1, 0, 0, 2),
                       insn(ebpf::RSH32_IMM, 1, 0, 0, 2),
                       insn(ebpf::MOD32_IMM, 1, 0, 0, 2),
                       insn(ebpf::XOR32_IMM, 1, 0, 0, 2),
                       insn(ebpf::MOV32_IMM, 1, 0, 0, 2),
                       insn(ebpf::ARSH32_IMM, 1, 0, 0, 2)]));
}

// Test all supported Load mnemonics.
#[test]
fn test_load() {
    assert_eq!(assemble("ldxw r1, [r2+3]
                         ldxh r1, [r2+3]
                         ldxb r1, [r2+3]
                         ldxdw r1, [r2+3]"),
               Ok(vec![insn(ebpf::LD_W_REG, 1, 2, 3, 0),
                       insn(ebpf::LD_H_REG, 1, 2, 3, 0),
                       insn(ebpf::LD_B_REG, 1, 2, 3, 0),
                       insn(ebpf::LD_DW_REG, 1, 2, 3, 0)]));
}

// Test all supported StoreImm mnemonics.
#[test]
fn test_store_imm() {
    assert_eq!(assemble("stw [r1+2], 3
                         sth [r1+2], 3
                         stb [r1+2], 3
                         stdw [r1+2], 3"),
               Ok(vec![insn(ebpf::ST_W_IMM, 1, 0, 2, 3),
                       insn(ebpf::ST_H_IMM, 1, 0, 2, 3),
                       insn(ebpf::ST_B_IMM, 1, 0, 2, 3),
                       insn(ebpf::ST_DW_IMM, 1, 0, 2, 3)]));
}

// Test all supported StoreReg mnemonics.
#[test]
fn test_store_reg() {
    assert_eq!(assemble("stxw [r1+2], r3
                         stxh [r1+2], r3
                         stxb [r1+2], r3
                         stxdw [r1+2], r3"),
               Ok(vec![insn(ebpf::ST_W_REG, 1, 3, 2, 0),
                       insn(ebpf::ST_H_REG, 1, 3, 2, 0),
                       insn(ebpf::ST_B_REG, 1, 3, 2, 0),
                       insn(ebpf::ST_DW_REG, 1, 3, 2, 0)]));
}

// Test all supported JumpConditional mnemonics.
#[test]
fn test_jump_conditional() {
    assert_eq!(assemble("jeq r1, r2, +3
                         jgt r1, r2, +3
                         jge r1, r2, +3
                         jset r1, r2, +3
                         jne r1, r2, +3
                         jsgt r1, r2, +3
                         jsge r1, r2, +3"),
               Ok(vec![insn(ebpf::JEQ_REG, 1, 2, 3, 0),
                       insn(ebpf::JGT_REG, 1, 2, 3, 0),
                       insn(ebpf::JGE_REG, 1, 2, 3, 0),
                       insn(ebpf::JSET_REG, 1, 2, 3, 0),
                       insn(ebpf::JNE_REG, 1, 2, 3, 0),
                       insn(ebpf::JSGT_REG, 1, 2, 3, 0),
                       insn(ebpf::JSGE_REG, 1, 2, 3, 0)]));

    assert_eq!(assemble("jeq r1, 2, +3
                         jgt r1, 2, +3
                         jge r1, 2, +3
                         jset r1, 2, +3
                         jne r1, 2, +3
                         jsgt r1, 2, +3
                         jsge r1, 2, +3"),
               Ok(vec![insn(ebpf::JEQ_IMM, 1, 0, 3, 2),
                       insn(ebpf::JGT_IMM, 1, 0, 3, 2),
                       insn(ebpf::JGE_IMM, 1, 0, 3, 2),
                       insn(ebpf::JSET_IMM, 1, 0, 3, 2),
                       insn(ebpf::JNE_IMM, 1, 0, 3, 2),
                       insn(ebpf::JSGT_IMM, 1, 0, 3, 2),
                       insn(ebpf::JSGE_IMM, 1, 0, 3, 2)]));
}