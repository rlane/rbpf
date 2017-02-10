// Copyright 2017 Rich Lane <lanerl@gmail.com>
//
// Licensed under the Apache License, Version 2.0 <http://www.apache.org/licenses/LICENSE-2.0> or
// the MIT license <http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.


//! This module translates eBPF assembly language to instructions.

use asm_parser::{Instruction, Operand, parse};
use ebpf;
use ebpf::Insn;
use std::collections::HashMap;
use self::InstructionType::{AluBinary, AluUnary, Load, StoreImm, StoreReg, JumpUnconditional,
                            JumpConditional, Call, Endian, NoOperand};
use asm_parser::Operand::{Integer, Memory, Register, Nil};

#[derive(Clone, Copy, Debug, PartialEq)]
enum InstructionType {
    NoOperand,
    AluBinary,
    AluUnary,
    Load,
    StoreImm,
    StoreReg,
    JumpUnconditional,
    JumpConditional,
    Call,
    Endian(i64),
}

fn make_instruction_map() -> HashMap<String, (InstructionType, u8)> {
    let mut result = HashMap::new();

    let alu_binary_ops = [("add", ebpf::BPF_ADD),
                          ("sub", ebpf::BPF_SUB),
                          ("mul", ebpf::BPF_MUL),
                          ("div", ebpf::BPF_DIV),
                          ("or", ebpf::BPF_OR),
                          ("and", ebpf::BPF_AND),
                          ("lsh", ebpf::BPF_LSH),
                          ("rsh", ebpf::BPF_RSH),
                          ("mod", ebpf::BPF_MOD),
                          ("xor", ebpf::BPF_XOR),
                          ("mov", ebpf::BPF_MOV),
                          ("arsh", ebpf::BPF_ARSH)];

    let mem_sizes =
        [("w", ebpf::BPF_W), ("h", ebpf::BPF_H), ("b", ebpf::BPF_B), ("dw", ebpf::BPF_DW)];

    let jump_conditions = [("jeq", ebpf::BPF_JEQ),
                           ("jgt", ebpf::BPF_JGT),
                           ("jge", ebpf::BPF_JGE),
                           ("jset", ebpf::BPF_JSET),
                           ("jne", ebpf::BPF_JNE),
                           ("jsgt", ebpf::BPF_JSGT),
                           ("jsge", ebpf::BPF_JSGE)];

    {
        let mut entry = |name: &str, inst_type: InstructionType, opc: u8| {
            result.insert(name.to_string(), (inst_type, opc))
        };

        // Miscellaneous.
        entry("exit", NoOperand, ebpf::BPF_EXIT);
        entry("ja", JumpUnconditional, ebpf::JA);
        entry("call", Call, ebpf::CALL);

        // AluUnary.
        entry("neg", AluUnary, ebpf::NEG64);
        entry("neg32", AluUnary, ebpf::NEG32);
        entry("neg64", AluUnary, ebpf::NEG64);

        // AluBinary.
        for &(name, opc) in alu_binary_ops.iter() {
            entry(name, AluBinary, ebpf::BPF_ALU64 | opc);
            entry(&format!("{}32", name), AluBinary, ebpf::BPF_ALU | opc);
            entry(&format!("{}64", name), AluBinary, ebpf::BPF_ALU64 | opc);
        }

        // Load, StoreImm, and StoreReg.
        for &(suffix, size) in mem_sizes.iter() {
            entry(&format!("ldx{}", suffix),
                  Load,
                  ebpf::BPF_MEM | ebpf::BPF_LDX | size);
            entry(&format!("st{}", suffix),
                  StoreImm,
                  ebpf::BPF_MEM | ebpf::BPF_ST | size);
            entry(&format!("stx{}", suffix),
                  StoreReg,
                  ebpf::BPF_MEM | ebpf::BPF_STX | size);
        }

        // JumpConditional.
        for &(name, condition) in jump_conditions.iter() {
            entry(name, JumpConditional, ebpf::BPF_JMP | condition);
        }

        // Endian.
        for &size in [16, 32, 64].iter() {
            entry(&format!("be{}", size), Endian(size), ebpf::BE);
            entry(&format!("le{}", size), Endian(size), ebpf::LE);
        }
    }

    result
}

fn inst(opc: u8, dst: i64, src: i64, off: i64, imm: i64) -> Result<Insn, String> {
    Ok(Insn {
        opc: opc,
        dst: dst as u8,
        src: src as u8,
        off: off as i16,
        imm: imm as i32,
    })
}

// TODO Use slice patterns when available.
fn operands_tuple(operands: &Vec<Operand>) -> (Operand, Operand, Operand) {
    match operands.len() {
        0 => (Nil, Nil, Nil),
        1 => (operands[0], Nil, Nil),
        2 => (operands[0], operands[1], Nil),
        3 => (operands[0], operands[1], operands[2]),
        _ => (Nil, Nil, Nil), // XXX
    }
}

fn encode_all(opc: u8,
              inst_type: InstructionType,
              operands: &Vec<Operand>)
              -> Result<Insn, String> {
    let (a, b, c) = operands_tuple(operands);
    match (inst_type, a, b, c) {
        (AluBinary, Register(dst), Register(src), Nil) => inst(opc | ebpf::BPF_X, dst, src, 0, 0),
        (AluBinary, Register(dst), Integer(imm), Nil) => inst(opc | ebpf::BPF_K, dst, 0, 0, imm),
        (AluUnary, Register(dst), Nil, Nil) => inst(opc, dst, 0, 0, 0),
        (Load, Register(dst), Memory(src, off), Nil) => inst(opc, dst, src, off, 0),
        (StoreImm, Memory(dst, off), Integer(imm), Nil) => inst(opc, dst, 0, off, imm),
        (StoreReg, Memory(dst, off), Register(src), Nil) => inst(opc, dst, src, off, 0),
        (NoOperand, Nil, Nil, Nil) => inst(opc, 0, 0, 0, 0),
        (JumpUnconditional, Integer(off), Nil, Nil) => inst(opc, 0, 0, off, 0),
        (JumpConditional, Register(dst), Register(src), Integer(off)) => {
            inst(opc | ebpf::BPF_X, dst, src, off, 0)
        }
        (JumpConditional, Register(dst), Integer(imm), Integer(off)) => {
            inst(opc | ebpf::BPF_K, dst, 0, off, imm)
        }
        (Call, Integer(imm), Nil, Nil) => inst(opc, 0, 0, 0, imm),
        (Endian(size), Register(dst), Nil, Nil) => inst(opc, dst, 0, 0, size),
        _ => Err(format!("Unexpected operands: {:?}", operands)),
    }
}

fn assemble_internal(instructions: &[Instruction]) -> Result<Vec<Insn>, String> {
    let instruction_map = make_instruction_map();
    let mut result = vec![];
    for instruction in instructions {
        match instruction_map.get(instruction.name.as_str()) {
            Some(&(inst_type, opc)) => {
                match encode_all(opc, inst_type, &instruction.operands) {
                    Ok(insn) => result.push(insn),
                    Err(msg) => return Err(msg),
                }
            }
            None => return Err(format!("Invalid instruction {:?}", &instruction.name)),
        }
    }
    Ok(result)
}

/// XXX
pub fn assemble(src: &str) -> Result<Vec<Insn>, String> {
    assemble_internal(&try!(parse(src)))
}
