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
use self::InstructionType::{AluBinary, AluUnary, Load, StoreImm, StoreReg, Jump, NoOperand};
use asm_parser::Operand::{Integer, Memory, Register, Nil};

#[derive(Clone, Copy, Debug, PartialEq)]
enum InstructionType {
    AluBinary,
    AluUnary,
    Load,
    StoreImm,
    StoreReg,
    Jump,
    NoOperand,
}

fn instruction_table() -> Vec<(&'static str, (u8, InstructionType))> {
    vec![("exit", (ebpf::BPF_EXIT, NoOperand)),
         ("add64", (ebpf::BPF_ALU64 | ebpf::BPF_ADD, AluBinary)),
         ("neg64", (ebpf::BPF_ALU64 | ebpf::BPF_NEG, AluUnary)),
         ("ldxw", (ebpf::LD_W_REG, Load)),
         ("stw", (ebpf::ST_W_IMM, StoreImm)),
         ("stxw", (ebpf::ST_W_REG, StoreReg))]
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

fn operands_tuple(operands: &Vec<Operand>) -> (Operand, Operand) {
    match operands.len() {
        0 => (Nil, Nil),
        1 => (operands[0], Nil),
        2 => (operands[0], operands[1]),
        _ => (Nil, Nil), // XXX
    }
}

fn encode_all(opc: u8,
              inst_type: InstructionType,
              operands: &Vec<Operand>)
              -> Result<Insn, String> {
    let (a, b) = operands_tuple(operands);
    match (inst_type, a, b) {
        (AluBinary, Register(dst), Register(src)) => inst(opc | ebpf::BPF_X, dst, src, 0, 0),
        (AluBinary, Register(dst), Integer(imm)) => inst(opc | ebpf::BPF_K, dst, 0, 0, imm),
        (AluUnary, Register(dst), Nil) => inst(opc, dst, 0, 0, 0),
        (Load, Register(dst), Memory(src, off)) => inst(opc, dst, src, off, 0),
        (StoreImm, Memory(dst, off), Integer(imm)) => inst(opc, dst, 0, off, imm),
        (StoreReg, Memory(dst, off), Register(src)) => inst(opc, dst, src, off, 0),
        (NoOperand, Nil, Nil) => inst(opc, 0, 0, 0, 0),
        _ => Err(format!("Unexpected operands: {:?}", operands)),
    }
}

fn assemble_internal(instructions: &[Instruction]) -> Result<Vec<Insn>, String> {
    let instruction_map: HashMap<&str, (u8, InstructionType)> =
        instruction_table().iter().cloned().collect();
    let mut result = vec![];
    for instruction in instructions {
        match instruction_map.get(instruction.name.as_str()) {
            Some(&(opc, inst_type)) => {
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
