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
use self::InstructionType::{AluBinary, AluUnary, Mem, Jump, NoOperand};
use asm_parser::Operand::{Integer, Memory, Register};

#[derive(Clone, Copy, Debug, PartialEq)]
enum InstructionType {
    AluBinary,
    AluUnary,
    Mem,
    Jump,
    NoOperand,
}

fn instruction_table() -> Vec<(&'static str, (u8, InstructionType))> {
    vec![("exit", (ebpf::BPF_EXIT, NoOperand)),
         ("add64", (ebpf::BPF_ALU64 | ebpf::BPF_ADD, AluBinary))]
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

fn encode_alu_binary(opc: u8, operands: &Vec<Operand>) -> Result<Insn, String> {
    if operands.len() != 2 {
        return Err(format!("Expected 2 operands, got {:?}", operands));
    }
    match (operands[0], operands[1]) {
        (Register(dst), Register(src)) => inst(opc | ebpf::BPF_X, dst, src, 0, 0),
        (Register(dst), Integer(imm)) => inst(opc | ebpf::BPF_K, dst, 0, 0, imm),
        _ => Err(format!("Unexpected operands {:?}", operands)),
    }
}

fn encode_no_operand(opc: u8, operands: &Vec<Operand>) -> Result<Insn, String> {
    if operands.len() != 0 {
        return Err(format!("Expected 0 operands, got {:?}", operands));
    }
    inst(opc, 0, 0, 0, 0)
}

fn assemble_one(instruction: &Instruction,
                instruction_map: &HashMap<&str, (u8, InstructionType)>)
                -> Result<Insn, String> {
    match instruction_map.get(instruction.name.as_str()) {
        Some(&(opc, inst_type)) => {
            match inst_type {
                AluBinary => encode_alu_binary(opc, &instruction.operands),
                NoOperand => encode_no_operand(opc, &instruction.operands),
                _ => Err(format!("Unexpected instruction type {:?}", inst_type)),
            }
        }
        None => Err(format!("Invalid instruction {:?}", &instruction.name)),
    }
}

fn assemble_internal(instructions: &[Instruction]) -> Result<Vec<Insn>, String> {
    let instruction_map: HashMap<&str, (u8, InstructionType)> =
        instruction_table().iter().cloned().collect();
    let mut result = vec![];
    for instruction in instructions {
        match assemble_one(instruction, &instruction_map) {
            Ok(insn) => result.push(insn),
            Err(msg) => return Err(msg),
        }
    }
    Ok(result)
}

/// XXX
pub fn assemble(src: &str) -> Result<Vec<Insn>, String> {
    assemble_internal(&try!(parse(src)))
}
