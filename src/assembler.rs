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
use self::InstructionType::{AluBinary, AluUnary, Memory, Jump, Misc};

#[derive(Clone, Copy, Debug, PartialEq)]
enum InstructionType {
    AluBinary,
    AluUnary,
    Memory,
    Jump,
    Misc,
}

fn instruction_table() -> Vec<(&'static str, (u8, InstructionType))> {
    vec![("exit", (ebpf::BPF_EXIT, Misc)), ("add64", (ebpf::BPF_ALU64 | ebpf::BPF_ADD, AluBinary))]
}

fn encode(opc: u8, inst_type: InstructionType, operands: &Vec<Operand>) -> Result<Insn, String> {
    match inst_type {
        AluBinary => {
            if operands.len() != 2 {
                return Err(format!("Expected 2 operands, got {:?}", operands));
            }
            match (operands[0], operands[1]) {
                (Operand::Register(dst), Operand::Register(src)) => {
                    Ok(Insn {
                        opc: opc | ebpf::BPF_X,
                        dst: dst as u8,
                        src: src as u8,
                        off: 0,
                        imm: 0,
                    })
                }
                (Operand::Register(dst), Operand::Integer(imm)) => {
                    Ok(Insn {
                        opc: opc | ebpf::BPF_K,
                        dst: dst as u8,
                        src: 0,
                        off: 0,
                        imm: imm as i32,
                    })
                }
                _ => Err(format!("Unexpected operands {:?}", operands)),
            }
        }
        Misc => {
            match opc {
                ebpf::BPF_EXIT => {
                    Ok(Insn {
                        opc: opc,
                        dst: 0,
                        src: 0,
                        off: 0,
                        imm: 0,
                    })
                }
                _ => Err(format!("Unexpected opcode {}", opc)),
            }
        }
        _ => Err(format!("Unexpected instruction type {:?}", inst_type)),
    }
}

fn assemble_one(instruction: &Instruction,
                instruction_map: &HashMap<&str, (u8, InstructionType)>)
                -> Result<Insn, String> {
    match instruction_map.get(instruction.name.as_str()) {
        Some(&(opc, inst_type)) => encode(opc, inst_type, &instruction.operands),
        None => Err("Invalid instruction".to_string()),
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
