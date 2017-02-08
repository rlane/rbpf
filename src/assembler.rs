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

fn instruction_table() -> Vec<(String, u8)> {
    vec![("exit".to_string(), ebpf::BPF_EXIT),
         ("add64".to_string(), ebpf::BPF_ALU64 | ebpf::BPF_ADD)]
}

fn encode(opc: u8, operands: &Vec<Operand>) -> Result<Insn, String> {
    let mut opc: u8 = opc;
    let mut dst: u8 = 0;
    let mut src: u8 = 0;
    let mut imm: i32 = 0;
    let mut seen_dst = false;
    for operand in operands {
        match operand {
            &Operand::Register(x) => {
                if seen_dst {
                    src = x as u8;
                    opc |= ebpf::BPF_X;
                } else {
                    dst = x as u8;
                    seen_dst = true;
                }
            }
            &Operand::Integer(x) => imm = x as i32,
            _ => panic!("unexpected operand"),
        }
    }
    Ok(Insn {
        opc: opc,
        dst: dst,
        src: src,
        off: 0,
        imm: imm,
    })
}

fn assemble_one(instruction: &Instruction,
                instruction_map: &HashMap<String, u8>)
                -> Result<Insn, String> {
    match instruction_map.get(&instruction.name) {
        Some(opc) => encode(*opc, &instruction.operands),
        None => Err("Invalid instruction".to_string()),
    }
}

fn assemble_internal(instructions: &[Instruction]) -> Result<Vec<Insn>, String> {
    let instruction_map: HashMap<String, u8> = instruction_table().iter().cloned().collect();
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
