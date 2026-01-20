//! x86-64 instruction semantics for emulation.

use crate::flags::ConditionCode;
use crate::state::{x86_regs, MachineState};
use crate::value::Value;
use crate::{EmulationError, EmulationResult};
use hexray_core::{Instruction, MemoryRef, Operand, Operation};

/// Execute an x86-64 instruction on the given state.
pub fn execute(state: &mut MachineState, inst: &Instruction) -> EmulationResult<()> {
    match inst.operation {
        Operation::Move => execute_mov(state, inst),
        Operation::Load => execute_mov(state, inst), // Treat as mov for now
        Operation::Store => execute_store(state, inst),
        Operation::LoadEffectiveAddress => execute_lea(state, inst),
        Operation::Add => execute_add(state, inst),
        Operation::Sub => execute_sub(state, inst),
        Operation::Mul => execute_mul(state, inst),
        Operation::And => execute_and(state, inst),
        Operation::Or => execute_or(state, inst),
        Operation::Xor => execute_xor(state, inst),
        Operation::Not => execute_not(state, inst),
        Operation::Neg => execute_neg(state, inst),
        Operation::Shl => execute_shl(state, inst),
        Operation::Shr => execute_shr(state, inst),
        Operation::Sar => execute_sar(state, inst),
        Operation::Inc => execute_inc(state, inst),
        Operation::Dec => execute_dec(state, inst),
        Operation::Compare => execute_cmp(state, inst),
        Operation::Test => execute_test(state, inst),
        Operation::Push => execute_push(state, inst),
        Operation::Pop => execute_pop(state, inst),
        Operation::Jump => execute_jmp(state, inst),
        Operation::ConditionalJump => execute_jcc(state, inst),
        Operation::Call => execute_call(state, inst),
        Operation::Return => execute_ret(state, inst),
        Operation::Nop => Ok(()), // No operation
        _ => {
            // Handle setcc and cmov by checking the mnemonic
            let mnemonic = inst.mnemonic.to_lowercase();
            if mnemonic.starts_with("set") {
                execute_setcc(state, inst)
            } else if mnemonic.starts_with("cmov") {
                execute_cmov(state, inst)
            } else {
                // For unsupported operations, just advance PC
                // This allows partial emulation
                Ok(())
            }
        }
    }
}

/// Get the size in bits for an operand.
fn operand_size(op: &Operand) -> u32 {
    match op {
        // Register.size is already in bits
        Operand::Register(reg) => reg.size as u32,
        // MemoryRef.size is in bytes, convert to bits
        Operand::Memory(mem) => (mem.size as u32) * 8,
        Operand::Immediate(_) => 64,
        Operand::PcRelative { .. } => 64,
    }
}

/// Read a value from an operand.
fn read_operand(state: &MachineState, op: &Operand, inst: &Instruction) -> Value {
    match op {
        Operand::Register(reg) => {
            let full = state.get_register(reg.id);
            // reg.size is in bits
            match reg.size {
                8 => full.trunc(8),
                16 => full.trunc(16),
                32 => full.trunc(32),
                _ => full, // 64-bit or larger
            }
        }
        Operand::Memory(mem) => {
            let addr = compute_effective_address(state, mem, inst);
            match addr {
                Value::Concrete(a) => match mem.size {
                    1 => state.memory.read_u8(a),
                    2 => state.memory.read_u16(a),
                    4 => state.memory.read_u32(a),
                    8 => state.memory.read_u64(a),
                    _ => Value::Unknown,
                },
                _ => Value::Unknown,
            }
        }
        Operand::Immediate(imm) => Value::Concrete(imm.as_u64()),
        Operand::PcRelative { target, .. } => {
            // PC-relative addressing - use the pre-computed target
            Value::Concrete(*target)
        }
    }
}

/// Write a value to an operand.
fn write_operand(state: &mut MachineState, op: &Operand, value: Value, inst: &Instruction) {
    match op {
        // reg.size is in bits
        Operand::Register(reg) => match reg.size {
            8 => state.set_register_8l(reg.id, value),
            16 => state.set_register_16(reg.id, value),
            32 => state.set_register_32(reg.id, value),
            _ => state.set_register(reg.id, value), // 64-bit or larger
        },
        Operand::Memory(mem) => {
            let addr = compute_effective_address(state, mem, inst);
            if let Value::Concrete(a) = addr {
                match mem.size {
                    1 => state.memory.write_u8(a, value),
                    2 => state.memory.write_u16(a, value),
                    4 => state.memory.write_u32(a, value),
                    8 => state.memory.write_u64(a, value),
                    _ => {}
                }
            }
        }
        _ => {} // Can't write to immediates or PC-relative
    }
}

/// Compute effective address for a memory operand.
fn compute_effective_address(state: &MachineState, mem: &MemoryRef, inst: &Instruction) -> Value {
    let mut addr = Value::Concrete(0);

    // Base register
    if let Some(ref base) = mem.base {
        let base_val = state.get_register(base.id);
        addr = addr.add(&base_val);
    }

    // Index register with scale
    if let Some(ref index) = mem.index {
        let index_val = state.get_register(index.id);
        let scaled = index_val.mul(&Value::Concrete(mem.scale as u64));
        addr = addr.add(&scaled);
    }

    // Displacement
    if mem.displacement != 0 {
        addr = addr.add(&Value::Concrete(mem.displacement as u64));
    }

    // RIP-relative addressing
    if mem.base.as_ref().map(|b| b.id) == Some(x86_regs::RIP) {
        // For RIP-relative, the base is the address after the instruction
        let rip = inst.address + inst.size as u64;
        addr = Value::Concrete(rip).add(&Value::Concrete(mem.displacement as u64));
    }

    addr
}

// ==================== Instruction Implementations ====================

fn execute_mov(state: &mut MachineState, inst: &Instruction) -> EmulationResult<()> {
    if inst.operands.len() < 2 {
        return Ok(());
    }
    let src = read_operand(state, &inst.operands[1], inst);
    write_operand(state, &inst.operands[0], src, inst);
    Ok(())
}

fn execute_store(state: &mut MachineState, inst: &Instruction) -> EmulationResult<()> {
    if inst.operands.len() < 2 {
        return Ok(());
    }
    let src = read_operand(state, &inst.operands[0], inst);
    write_operand(state, &inst.operands[1], src, inst);
    Ok(())
}

fn execute_lea(state: &mut MachineState, inst: &Instruction) -> EmulationResult<()> {
    if inst.operands.len() < 2 {
        return Ok(());
    }
    if let Operand::Memory(ref mem) = inst.operands[1] {
        let addr = compute_effective_address(state, mem, inst);
        write_operand(state, &inst.operands[0], addr, inst);
    }
    Ok(())
}

fn execute_add(state: &mut MachineState, inst: &Instruction) -> EmulationResult<()> {
    if inst.operands.len() < 2 {
        return Ok(());
    }
    let size = operand_size(&inst.operands[0]);
    let a = read_operand(state, &inst.operands[0], inst);
    let b = read_operand(state, &inst.operands[1], inst);
    let result = a.add(&b);

    if let (Value::Concrete(av), Value::Concrete(bv), Value::Concrete(rv)) =
        (&a, &b, &result)
    {
        state.flags.update_add(*av, *bv, *rv, size);
    }

    write_operand(state, &inst.operands[0], result, inst);
    Ok(())
}

fn execute_sub(state: &mut MachineState, inst: &Instruction) -> EmulationResult<()> {
    if inst.operands.len() < 2 {
        return Ok(());
    }
    let size = operand_size(&inst.operands[0]);
    let a = read_operand(state, &inst.operands[0], inst);
    let b = read_operand(state, &inst.operands[1], inst);
    let result = a.sub(&b);

    if let (Value::Concrete(av), Value::Concrete(bv), Value::Concrete(rv)) =
        (&a, &b, &result)
    {
        state.flags.update_sub(*av, *bv, *rv, size);
    }

    write_operand(state, &inst.operands[0], result, inst);
    Ok(())
}

fn execute_mul(state: &mut MachineState, inst: &Instruction) -> EmulationResult<()> {
    if inst.operands.len() < 2 {
        return Ok(());
    }
    let a = read_operand(state, &inst.operands[0], inst);
    let b = read_operand(state, &inst.operands[1], inst);
    let result = a.mul(&b);
    write_operand(state, &inst.operands[0], result, inst);
    Ok(())
}

fn execute_and(state: &mut MachineState, inst: &Instruction) -> EmulationResult<()> {
    if inst.operands.len() < 2 {
        return Ok(());
    }
    let size = operand_size(&inst.operands[0]);
    let a = read_operand(state, &inst.operands[0], inst);
    let b = read_operand(state, &inst.operands[1], inst);
    let result = a.and(&b);

    if let Value::Concrete(rv) = &result {
        state.flags.update_logic(*rv, size);
    }

    write_operand(state, &inst.operands[0], result, inst);
    Ok(())
}

fn execute_or(state: &mut MachineState, inst: &Instruction) -> EmulationResult<()> {
    if inst.operands.len() < 2 {
        return Ok(());
    }
    let size = operand_size(&inst.operands[0]);
    let a = read_operand(state, &inst.operands[0], inst);
    let b = read_operand(state, &inst.operands[1], inst);
    let result = a.or(&b);

    if let Value::Concrete(rv) = &result {
        state.flags.update_logic(*rv, size);
    }

    write_operand(state, &inst.operands[0], result, inst);
    Ok(())
}

fn execute_xor(state: &mut MachineState, inst: &Instruction) -> EmulationResult<()> {
    if inst.operands.len() < 2 {
        return Ok(());
    }
    let size = operand_size(&inst.operands[0]);
    let a = read_operand(state, &inst.operands[0], inst);
    let b = read_operand(state, &inst.operands[1], inst);
    let result = a.xor(&b);

    if let Value::Concrete(rv) = &result {
        state.flags.update_logic(*rv, size);
    }

    write_operand(state, &inst.operands[0], result, inst);
    Ok(())
}

fn execute_not(state: &mut MachineState, inst: &Instruction) -> EmulationResult<()> {
    if inst.operands.is_empty() {
        return Ok(());
    }
    let a = read_operand(state, &inst.operands[0], inst);
    let result = a.not();
    write_operand(state, &inst.operands[0], result, inst);
    // NOT doesn't affect flags
    Ok(())
}

fn execute_neg(state: &mut MachineState, inst: &Instruction) -> EmulationResult<()> {
    if inst.operands.is_empty() {
        return Ok(());
    }
    let size = operand_size(&inst.operands[0]);
    let a = read_operand(state, &inst.operands[0], inst);
    let result = a.neg();

    if let (Value::Concrete(av), Value::Concrete(rv)) = (&a, &result) {
        state.flags.update_sub(0, *av, *rv, size);
    }

    write_operand(state, &inst.operands[0], result, inst);
    Ok(())
}

fn execute_shl(state: &mut MachineState, inst: &Instruction) -> EmulationResult<()> {
    if inst.operands.len() < 2 {
        return Ok(());
    }
    let a = read_operand(state, &inst.operands[0], inst);
    let b = read_operand(state, &inst.operands[1], inst);
    let result = a.shl(&b);
    write_operand(state, &inst.operands[0], result, inst);
    Ok(())
}

fn execute_shr(state: &mut MachineState, inst: &Instruction) -> EmulationResult<()> {
    if inst.operands.len() < 2 {
        return Ok(());
    }
    let a = read_operand(state, &inst.operands[0], inst);
    let b = read_operand(state, &inst.operands[1], inst);
    let result = a.shr(&b);
    write_operand(state, &inst.operands[0], result, inst);
    Ok(())
}

fn execute_sar(state: &mut MachineState, inst: &Instruction) -> EmulationResult<()> {
    if inst.operands.len() < 2 {
        return Ok(());
    }
    let a = read_operand(state, &inst.operands[0], inst);
    let b = read_operand(state, &inst.operands[1], inst);
    let result = a.sar(&b);
    write_operand(state, &inst.operands[0], result, inst);
    Ok(())
}

fn execute_inc(state: &mut MachineState, inst: &Instruction) -> EmulationResult<()> {
    if inst.operands.is_empty() {
        return Ok(());
    }
    let size = operand_size(&inst.operands[0]);
    let a = read_operand(state, &inst.operands[0], inst);
    let result = a.add(&Value::Concrete(1));

    if let (Value::Concrete(av), Value::Concrete(rv)) = (&a, &result) {
        state.flags.update_inc(*av, *rv, size);
    }

    write_operand(state, &inst.operands[0], result, inst);
    Ok(())
}

fn execute_dec(state: &mut MachineState, inst: &Instruction) -> EmulationResult<()> {
    if inst.operands.is_empty() {
        return Ok(());
    }
    let size = operand_size(&inst.operands[0]);
    let a = read_operand(state, &inst.operands[0], inst);
    let result = a.sub(&Value::Concrete(1));

    if let (Value::Concrete(av), Value::Concrete(rv)) = (&a, &result) {
        state.flags.update_dec(*av, *rv, size);
    }

    write_operand(state, &inst.operands[0], result, inst);
    Ok(())
}

fn execute_cmp(state: &mut MachineState, inst: &Instruction) -> EmulationResult<()> {
    if inst.operands.len() < 2 {
        return Ok(());
    }
    let size = operand_size(&inst.operands[0]);
    let a = read_operand(state, &inst.operands[0], inst);
    let b = read_operand(state, &inst.operands[1], inst);
    let result = a.sub(&b);

    if let (Value::Concrete(av), Value::Concrete(bv), Value::Concrete(rv)) =
        (&a, &b, &result)
    {
        state.flags.update_sub(*av, *bv, *rv, size);
    }

    // CMP doesn't write the result, just updates flags
    Ok(())
}

fn execute_test(state: &mut MachineState, inst: &Instruction) -> EmulationResult<()> {
    if inst.operands.len() < 2 {
        return Ok(());
    }
    let size = operand_size(&inst.operands[0]);
    let a = read_operand(state, &inst.operands[0], inst);
    let b = read_operand(state, &inst.operands[1], inst);
    let result = a.and(&b);

    if let Value::Concrete(rv) = &result {
        state.flags.update_logic(*rv, size);
    }

    // TEST doesn't write the result, just updates flags
    Ok(())
}

fn execute_push(state: &mut MachineState, inst: &Instruction) -> EmulationResult<()> {
    if inst.operands.is_empty() {
        return Ok(());
    }
    let value = read_operand(state, &inst.operands[0], inst);
    state
        .push(value)
        .map_err(|_| EmulationError::StackOverflow)?;
    Ok(())
}

fn execute_pop(state: &mut MachineState, inst: &Instruction) -> EmulationResult<()> {
    if inst.operands.is_empty() {
        return Ok(());
    }
    let value = state.pop().map_err(|_| EmulationError::StackUnderflow)?;
    write_operand(state, &inst.operands[0], value, inst);
    Ok(())
}

fn execute_jmp(state: &mut MachineState, inst: &Instruction) -> EmulationResult<()> {
    if inst.operands.is_empty() {
        return Ok(());
    }
    let target = read_operand(state, &inst.operands[0], inst);
    if let Value::Concrete(addr) = target {
        state.set_pc(addr);
    }
    Ok(())
}

fn execute_jcc(state: &mut MachineState, inst: &Instruction) -> EmulationResult<()> {
    if inst.operands.is_empty() {
        return Ok(());
    }

    // Extract condition from mnemonic (e.g., "je", "jne", "jl", etc.)
    let mnemonic = inst.mnemonic.to_lowercase();
    let condition_str = mnemonic.strip_prefix('j').unwrap_or(&mnemonic);

    if let Some(cc) = ConditionCode::from_suffix(condition_str) {
        if let Some(true) = state.flags.check_condition(cc) {
            let target = read_operand(state, &inst.operands[0], inst);
            if let Value::Concrete(addr) = target {
                state.set_pc(addr);
            }
        }
        // If condition is false or unknown, execution continues to next instruction
    }

    Ok(())
}

fn execute_call(state: &mut MachineState, inst: &Instruction) -> EmulationResult<()> {
    if inst.operands.is_empty() {
        return Ok(());
    }

    // Push return address
    let return_addr = inst.address + inst.size as u64;
    state
        .push(Value::Concrete(return_addr))
        .map_err(|_| EmulationError::StackOverflow)?;

    // Jump to target
    let target = read_operand(state, &inst.operands[0], inst);
    if let Value::Concrete(addr) = target {
        state.set_pc(addr);
    }

    Ok(())
}

fn execute_ret(state: &mut MachineState, inst: &Instruction) -> EmulationResult<()> {
    // Pop return address
    let return_addr = state.pop().map_err(|_| EmulationError::StackUnderflow)?;

    if let Value::Concrete(addr) = return_addr {
        state.set_pc(addr);
    }

    // Handle ret imm16 (pop additional bytes)
    if !inst.operands.is_empty() {
        if let Operand::Immediate(imm) = &inst.operands[0] {
            let rsp = state.get_register(x86_regs::RSP);
            if let Value::Concrete(sp) = rsp {
                state.set_register(x86_regs::RSP, Value::Concrete(sp + imm.as_u64()));
            }
        }
    }

    Ok(())
}

fn execute_setcc(state: &mut MachineState, inst: &Instruction) -> EmulationResult<()> {
    if inst.operands.is_empty() {
        return Ok(());
    }

    // Extract condition from mnemonic (e.g., "sete", "setne", etc.)
    let mnemonic = inst.mnemonic.to_lowercase();
    let condition_str = mnemonic.strip_prefix("set").unwrap_or(&mnemonic);

    if let Some(cc) = ConditionCode::from_suffix(condition_str) {
        let result = match state.flags.check_condition(cc) {
            Some(true) => Value::Concrete(1),
            Some(false) => Value::Concrete(0),
            None => Value::Unknown,
        };
        write_operand(state, &inst.operands[0], result, inst);
    }

    Ok(())
}

fn execute_cmov(state: &mut MachineState, inst: &Instruction) -> EmulationResult<()> {
    if inst.operands.len() < 2 {
        return Ok(());
    }

    // Extract condition from mnemonic (e.g., "cmove", "cmovne", etc.)
    let mnemonic = inst.mnemonic.to_lowercase();
    let condition_str = mnemonic.strip_prefix("cmov").unwrap_or(&mnemonic);

    if let Some(cc) = ConditionCode::from_suffix(condition_str) {
        if let Some(true) = state.flags.check_condition(cc) {
            let src = read_operand(state, &inst.operands[1], inst);
            write_operand(state, &inst.operands[0], src, inst);
        }
        // If condition is false or unknown, destination is unchanged
    }

    Ok(())
}
