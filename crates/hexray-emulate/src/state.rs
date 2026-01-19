//! Machine state for emulation.
//!
//! Contains registers, memory, flags, and program counter.

use crate::flags::Flags;
use crate::memory::SparseMemory;
use crate::value::Value;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// x86-64 register IDs (matching hexray-core convention).
pub mod x86_regs {
    pub const RAX: u16 = 0;
    pub const RCX: u16 = 1;
    pub const RDX: u16 = 2;
    pub const RBX: u16 = 3;
    pub const RSP: u16 = 4;
    pub const RBP: u16 = 5;
    pub const RSI: u16 = 6;
    pub const RDI: u16 = 7;
    pub const R8: u16 = 8;
    pub const R9: u16 = 9;
    pub const R10: u16 = 10;
    pub const R11: u16 = 11;
    pub const R12: u16 = 12;
    pub const R13: u16 = 13;
    pub const R14: u16 = 14;
    pub const R15: u16 = 15;
    pub const RIP: u16 = 16;

    /// Get the register name.
    pub fn name(id: u16) -> &'static str {
        match id {
            RAX => "rax",
            RCX => "rcx",
            RDX => "rdx",
            RBX => "rbx",
            RSP => "rsp",
            RBP => "rbp",
            RSI => "rsi",
            RDI => "rdi",
            R8 => "r8",
            R9 => "r9",
            R10 => "r10",
            R11 => "r11",
            R12 => "r12",
            R13 => "r13",
            R14 => "r14",
            R15 => "r15",
            RIP => "rip",
            _ => "unknown",
        }
    }

    /// Get the 32-bit version of a 64-bit register.
    pub fn to_32bit(id: u16) -> u16 {
        id // Same ID, different size handling
    }
}

/// Full machine state for emulation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MachineState {
    /// General purpose registers (64-bit values).
    registers: HashMap<u16, Value>,

    /// Memory.
    pub memory: SparseMemory,

    /// CPU flags.
    pub flags: Flags,

    /// Program counter / instruction pointer.
    pc: u64,

    /// Stack base (for detecting stack overflow).
    stack_base: u64,

    /// Stack limit (for detecting stack overflow).
    stack_limit: u64,
}

impl MachineState {
    /// Create a new machine state.
    pub fn new() -> Self {
        Self {
            registers: HashMap::new(),
            memory: SparseMemory::new(),
            flags: Flags::new(),
            pc: 0,
            stack_base: 0x7FFF_FFFF_0000,
            stack_limit: 0x7FFF_FFFE_0000,
        }
    }

    /// Create with initial stack setup.
    pub fn with_stack(stack_base: u64, stack_size: u64) -> Self {
        let mut state = Self::new();
        state.stack_base = stack_base;
        state.stack_limit = stack_base.saturating_sub(stack_size);
        state.set_register(x86_regs::RSP, Value::Concrete(stack_base));
        state.set_register(x86_regs::RBP, Value::Concrete(stack_base));
        state
    }

    // ==================== Register Access ====================

    /// Get a register value.
    pub fn get_register(&self, id: u16) -> Value {
        self.registers.get(&id).cloned().unwrap_or(Value::Unknown)
    }

    /// Set a register value.
    pub fn set_register(&mut self, id: u16, value: Value) {
        self.registers.insert(id, value);
    }

    /// Get a 32-bit register (zero-extended to 64 bits).
    pub fn get_register_32(&self, id: u16) -> Value {
        self.get_register(id).trunc(32)
    }

    /// Set a 32-bit register (zero-extends to 64 bits, clearing high bits).
    pub fn set_register_32(&mut self, id: u16, value: Value) {
        self.set_register(id, value.zext(32));
    }

    /// Get a 16-bit register.
    pub fn get_register_16(&self, id: u16) -> Value {
        self.get_register(id).trunc(16)
    }

    /// Set a 16-bit register (preserves high bits).
    pub fn set_register_16(&mut self, id: u16, value: Value) {
        let current = self.get_register(id);
        match (current, value) {
            (Value::Concrete(cur), Value::Concrete(new)) => {
                let result = (cur & !0xFFFF) | (new & 0xFFFF);
                self.set_register(id, Value::Concrete(result));
            }
            _ => self.set_register(id, Value::Unknown),
        }
    }

    /// Get an 8-bit register (low byte).
    pub fn get_register_8l(&self, id: u16) -> Value {
        self.get_register(id).trunc(8)
    }

    /// Set an 8-bit register (low byte, preserves other bits).
    pub fn set_register_8l(&mut self, id: u16, value: Value) {
        let current = self.get_register(id);
        match (current, value) {
            (Value::Concrete(cur), Value::Concrete(new)) => {
                let result = (cur & !0xFF) | (new & 0xFF);
                self.set_register(id, Value::Concrete(result));
            }
            _ => self.set_register(id, Value::Unknown),
        }
    }

    /// Get an 8-bit register (high byte of low 16 bits - ah, bh, ch, dh).
    pub fn get_register_8h(&self, id: u16) -> Value {
        match self.get_register(id) {
            Value::Concrete(v) => Value::Concrete((v >> 8) & 0xFF),
            _ => Value::Unknown,
        }
    }

    /// Set an 8-bit register (high byte of low 16 bits).
    pub fn set_register_8h(&mut self, id: u16, value: Value) {
        let current = self.get_register(id);
        match (current, value) {
            (Value::Concrete(cur), Value::Concrete(new)) => {
                let result = (cur & !0xFF00) | ((new & 0xFF) << 8);
                self.set_register(id, Value::Concrete(result));
            }
            _ => self.set_register(id, Value::Unknown),
        }
    }

    // ==================== Program Counter ====================

    /// Get the program counter.
    pub fn pc(&self) -> u64 {
        self.pc
    }

    /// Set the program counter.
    pub fn set_pc(&mut self, pc: u64) {
        self.pc = pc;
    }

    /// Advance the program counter.
    pub fn advance_pc(&mut self, bytes: u64) {
        self.pc += bytes;
    }

    // ==================== Stack Operations ====================

    /// Push a value onto the stack.
    pub fn push(&mut self, value: Value) -> Result<(), &'static str> {
        let rsp = self.get_register(x86_regs::RSP);
        match rsp {
            Value::Concrete(sp) => {
                let new_sp = sp.wrapping_sub(8);
                if new_sp < self.stack_limit {
                    return Err("Stack overflow");
                }
                self.memory.write_u64(new_sp, value);
                self.set_register(x86_regs::RSP, Value::Concrete(new_sp));
                Ok(())
            }
            _ => {
                // Unknown stack pointer - can't push reliably
                self.set_register(x86_regs::RSP, Value::Unknown);
                Ok(())
            }
        }
    }

    /// Pop a value from the stack.
    pub fn pop(&mut self) -> Result<Value, &'static str> {
        let rsp = self.get_register(x86_regs::RSP);
        match rsp {
            Value::Concrete(sp) => {
                if sp >= self.stack_base {
                    return Err("Stack underflow");
                }
                let value = self.memory.read_u64(sp);
                self.set_register(x86_regs::RSP, Value::Concrete(sp.wrapping_add(8)));
                Ok(value)
            }
            _ => {
                self.set_register(x86_regs::RSP, Value::Unknown);
                Ok(Value::Unknown)
            }
        }
    }

    // ==================== State Management ====================

    /// Reset all registers to unknown.
    pub fn reset_registers(&mut self) {
        self.registers.clear();
    }

    /// Clone the state for branching.
    pub fn fork(&self) -> Self {
        self.clone()
    }

    /// Get all concrete register values.
    pub fn concrete_registers(&self) -> Vec<(u16, u64)> {
        self.registers
            .iter()
            .filter_map(|(&id, v)| v.as_concrete().map(|c| (id, c)))
            .collect()
    }

    /// Load memory from binary data.
    pub fn load_memory(&mut self, base: u64, data: &[u8]) {
        self.memory.load_section(base, data);
    }

    /// Dump state for debugging.
    pub fn dump(&self) -> String {
        let mut s = String::new();
        s.push_str("Registers:\n");
        for id in 0..=16 {
            let value = self.get_register(id);
            if !value.is_unknown() {
                s.push_str(&format!("  {}: {}\n", x86_regs::name(id), value));
            }
        }
        s.push_str(&format!("PC: {:#x}\n", self.pc));
        s.push_str(&format!("Flags: {:?}\n", self.flags));
        s
    }
}

impl Default for MachineState {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_register_access() {
        let mut state = MachineState::new();

        state.set_register(x86_regs::RAX, Value::Concrete(0x1234567890ABCDEF));
        assert_eq!(
            state.get_register(x86_regs::RAX),
            Value::Concrete(0x1234567890ABCDEF)
        );

        // 32-bit access
        assert_eq!(
            state.get_register_32(x86_regs::RAX),
            Value::Concrete(0x90ABCDEF)
        );

        // Setting 32-bit clears high bits
        state.set_register_32(x86_regs::RAX, Value::Concrete(0xDEADBEEF));
        assert_eq!(
            state.get_register(x86_regs::RAX),
            Value::Concrete(0xDEADBEEF)
        );
    }

    #[test]
    fn test_stack_operations() {
        let mut state = MachineState::with_stack(0x7FFF_FFFF_0000, 0x10000);

        // Push
        state.push(Value::Concrete(0x1234)).unwrap();
        assert_eq!(
            state.get_register(x86_regs::RSP),
            Value::Concrete(0x7FFF_FFFE_FFF8)
        );

        // Pop
        let value = state.pop().unwrap();
        assert_eq!(value, Value::Concrete(0x1234));
        assert_eq!(
            state.get_register(x86_regs::RSP),
            Value::Concrete(0x7FFF_FFFF_0000)
        );
    }

    #[test]
    fn test_8bit_registers() {
        let mut state = MachineState::new();

        state.set_register(x86_regs::RAX, Value::Concrete(0x1122334455667788));

        // Low byte
        assert_eq!(state.get_register_8l(x86_regs::RAX), Value::Concrete(0x88));

        // High byte of low word (ah)
        assert_eq!(state.get_register_8h(x86_regs::RAX), Value::Concrete(0x77));

        // Set low byte
        state.set_register_8l(x86_regs::RAX, Value::Concrete(0xFF));
        assert_eq!(
            state.get_register(x86_regs::RAX),
            Value::Concrete(0x11223344556677FF)
        );
    }
}
