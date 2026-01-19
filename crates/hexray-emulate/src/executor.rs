//! Emulator executor - main interface for running emulation.

use crate::state::MachineState;
use crate::value::Value;
use crate::x86_64;
use crate::{EmulationResult, IndirectTarget, ResolutionMethod};
use hexray_core::Instruction;
use std::collections::{HashMap, HashSet};

/// Configuration for the emulator.
#[derive(Debug, Clone)]
pub struct EmulatorConfig {
    /// Maximum number of instructions to execute.
    pub max_instructions: usize,
    /// Stop at calls (don't follow them).
    pub stop_at_calls: bool,
    /// Stop at returns.
    pub stop_at_returns: bool,
    /// Stop addresses.
    pub stop_addresses: HashSet<u64>,
    /// Track visited addresses for loop detection.
    pub detect_loops: bool,
    /// Maximum loop iterations before stopping.
    pub max_loop_iterations: usize,
}

impl Default for EmulatorConfig {
    fn default() -> Self {
        Self {
            max_instructions: 10000,
            stop_at_calls: true,
            stop_at_returns: true,
            stop_addresses: HashSet::new(),
            detect_loops: true,
            max_loop_iterations: 100,
        }
    }
}

/// Result of executing instructions.
#[derive(Debug, Clone)]
pub struct ExecutionResult {
    /// Final machine state.
    pub state: MachineState,
    /// Why execution stopped.
    pub stop_reason: StopReason,
    /// Number of instructions executed.
    pub instruction_count: usize,
    /// Path of executed instruction addresses.
    pub path: Vec<u64>,
    /// Any indirect targets that were resolved.
    pub indirect_targets: Vec<IndirectTarget>,
}

/// Reason why execution stopped.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StopReason {
    /// Reached the target address.
    ReachedTarget(u64),
    /// Reached a stop address.
    ReachedStopAddress(u64),
    /// Executed maximum instructions.
    MaxInstructions,
    /// Encountered a call instruction.
    Call(u64),
    /// Encountered a return instruction.
    Return,
    /// Detected a loop.
    Loop(u64),
    /// Encountered an indirect jump/call with unknown target.
    IndirectBranch(u64),
    /// Error during execution.
    Error(String),
    /// Reached end of provided instructions.
    EndOfInstructions,
}

/// The main emulator.
#[derive(Debug)]
pub struct Emulator {
    /// Current machine state.
    state: MachineState,
    /// Configuration.
    config: EmulatorConfig,
    /// Execution path.
    path: Vec<u64>,
    /// Visit counts for loop detection.
    visit_counts: HashMap<u64, usize>,
    /// Resolved indirect targets.
    indirect_targets: Vec<IndirectTarget>,
}

impl Emulator {
    /// Create a new emulator with default configuration.
    pub fn new(config: EmulatorConfig) -> Self {
        Self {
            state: MachineState::with_stack(0x7FFF_FFFF_0000, 0x100000),
            config,
            path: Vec::new(),
            visit_counts: HashMap::new(),
            indirect_targets: Vec::new(),
        }
    }

    /// Get the current machine state.
    pub fn state(&self) -> &MachineState {
        &self.state
    }

    /// Get a mutable reference to the machine state.
    pub fn state_mut(&mut self) -> &mut MachineState {
        &mut self.state
    }

    /// Set a register value.
    pub fn set_register(&mut self, id: u16, value: u64) {
        self.state.set_register(id, Value::Concrete(value));
    }

    /// Get a register value.
    pub fn get_register(&self, id: u16) -> Value {
        self.state.get_register(id)
    }

    /// Load memory from binary data.
    pub fn load_memory(&mut self, base: u64, data: &[u8]) {
        self.state.load_memory(base, data);
    }

    /// Reset the emulator state.
    pub fn reset(&mut self) {
        self.state = MachineState::with_stack(0x7FFF_FFFF_0000, 0x100000);
        self.path.clear();
        self.visit_counts.clear();
        self.indirect_targets.clear();
    }

    /// Execute a single instruction.
    pub fn step(&mut self, inst: &Instruction) -> EmulationResult<StopReason> {
        // Record the visit
        self.path.push(inst.address);

        // Check for loops
        if self.config.detect_loops {
            let count = self.visit_counts.entry(inst.address).or_insert(0);
            *count += 1;
            if *count > self.config.max_loop_iterations {
                return Ok(StopReason::Loop(inst.address));
            }
        }

        // Check for stop address
        if self.config.stop_addresses.contains(&inst.address) {
            return Ok(StopReason::ReachedStopAddress(inst.address));
        }

        // Execute the instruction
        x86_64::execute(&mut self.state, inst)?;

        // Handle control flow
        match inst.operation {
            hexray_core::Operation::Call => {
                if self.config.stop_at_calls {
                    let target = self.get_call_target(inst);
                    return Ok(StopReason::Call(target.as_concrete().unwrap_or(0)));
                }
            }
            hexray_core::Operation::Return => {
                if self.config.stop_at_returns {
                    return Ok(StopReason::Return);
                }
            }
            hexray_core::Operation::Jump => {
                let target = self.get_jump_target(inst);
                if !target.is_concrete() {
                    // Try to resolve indirect jump
                    self.try_resolve_indirect(inst.address, &target);
                    return Ok(StopReason::IndirectBranch(inst.address));
                }
            }
            _ => {}
        }

        // Advance PC if not already changed by control flow
        let expected_next = inst.address + inst.size as u64;
        if self.state.pc() == 0 || self.state.pc() == inst.address {
            self.state.set_pc(expected_next);
        }

        Ok(StopReason::EndOfInstructions)
    }

    /// Execute instructions until a stop condition is met.
    pub fn execute(&mut self, instructions: &[Instruction]) -> EmulationResult<ExecutionResult> {
        // Build address -> instruction map
        let inst_map: HashMap<u64, &Instruction> =
            instructions.iter().map(|i| (i.address, i)).collect();

        // Set initial PC
        if let Some(first) = instructions.first() {
            self.state.set_pc(first.address);
        }

        let mut instruction_count = 0;

        loop {
            // Check max instructions
            if instruction_count >= self.config.max_instructions {
                return Ok(ExecutionResult {
                    state: self.state.clone(),
                    stop_reason: StopReason::MaxInstructions,
                    instruction_count,
                    path: self.path.clone(),
                    indirect_targets: self.indirect_targets.clone(),
                });
            }

            // Get current instruction
            let pc = self.state.pc();
            let inst = match inst_map.get(&pc) {
                Some(i) => *i,
                None => {
                    return Ok(ExecutionResult {
                        state: self.state.clone(),
                        stop_reason: StopReason::EndOfInstructions,
                        instruction_count,
                        path: self.path.clone(),
                        indirect_targets: self.indirect_targets.clone(),
                    });
                }
            };

            // Execute
            let reason = self.step(inst)?;
            instruction_count += 1;

            // Check stop conditions
            match reason {
                StopReason::EndOfInstructions => continue,
                other => {
                    return Ok(ExecutionResult {
                        state: self.state.clone(),
                        stop_reason: other,
                        instruction_count,
                        path: self.path.clone(),
                        indirect_targets: self.indirect_targets.clone(),
                    });
                }
            }
        }
    }

    /// Execute from a start address to a target address.
    pub fn execute_to(
        &mut self,
        instructions: &[Instruction],
        start: u64,
        target: u64,
    ) -> EmulationResult<ExecutionResult> {
        self.state.set_pc(start);
        self.config.stop_addresses.insert(target);

        let result = self.execute(instructions)?;

        // Check if we reached the target
        if self.state.pc() == target {
            return Ok(ExecutionResult {
                stop_reason: StopReason::ReachedTarget(target),
                ..result
            });
        }

        Ok(result)
    }

    /// Get the target of a call instruction.
    fn get_call_target(&self, inst: &Instruction) -> Value {
        if inst.operands.is_empty() {
            return Value::Unknown;
        }

        match &inst.operands[0] {
            hexray_core::Operand::Immediate(imm) => Value::Concrete(imm.as_u64()),
            hexray_core::Operand::PcRelative { target, .. } => {
                Value::Concrete(*target)
            }
            hexray_core::Operand::Register(reg) => self.state.get_register(reg.id),
            hexray_core::Operand::Memory(mem) => {
                // Indirect call through memory
                let addr = self.compute_memory_address(mem, inst);
                match addr {
                    Value::Concrete(a) => self.state.memory.read_u64(a),
                    _ => Value::Unknown,
                }
            }
        }
    }

    /// Get the target of a jump instruction.
    fn get_jump_target(&self, inst: &Instruction) -> Value {
        self.get_call_target(inst) // Same logic
    }

    /// Compute a memory address.
    fn compute_memory_address(
        &self,
        mem: &hexray_core::MemoryRef,
        inst: &Instruction,
    ) -> Value {
        let mut addr = Value::Concrete(0);

        if let Some(ref base) = mem.base {
            let base_val = self.state.get_register(base.id);
            addr = addr.add(&base_val);
        }

        if let Some(ref index) = mem.index {
            let index_val = self.state.get_register(index.id);
            let scaled = index_val.mul(&Value::Concrete(mem.scale as u64));
            addr = addr.add(&scaled);
        }

        if mem.displacement != 0 {
            addr = addr.add(&Value::Concrete(mem.displacement as u64));
        }

        // Handle RIP-relative
        if mem.base.as_ref().map(|b| b.id) == Some(16) {
            // RIP
            let rip = inst.address + inst.size as u64;
            addr = Value::Concrete(rip).add(&Value::Concrete(mem.displacement as u64));
        }

        addr
    }

    /// Try to resolve an indirect branch target.
    fn try_resolve_indirect(&mut self, address: u64, target: &Value) {
        if let Value::Concrete(t) = target {
            self.indirect_targets.push(IndirectTarget {
                instruction_address: address,
                targets: vec![*t],
                confidence: 1.0,
                resolution_method: ResolutionMethod::ConcreteExecution,
            });
        }
    }

    /// Resolve an indirect call/jump by trying multiple input values.
    pub fn resolve_indirect(
        &mut self,
        instructions: &[Instruction],
        indirect_addr: u64,
        index_register: u16,
        min_index: u64,
        max_index: u64,
    ) -> Vec<u64> {
        let mut targets = Vec::new();
        let initial_state = self.state.clone();

        for i in min_index..=max_index {
            self.state = initial_state.clone();
            self.state.set_register(index_register, Value::Concrete(i));
            self.path.clear();
            self.visit_counts.clear();

            if let Ok(result) = self.execute(instructions) {
                if let StopReason::IndirectBranch(addr) = result.stop_reason {
                    if addr == indirect_addr {
                        // Get the computed target
                        let inst_map: HashMap<u64, &Instruction> =
                            instructions.iter().map(|inst| (inst.address, inst)).collect();
                        if let Some(inst) = inst_map.get(&addr) {
                            let target = self.get_jump_target(inst);
                            if let Value::Concrete(t) = target {
                                if !targets.contains(&t) {
                                    targets.push(t);
                                }
                            }
                        }
                    }
                }
            }
        }

        self.state = initial_state;
        targets
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state::x86_regs;
    use hexray_core::{Architecture, Operation, Operand, Register, RegisterClass};

    fn make_inst(addr: u64, op: Operation, operands: Vec<Operand>) -> Instruction {
        Instruction {
            address: addr,
            size: 4,
            bytes: vec![0x90; 4], // NOP padding for test
            operation: op,
            mnemonic: String::new(),
            operands,
            control_flow: hexray_core::ControlFlow::Sequential,
            reads: Vec::new(),
            writes: Vec::new(),
        }
    }

    fn reg(id: u16) -> Operand {
        Operand::Register(Register::new(
            Architecture::X86_64,
            RegisterClass::General,
            id,
            8,
        ))
    }

    fn imm(val: i64) -> Operand {
        Operand::imm(val as i128, 8)
    }

    #[test]
    fn test_simple_execution() {
        let mut emu = Emulator::new(EmulatorConfig::default());

        // mov rax, 10
        // add rax, 5
        let instructions = vec![
            make_inst(0x1000, Operation::Move, vec![reg(x86_regs::RAX), imm(10)]),
            make_inst(0x1004, Operation::Add, vec![reg(x86_regs::RAX), imm(5)]),
        ];

        emu.state_mut().set_pc(0x1000);
        let result = emu.execute(&instructions).unwrap();

        assert_eq!(emu.get_register(x86_regs::RAX), Value::Concrete(15));
        assert_eq!(result.instruction_count, 2);
    }

    #[test]
    fn test_memory_operations() {
        let mut emu = Emulator::new(EmulatorConfig::default());

        // Write to memory and read back
        emu.state_mut()
            .memory
            .write_u64(0x1000, Value::Concrete(0xDEADBEEF));
        assert_eq!(
            emu.state().memory.read_u64(0x1000),
            Value::Concrete(0xDEADBEEF)
        );
    }

    #[test]
    fn test_stop_at_call() {
        let mut emu = Emulator::new(EmulatorConfig {
            stop_at_calls: true,
            ..Default::default()
        });

        // mov rax, 10
        // call 0x2000
        let instructions = vec![
            make_inst(0x1000, Operation::Move, vec![reg(x86_regs::RAX), imm(10)]),
            make_inst(0x1004, Operation::Call, vec![imm(0x2000)]),
        ];

        emu.state_mut().set_pc(0x1000);
        let result = emu.execute(&instructions).unwrap();

        assert!(matches!(result.stop_reason, StopReason::Call(0x2000)));
    }
}
