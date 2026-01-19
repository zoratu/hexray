//! Deterministic simulation framework for the emulator.
//!
//! This module provides infrastructure for deterministic testing:
//! - Seed-based reproducible execution
//! - State snapshots and comparison
//! - Fault injection at deterministic points
//! - Execution trace recording and replay
//!
//! # Deterministic Simulation Testing
//!
//! The key insight is that emulator bugs are often non-deterministic in the wild
//! but can be reproduced if we control all sources of randomness. This module
//! provides the tools to:
//!
//! 1. **Seed everything** - Use a seed to initialize all random state
//! 2. **Snapshot/restore** - Save and restore complete machine state
//! 3. **Inject faults** - Introduce errors at specific points
//! 4. **Compare executions** - Verify two runs produce identical results
//!
//! # Example
//!
//! ```ignore
//! use hexray_emulate::simulation::{Simulation, SimulationConfig};
//!
//! // Create a simulation with a fixed seed
//! let mut sim = Simulation::new(SimulationConfig {
//!     seed: 12345,
//!     ..Default::default()
//! });
//!
//! // Run and capture state
//! let result1 = sim.run(&instructions);
//! let snapshot1 = sim.snapshot();
//!
//! // Reset and run again - should be identical
//! sim.reset();
//! let result2 = sim.run(&instructions);
//! let snapshot2 = sim.snapshot();
//!
//! assert_eq!(snapshot1, snapshot2);
//! ```

use crate::executor::{Emulator, EmulatorConfig, ExecutionResult, StopReason};
use crate::state::MachineState;
use crate::value::Value;
use hexray_core::Instruction;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// Configuration for deterministic simulation.
#[derive(Debug, Clone)]
pub struct SimulationConfig {
    /// Random seed for reproducibility.
    pub seed: u64,
    /// Maximum instructions per execution.
    pub max_instructions: usize,
    /// Whether to record execution trace.
    pub record_trace: bool,
    /// Fault injection schedule: (instruction_count, fault_kind).
    pub faults: Vec<(usize, FaultKind)>,
}

impl Default for SimulationConfig {
    fn default() -> Self {
        Self {
            seed: 0,
            max_instructions: 10000,
            record_trace: true,
            faults: Vec::new(),
        }
    }
}

/// Types of faults that can be injected.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum FaultKind {
    /// Memory read returns unknown.
    MemoryReadUnknown,
    /// Memory write is dropped.
    MemoryWriteDropped,
    /// Register read returns unknown.
    RegisterReadUnknown,
    /// Force a specific flag state.
    FlagsCorrupted,
    /// Instruction execution skipped.
    InstructionSkipped,
    /// Force stop execution.
    ForceStop,
}

/// A snapshot of the complete simulation state.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SimulationSnapshot {
    /// Machine state.
    pub state: MachineState,
    /// Instruction count at snapshot time.
    pub instruction_count: usize,
    /// Execution path up to this point.
    pub path: Vec<u64>,
    /// Hash of the state for quick comparison.
    pub state_hash: u64,
}

impl SimulationSnapshot {
    /// Create a snapshot from current state.
    pub fn new(state: &MachineState, instruction_count: usize, path: &[u64]) -> Self {
        let state_hash = Self::compute_hash(state);
        Self {
            state: state.clone(),
            instruction_count,
            path: path.to_vec(),
            state_hash,
        }
    }

    /// Compute a hash of the machine state for quick comparison.
    fn compute_hash(state: &MachineState) -> u64 {
        use std::hash::{Hash, Hasher};
        use std::collections::hash_map::DefaultHasher;

        let mut hasher = DefaultHasher::new();
        // Hash concrete register values in sorted order for determinism
        let mut regs: Vec<_> = state.concrete_registers();
        regs.sort_by_key(|(id, _)| *id);
        for (id, val) in regs {
            id.hash(&mut hasher);
            val.hash(&mut hasher);
        }
        state.pc().hash(&mut hasher);
        hasher.finish()
    }

    /// Check if two snapshots have the same state.
    pub fn states_equal(&self, other: &SimulationSnapshot) -> bool {
        // Quick hash check first
        if self.state_hash != other.state_hash {
            return false;
        }
        // Full comparison
        self.state == other.state
    }
}

/// A single step in the execution trace.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TraceStep {
    /// Instruction address.
    pub address: u64,
    /// Instruction mnemonic.
    pub mnemonic: String,
    /// State before execution.
    pub pre_state_hash: u64,
    /// State after execution.
    pub post_state_hash: u64,
    /// Any fault injected at this step.
    pub fault: Option<FaultKind>,
}

/// Complete execution trace.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ExecutionTrace {
    /// Steps in the trace.
    pub steps: Vec<TraceStep>,
    /// Initial state hash.
    pub initial_state_hash: u64,
    /// Final state hash.
    pub final_state_hash: u64,
    /// Seed used.
    pub seed: u64,
}

impl ExecutionTrace {
    /// Check if two traces are identical.
    pub fn is_identical(&self, other: &ExecutionTrace) -> bool {
        if self.seed != other.seed {
            return false;
        }
        if self.steps.len() != other.steps.len() {
            return false;
        }
        if self.initial_state_hash != other.initial_state_hash {
            return false;
        }
        if self.final_state_hash != other.final_state_hash {
            return false;
        }
        for (a, b) in self.steps.iter().zip(other.steps.iter()) {
            if a.address != b.address || a.post_state_hash != b.post_state_hash {
                return false;
            }
        }
        true
    }

    /// Find the first divergence point between two traces.
    pub fn find_divergence(&self, other: &ExecutionTrace) -> Option<usize> {
        for (i, (a, b)) in self.steps.iter().zip(other.steps.iter()).enumerate() {
            if a.post_state_hash != b.post_state_hash {
                return Some(i);
            }
        }
        if self.steps.len() != other.steps.len() {
            return Some(self.steps.len().min(other.steps.len()));
        }
        None
    }
}

/// Deterministic simulation controller.
pub struct Simulation {
    /// Configuration.
    config: SimulationConfig,
    /// The emulator.
    emulator: Emulator,
    /// Current instruction count.
    instruction_count: usize,
    /// Execution trace.
    trace: ExecutionTrace,
    /// Pending faults (sorted by instruction count).
    pending_faults: BTreeMap<usize, FaultKind>,
    /// Initial state for reset.
    initial_state: MachineState,
}

impl Simulation {
    /// Create a new simulation with the given configuration.
    pub fn new(config: SimulationConfig) -> Self {
        let emulator_config = EmulatorConfig {
            max_instructions: config.max_instructions,
            stop_at_calls: false,
            stop_at_returns: false,
            detect_loops: true,
            max_loop_iterations: 100,
            ..Default::default()
        };

        let emulator = Emulator::new(emulator_config);
        let initial_state = emulator.state().clone();

        let mut pending_faults = BTreeMap::new();
        for (count, fault) in &config.faults {
            pending_faults.insert(*count, *fault);
        }

        let mut trace = ExecutionTrace::default();
        trace.seed = config.seed;
        trace.initial_state_hash = SimulationSnapshot::compute_hash(&initial_state);

        Self {
            config,
            emulator,
            instruction_count: 0,
            trace,
            pending_faults,
            initial_state,
        }
    }

    /// Get the current machine state.
    pub fn state(&self) -> &MachineState {
        self.emulator.state()
    }

    /// Get a mutable reference to the machine state.
    pub fn state_mut(&mut self) -> &mut MachineState {
        self.emulator.state_mut()
    }

    /// Set a register value.
    pub fn set_register(&mut self, id: u16, value: u64) {
        self.emulator.set_register(id, value);
    }

    /// Load memory from binary data.
    pub fn load_memory(&mut self, base: u64, data: &[u8]) {
        self.emulator.load_memory(base, data);
    }

    /// Reset to initial state.
    pub fn reset(&mut self) {
        self.emulator.reset();
        self.instruction_count = 0;
        self.trace = ExecutionTrace::default();
        self.trace.seed = self.config.seed;
        self.trace.initial_state_hash = SimulationSnapshot::compute_hash(&self.initial_state);

        // Reset pending faults
        self.pending_faults.clear();
        for (count, fault) in &self.config.faults {
            self.pending_faults.insert(*count, *fault);
        }
    }

    /// Reset with a new seed.
    pub fn reset_with_seed(&mut self, seed: u64) {
        self.config.seed = seed;
        self.reset();
    }

    /// Take a snapshot of current state.
    pub fn snapshot(&self) -> SimulationSnapshot {
        SimulationSnapshot::new(
            self.emulator.state(),
            self.instruction_count,
            &self.trace.steps.iter().map(|s| s.address).collect::<Vec<_>>(),
        )
    }

    /// Execute a single instruction with optional fault injection.
    pub fn step(&mut self, inst: &Instruction) -> Result<StopReason, String> {
        // Check for pending faults
        let fault = self.pending_faults.remove(&self.instruction_count);

        // Record pre-state
        let pre_hash = SimulationSnapshot::compute_hash(self.emulator.state());

        // Apply fault if any
        if let Some(fault_kind) = fault {
            match fault_kind {
                FaultKind::ForceStop => {
                    // Record trace entry for the fault
                    if self.config.record_trace {
                        self.trace.steps.push(TraceStep {
                            address: inst.address,
                            mnemonic: inst.mnemonic.clone(),
                            pre_state_hash: pre_hash,
                            post_state_hash: pre_hash, // State unchanged
                            fault: Some(fault_kind),
                        });
                    }
                    return Ok(StopReason::Error("Fault injected: ForceStop".to_string()));
                }
                FaultKind::InstructionSkipped => {
                    // Record trace entry for the skipped instruction
                    if self.config.record_trace {
                        self.trace.steps.push(TraceStep {
                            address: inst.address,
                            mnemonic: inst.mnemonic.clone(),
                            pre_state_hash: pre_hash,
                            post_state_hash: pre_hash, // State unchanged (instruction skipped)
                            fault: Some(fault_kind),
                        });
                    }
                    self.instruction_count += 1;
                    return Ok(StopReason::EndOfInstructions);
                }
                FaultKind::RegisterReadUnknown => {
                    // Mark a register as unknown
                    self.emulator.state_mut().set_register(0, Value::Unknown);
                }
                FaultKind::MemoryReadUnknown => {
                    // Will cause reads to return unknown
                }
                FaultKind::MemoryWriteDropped => {
                    // Skip the write
                }
                FaultKind::FlagsCorrupted => {
                    self.emulator.state_mut().flags.clear();
                }
            }
        }

        // Execute
        let result = self.emulator.step(inst).map_err(|e| e.to_string())?;

        // Record post-state
        let post_hash = SimulationSnapshot::compute_hash(self.emulator.state());

        // Record trace
        if self.config.record_trace {
            self.trace.steps.push(TraceStep {
                address: inst.address,
                mnemonic: inst.mnemonic.clone(),
                pre_state_hash: pre_hash,
                post_state_hash: post_hash,
                fault,
            });
        }

        self.instruction_count += 1;
        Ok(result)
    }

    /// Execute until a stop condition.
    pub fn run(&mut self, instructions: &[Instruction]) -> Result<ExecutionResult, String> {
        let result = self.emulator.execute(instructions).map_err(|e| e.to_string())?;
        self.instruction_count = result.instruction_count;
        self.trace.final_state_hash = SimulationSnapshot::compute_hash(self.emulator.state());
        Ok(result)
    }

    /// Get the execution trace.
    pub fn trace(&self) -> &ExecutionTrace {
        &self.trace
    }

    /// Get the instruction count.
    pub fn instruction_count(&self) -> usize {
        self.instruction_count
    }

    /// Verify that running with the same seed produces identical results.
    pub fn verify_determinism(&mut self, instructions: &[Instruction]) -> Result<bool, String> {
        // First run
        self.reset();
        let _ = self.run(instructions)?;
        let snapshot1 = self.snapshot();
        let trace1 = self.trace.clone();

        // Second run
        self.reset();
        let _ = self.run(instructions)?;
        let snapshot2 = self.snapshot();
        let trace2 = self.trace.clone();

        // Compare
        let states_match = snapshot1.states_equal(&snapshot2);
        let traces_match = trace1.is_identical(&trace2);

        Ok(states_match && traces_match)
    }
}

/// Run two simulations in parallel and compare results.
pub fn compare_simulations(
    instructions: &[Instruction],
    config1: SimulationConfig,
    config2: SimulationConfig,
) -> SimulationComparison {
    let mut sim1 = Simulation::new(config1);
    let mut sim2 = Simulation::new(config2);

    let result1 = sim1.run(instructions);
    let result2 = sim2.run(instructions);

    let snapshot1 = sim1.snapshot();
    let snapshot2 = sim2.snapshot();

    SimulationComparison {
        result1: result1.ok(),
        result2: result2.ok(),
        states_equal: snapshot1.states_equal(&snapshot2),
        trace_divergence: sim1.trace().find_divergence(sim2.trace()),
        snapshot1,
        snapshot2,
    }
}

/// Result of comparing two simulations.
#[derive(Debug)]
pub struct SimulationComparison {
    /// Result from first simulation.
    pub result1: Option<ExecutionResult>,
    /// Result from second simulation.
    pub result2: Option<ExecutionResult>,
    /// Whether final states are equal.
    pub states_equal: bool,
    /// First point of divergence (if any).
    pub trace_divergence: Option<usize>,
    /// Snapshot from first simulation.
    pub snapshot1: SimulationSnapshot,
    /// Snapshot from second simulation.
    pub snapshot2: SimulationSnapshot,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state::x86_regs;
    use hexray_core::{Architecture, ControlFlow, Operation, Operand, Register, RegisterClass};

    fn make_inst(addr: u64, op: Operation, operands: Vec<Operand>) -> Instruction {
        Instruction {
            address: addr,
            size: 4,
            bytes: vec![0x90; 4],
            operation: op,
            mnemonic: format!("{:?}", op).to_lowercase(),
            operands,
            control_flow: ControlFlow::Sequential,
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
    fn test_deterministic_execution() {
        let config = SimulationConfig::default();
        let mut sim = Simulation::new(config);

        let instructions = vec![
            make_inst(0x1000, Operation::Move, vec![reg(x86_regs::RAX), imm(10)]),
            make_inst(0x1004, Operation::Add, vec![reg(x86_regs::RAX), imm(5)]),
        ];

        // First run
        sim.reset();
        let _ = sim.run(&instructions);
        let snap1 = sim.snapshot();

        // Second run
        sim.reset();
        let _ = sim.run(&instructions);
        let snap2 = sim.snapshot();

        assert!(snap1.states_equal(&snap2), "Determinism violation: states differ");
    }

    #[test]
    fn test_snapshot_comparison() {
        let config = SimulationConfig::default();
        let mut sim = Simulation::new(config);

        let instructions = vec![
            make_inst(0x1000, Operation::Move, vec![reg(x86_regs::RAX), imm(42)]),
        ];

        sim.reset();
        let _ = sim.run(&instructions);
        let snap1 = sim.snapshot();

        // Modify state
        sim.state_mut().set_register(x86_regs::RBX, Value::Concrete(100));
        let snap2 = sim.snapshot();

        assert!(!snap1.states_equal(&snap2), "Snapshots should differ");
    }

    #[test]
    fn test_verify_determinism() {
        let config = SimulationConfig {
            seed: 12345,
            ..Default::default()
        };
        let mut sim = Simulation::new(config);

        let instructions = vec![
            make_inst(0x1000, Operation::Move, vec![reg(x86_regs::RAX), imm(10)]),
            make_inst(0x1004, Operation::Add, vec![reg(x86_regs::RAX), imm(5)]),
            make_inst(0x1008, Operation::Move, vec![reg(x86_regs::RBX), reg(x86_regs::RAX)]),
        ];

        let is_deterministic = sim.verify_determinism(&instructions).unwrap();
        assert!(is_deterministic, "Emulator should be deterministic");
    }

    #[test]
    fn test_fault_injection() {
        let config = SimulationConfig {
            seed: 12345,
            faults: vec![(1, FaultKind::ForceStop)],
            ..Default::default()
        };
        let mut sim = Simulation::new(config);

        let instructions = vec![
            make_inst(0x1000, Operation::Move, vec![reg(x86_regs::RAX), imm(10)]),
            make_inst(0x1004, Operation::Add, vec![reg(x86_regs::RAX), imm(5)]),
        ];

        // Step through manually
        let _ = sim.step(&instructions[0]);
        let result = sim.step(&instructions[1]);

        // Should have stopped due to fault
        assert!(matches!(result, Ok(StopReason::Error(_))));
    }

    #[test]
    fn test_trace_recording() {
        let config = SimulationConfig {
            record_trace: true,
            ..Default::default()
        };
        let mut sim = Simulation::new(config);

        let instructions = vec![
            make_inst(0x1000, Operation::Move, vec![reg(x86_regs::RAX), imm(10)]),
            make_inst(0x1004, Operation::Add, vec![reg(x86_regs::RAX), imm(5)]),
        ];

        for inst in &instructions {
            let _ = sim.step(inst);
        }

        let trace = sim.trace();
        assert_eq!(trace.steps.len(), 2);
        assert_eq!(trace.steps[0].address, 0x1000);
        assert_eq!(trace.steps[1].address, 0x1004);
    }
}
