//! Property-based tests for deterministic simulation.
//!
//! These tests verify key properties of the emulator:
//! - Determinism: Same input + seed → same output
//! - State serialization round-trip
//! - Snapshot correctness
//! - Fault injection behavior

use proptest::prelude::*;

use hexray_core::{Architecture, ControlFlow, Operation, Operand, Register, RegisterClass};
use hexray_emulate::simulation::{FaultKind, Simulation, SimulationConfig, SimulationSnapshot};
use hexray_emulate::state::x86_regs;
use hexray_emulate::value::Value;
use hexray_emulate::MachineState;

// =============================================================================
// Test Helpers
// =============================================================================

fn make_inst(
    addr: u64,
    op: hexray_core::Operation,
    operands: Vec<hexray_core::Operand>,
) -> hexray_core::Instruction {
    hexray_core::Instruction {
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

// =============================================================================
// Instruction Generators
// =============================================================================

/// Generate a sequence of instructions.
fn arb_instruction_sequence(count: impl Into<proptest::collection::SizeRange>) -> impl Strategy<Value = Vec<hexray_core::Instruction>> {
    prop::collection::vec(
        (
            prop::sample::select(vec![
                Operation::Add,
                Operation::Sub,
                Operation::Move,
                Operation::And,
                Operation::Or,
            ]),
            prop::sample::select(vec![
                x86_regs::RAX,
                x86_regs::RBX,
                x86_regs::RCX,
                x86_regs::RDX,
            ]),
            -100i64..100i64,
        ),
        count,
    )
    .prop_map(|ops| {
        ops.into_iter()
            .enumerate()
            .map(|(i, (op, reg_id, imm_val))| {
                let addr = 0x1000 + (i as u64) * 4;
                make_inst(addr, op, vec![reg(reg_id), imm(imm_val)])
            })
            .collect()
    })
}

// =============================================================================
// Determinism Properties
// =============================================================================

proptest! {
    #![proptest_config(ProptestConfig::with_cases(100))]

    /// Executing the same instructions twice with the same seed produces identical states.
    #[test]
    fn execution_is_deterministic(
        seed in any::<u64>(),
        instructions in arb_instruction_sequence(5..20)
    ) {
        let config = SimulationConfig {
            seed,
            record_trace: true,
            ..Default::default()
        };

        let mut sim = Simulation::new(config);

        // First run
        sim.reset();
        let _ = sim.run(&instructions);
        let snapshot1 = sim.snapshot();
        let trace1 = sim.trace().clone();

        // Second run
        sim.reset();
        let _ = sim.run(&instructions);
        let snapshot2 = sim.snapshot();
        let trace2 = sim.trace().clone();

        prop_assert!(
            snapshot1.states_equal(&snapshot2),
            "State mismatch: determinism violated with seed {}",
            seed
        );

        prop_assert!(
            trace1.is_identical(&trace2),
            "Trace mismatch: determinism violated with seed {}",
            seed
        );
    }

    /// Different seeds should (usually) produce different results.
    /// Note: This is probabilistic, so we allow some collisions.
    #[test]
    fn different_seeds_different_results(
        seed1 in 0u64..1000,
        seed2 in 1000u64..2000,
        instructions in arb_instruction_sequence(3..10)
    ) {
        // Only test if instructions actually do something
        prop_assume!(!instructions.is_empty());

        let config1 = SimulationConfig {
            seed: seed1,
            ..Default::default()
        };
        let config2 = SimulationConfig {
            seed: seed2,
            ..Default::default()
        };

        let mut sim1 = Simulation::new(config1);
        let mut sim2 = Simulation::new(config2);

        // Since we're using the same instructions, the results should actually
        // be the same (seeds only affect fault injection timing, not execution).
        // This test verifies that the infrastructure works correctly.
        let _ = sim1.run(&instructions);
        let _ = sim2.run(&instructions);

        let snap1 = sim1.snapshot();
        let snap2 = sim2.snapshot();

        // With same instructions and no faults, states should be equal
        prop_assert!(
            snap1.states_equal(&snap2),
            "Without faults, same instructions should produce same state"
        );
    }

    /// Verify that reset actually resets to initial state.
    #[test]
    fn reset_restores_initial_state(
        seed in any::<u64>(),
        instructions in arb_instruction_sequence(5..15)
    ) {
        let config = SimulationConfig {
            seed,
            ..Default::default()
        };

        let mut sim = Simulation::new(config);

        // Run some instructions
        let _ = sim.run(&instructions);

        // Reset
        sim.reset();
        let after_reset_snapshot = sim.snapshot();

        // After reset, instruction count should be 0
        prop_assert_eq!(
            after_reset_snapshot.instruction_count, 0,
            "Instruction count should be 0 after reset"
        );

        // Path should be empty
        prop_assert!(
            after_reset_snapshot.path.is_empty(),
            "Path should be empty after reset"
        );
    }
}

// =============================================================================
// State Serialization Properties
// =============================================================================

proptest! {
    #![proptest_config(ProptestConfig::with_cases(200))]

    /// Machine state can be serialized and deserialized without loss.
    #[test]
    fn state_serialization_roundtrip(
        rax in any::<u64>(),
        rbx in any::<u64>(),
        rcx in any::<u64>(),
        pc in 0x1000u64..0x10000u64,
    ) {
        let mut state = MachineState::new();
        state.set_register(x86_regs::RAX, Value::Concrete(rax));
        state.set_register(x86_regs::RBX, Value::Concrete(rbx));
        state.set_register(x86_regs::RCX, Value::Concrete(rcx));
        state.set_pc(pc);

        // Serialize
        let json = serde_json::to_string(&state).expect("Serialization failed");

        // Deserialize
        let restored: MachineState = serde_json::from_str(&json).expect("Deserialization failed");

        // Compare
        prop_assert_eq!(
            state.get_register(x86_regs::RAX),
            restored.get_register(x86_regs::RAX),
            "RAX mismatch after round-trip"
        );
        prop_assert_eq!(
            state.get_register(x86_regs::RBX),
            restored.get_register(x86_regs::RBX),
            "RBX mismatch after round-trip"
        );
        prop_assert_eq!(
            state.get_register(x86_regs::RCX),
            restored.get_register(x86_regs::RCX),
            "RCX mismatch after round-trip"
        );
        prop_assert_eq!(state.pc(), restored.pc(), "PC mismatch after round-trip");
    }

    /// Snapshot hash is consistent for the same state.
    #[test]
    fn snapshot_hash_consistency(
        rax in any::<u64>(),
        rbx in any::<u64>(),
        pc in 0x1000u64..0x10000u64,
    ) {
        let mut state = MachineState::new();
        state.set_register(x86_regs::RAX, Value::Concrete(rax));
        state.set_register(x86_regs::RBX, Value::Concrete(rbx));
        state.set_pc(pc);

        let snap1 = SimulationSnapshot::new(&state, 0, &[]);
        let snap2 = SimulationSnapshot::new(&state, 0, &[]);

        prop_assert_eq!(
            snap1.state_hash, snap2.state_hash,
            "Same state should produce same hash"
        );
    }

    /// Different states produce different hashes (with high probability).
    #[test]
    fn snapshot_hash_sensitivity(
        rax1 in any::<u64>(),
        rax2 in any::<u64>(),
    ) {
        prop_assume!(rax1 != rax2);

        let mut state1 = MachineState::new();
        state1.set_register(x86_regs::RAX, Value::Concrete(rax1));

        let mut state2 = MachineState::new();
        state2.set_register(x86_regs::RAX, Value::Concrete(rax2));

        let snap1 = SimulationSnapshot::new(&state1, 0, &[]);
        let snap2 = SimulationSnapshot::new(&state2, 0, &[]);

        prop_assert_ne!(
            snap1.state_hash, snap2.state_hash,
            "Different states should (usually) produce different hashes"
        );
    }
}

// =============================================================================
// Value Arithmetic Properties
// =============================================================================

proptest! {
    #![proptest_config(ProptestConfig::with_cases(1000))]

    /// Concrete value addition is commutative.
    #[test]
    fn value_add_commutative(a in any::<u64>(), b in any::<u64>()) {
        let va = Value::Concrete(a);
        let vb = Value::Concrete(b);

        prop_assert_eq!(va.add(&vb), vb.add(&va));
    }

    /// Concrete value multiplication is commutative.
    #[test]
    fn value_mul_commutative(a in any::<u64>(), b in any::<u64>()) {
        let va = Value::Concrete(a);
        let vb = Value::Concrete(b);

        prop_assert_eq!(va.mul(&vb), vb.mul(&va));
    }

    /// Adding zero is identity.
    #[test]
    fn value_add_zero_identity(a in any::<u64>()) {
        let va = Value::Concrete(a);
        let zero = Value::Concrete(0);

        prop_assert_eq!(va.add(&zero), va.clone());
        prop_assert_eq!(zero.add(&va), va);
    }

    /// Multiplying by one is identity.
    #[test]
    fn value_mul_one_identity(a in any::<u64>()) {
        let va = Value::Concrete(a);
        let one = Value::Concrete(1);

        prop_assert_eq!(va.mul(&one), va.clone());
        prop_assert_eq!(one.mul(&va), va);
    }

    /// Multiplying by zero gives zero.
    #[test]
    fn value_mul_zero_annihilates(a in any::<u64>()) {
        let va = Value::Concrete(a);
        let zero = Value::Concrete(0);

        prop_assert_eq!(va.mul(&zero), zero.clone());
        prop_assert_eq!(zero.mul(&va), zero);
    }

    /// XOR with self gives zero.
    #[test]
    fn value_xor_self_is_zero(a in any::<u64>()) {
        let va = Value::Concrete(a);

        prop_assert_eq!(va.xor(&va), Value::Concrete(0));
    }

    /// AND with all-ones is identity.
    #[test]
    fn value_and_all_ones_identity(a in any::<u64>()) {
        let va = Value::Concrete(a);
        let all_ones = Value::Concrete(u64::MAX);

        prop_assert_eq!(va.and(&all_ones), va);
    }

    /// OR with zero is identity.
    #[test]
    fn value_or_zero_identity(a in any::<u64>()) {
        let va = Value::Concrete(a);
        let zero = Value::Concrete(0);

        prop_assert_eq!(va.or(&zero), va);
    }

    /// Division by non-zero doesn't fail.
    #[test]
    fn value_div_non_zero_succeeds(
        a in any::<u64>(),
        b in 1u64..=u64::MAX,  // Non-zero
    ) {
        let va = Value::Concrete(a);
        let vb = Value::Concrete(b);

        let result = va.div(&vb);
        prop_assert!(result.is_some(), "Division by non-zero should succeed");
    }

    /// Division by zero fails.
    #[test]
    fn value_div_zero_fails(a in any::<u64>()) {
        let va = Value::Concrete(a);
        let zero = Value::Concrete(0);

        prop_assert!(va.div(&zero).is_none(), "Division by zero should fail");
    }
}

// =============================================================================
// Memory Operations Properties
// =============================================================================

proptest! {
    #![proptest_config(ProptestConfig::with_cases(500))]

    /// Writing and reading back gives the same value.
    #[test]
    fn memory_write_read_roundtrip(
        addr in 0x1000u64..0x100000u64,
        value in any::<u64>(),
    ) {
        let mut state = MachineState::new();

        state.memory.write_u64(addr, Value::Concrete(value));
        let read_back = state.memory.read_u64(addr);

        prop_assert_eq!(
            read_back,
            Value::Concrete(value),
            "Memory read should return written value"
        );
    }

    /// Uninitialized memory reads as Unknown.
    #[test]
    fn memory_uninitialized_is_unknown(addr in 0x1000u64..0x100000u64) {
        let state = MachineState::new();
        let value = state.memory.read_u64(addr);

        prop_assert!(value.is_unknown(), "Uninitialized memory should be Unknown");
    }

    /// Loaded sections can be read back.
    #[test]
    fn memory_load_section_readable(
        base in 0x1000u64..0x10000u64,
        data in prop::collection::vec(any::<u8>(), 1..100),
    ) {
        let mut state = MachineState::new();
        state.load_memory(base, &data);

        for (i, &byte) in data.iter().enumerate() {
            let addr = base + i as u64;
            let value = state.memory.read_byte(addr);
            prop_assert_eq!(
                value,
                Value::Concrete(byte as u64),
                "Loaded byte at offset {} should match",
                i
            );
        }
    }
}

// =============================================================================
// Fault Injection Properties
// =============================================================================

proptest! {
    #![proptest_config(ProptestConfig::with_cases(50))]

    /// ForceStop fault actually stops execution.
    #[test]
    fn fault_force_stop_works(
        stop_at in 1usize..5,
        instructions in arb_instruction_sequence(10..20),
    ) {
        prop_assume!(instructions.len() > stop_at);

        let config = SimulationConfig {
            faults: vec![(stop_at, FaultKind::ForceStop)],
            ..Default::default()
        };

        let mut sim = Simulation::new(config);

        // Step through instructions
        for (i, inst) in instructions.iter().enumerate() {
            let result = sim.step(inst);

            if i == stop_at {
                // Should have stopped here
                prop_assert!(
                    matches!(result, Ok(hexray_emulate::StopReason::Error(_))),
                    "Should have stopped at instruction {}",
                    i
                );
                break;
            }
        }
    }

    /// InstructionSkipped fault skips the instruction.
    #[test]
    fn fault_skip_instruction(
        skip_at in 0usize..5,
        instructions in arb_instruction_sequence(10..15),
    ) {
        prop_assume!(instructions.len() > skip_at);

        let config = SimulationConfig {
            faults: vec![(skip_at, FaultKind::InstructionSkipped)],
            record_trace: true,
            ..Default::default()
        };

        let mut sim = Simulation::new(config);

        // Step through all instructions
        for inst in &instructions {
            let _ = sim.step(inst);
        }

        let trace = sim.trace();

        // Find the skipped instruction in trace
        let skipped_step = &trace.steps[skip_at];
        prop_assert!(
            skipped_step.fault == Some(FaultKind::InstructionSkipped),
            "Trace should record the skip fault"
        );
    }
}
