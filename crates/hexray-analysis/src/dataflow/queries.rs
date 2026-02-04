//! Data flow query engine.
//!
//! This module provides interactive queries for tracing data flow:
//! - Backward slicing: "Where does this value come from?"
//! - Forward slicing: "Where does this value go?"
//!
//! These queries build on top of def-use chain analysis to provide
//! human-readable traces of how values flow through a program.

use super::{DefId, DefUseChain, InstructionEffects, Location, Use};
use hexray_core::{ControlFlowGraph, Instruction};
use std::collections::{HashMap, HashSet, VecDeque};

/// A data flow query to execute.
#[derive(Debug, Clone)]
pub enum DataFlowQuery {
    /// Trace a value backwards: where did it come from?
    /// Starts from a use and finds all contributing definitions.
    TraceBackward {
        /// Address of the instruction containing the use.
        address: u64,
        /// Register to trace (by ID).
        register_id: u16,
    },
    /// Trace a value forwards: where does it go?
    /// Starts from a definition and finds all uses.
    TraceForward {
        /// Address of the instruction containing the definition.
        address: u64,
        /// Register to trace (by ID).
        register_id: u16,
    },
    /// Find all uses of a specific definition.
    FindUses {
        /// Address where the value is defined.
        def_address: u64,
        /// Register being defined.
        register_id: u16,
    },
    /// Find all definitions that could reach a use.
    FindDefs {
        /// Address where the value is used.
        use_address: u64,
        /// Register being used.
        register_id: u16,
    },
}

/// The role of an instruction in a data flow trace.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DataFlowRole {
    /// This instruction defines (creates) the value.
    Definition,
    /// This instruction uses (consumes) the value.
    Use,
    /// This instruction passes the value through (copies it).
    PassThrough,
    /// This is a function parameter (value comes from caller).
    Parameter,
    /// Source of the value (e.g., constant, external input).
    Source,
}

impl std::fmt::Display for DataFlowRole {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DataFlowRole::Definition => write!(f, "DEF"),
            DataFlowRole::Use => write!(f, "USE"),
            DataFlowRole::PassThrough => write!(f, "PASS"),
            DataFlowRole::Parameter => write!(f, "PARAM"),
            DataFlowRole::Source => write!(f, "SOURCE"),
        }
    }
}

/// A single step in a data flow trace.
#[derive(Debug, Clone)]
pub struct DataFlowStep {
    /// Address of the instruction.
    pub address: u64,
    /// The instruction mnemonic/disassembly.
    pub instruction: String,
    /// Role of this instruction in the trace.
    pub role: DataFlowRole,
    /// The location (register/memory) being tracked.
    pub location: Location,
    /// Optional description of the data transformation.
    pub description: Option<String>,
}

impl DataFlowStep {
    /// Create a new data flow step.
    pub fn new(address: u64, instruction: String, role: DataFlowRole, location: Location) -> Self {
        Self {
            address,
            instruction,
            role,
            location,
            description: None,
        }
    }

    /// Add a description to this step.
    pub fn with_description(mut self, desc: impl Into<String>) -> Self {
        self.description = Some(desc.into());
        self
    }
}

/// Result of a data flow query.
#[derive(Debug, Clone)]
pub struct DataFlowResult {
    /// The original query.
    pub query: DataFlowQuery,
    /// The chain of data flow steps.
    pub steps: Vec<DataFlowStep>,
    /// Whether the trace is complete (reached a source/sink).
    pub complete: bool,
    /// Reason if the trace was truncated.
    pub truncation_reason: Option<String>,
}

impl DataFlowResult {
    /// Create a new empty result.
    pub fn new(query: DataFlowQuery) -> Self {
        Self {
            query,
            steps: Vec::new(),
            complete: false,
            truncation_reason: None,
        }
    }

    /// Add a step to the result.
    pub fn add_step(&mut self, step: DataFlowStep) {
        self.steps.push(step);
    }

    /// Mark the trace as complete.
    pub fn mark_complete(&mut self) {
        self.complete = true;
    }

    /// Mark the trace as truncated with a reason.
    pub fn truncate(&mut self, reason: impl Into<String>) {
        self.truncation_reason = Some(reason.into());
    }

    /// Returns true if the trace found any steps.
    pub fn has_results(&self) -> bool {
        !self.steps.is_empty()
    }

    /// Returns the number of steps in the trace.
    pub fn len(&self) -> usize {
        self.steps.len()
    }

    /// Returns true if there are no steps.
    pub fn is_empty(&self) -> bool {
        self.steps.is_empty()
    }
}

/// Engine for executing data flow queries.
pub struct DataFlowQueryEngine<'a> {
    /// Pre-computed def-use chains.
    def_use: DefUseChain,
    /// Map from address to instruction for quick lookup.
    addr_to_inst: HashMap<u64, &'a Instruction>,
    /// Maximum depth for recursive traces.
    max_depth: usize,
    /// Phantom data for lifetime.
    _phantom: std::marker::PhantomData<&'a ()>,
}

impl<'a> DataFlowQueryEngine<'a> {
    /// Create a new query engine for the given CFG.
    pub fn new(cfg: &'a ControlFlowGraph) -> Self {
        let def_use = DefUseChain::build(cfg);

        // Build address -> instruction map
        let mut addr_to_inst = HashMap::new();
        for block in cfg.blocks() {
            for inst in &block.instructions {
                addr_to_inst.insert(inst.address, inst);
            }
        }

        Self {
            def_use,
            addr_to_inst,
            max_depth: 50,
            _phantom: std::marker::PhantomData,
        }
    }

    /// Set the maximum trace depth.
    pub fn with_max_depth(mut self, depth: usize) -> Self {
        self.max_depth = depth;
        self
    }

    /// Execute a data flow query.
    pub fn query(&self, query: &DataFlowQuery) -> DataFlowResult {
        match query {
            DataFlowQuery::TraceBackward {
                address,
                register_id,
            } => self.trace_backward(*address, *register_id),
            DataFlowQuery::TraceForward {
                address,
                register_id,
            } => self.trace_forward(*address, *register_id),
            DataFlowQuery::FindUses {
                def_address,
                register_id,
            } => self.find_uses(*def_address, *register_id),
            DataFlowQuery::FindDefs {
                use_address,
                register_id,
            } => self.find_defs(*use_address, *register_id),
        }
    }

    /// Trace a value backwards from a use to its definitions.
    fn trace_backward(&self, start_addr: u64, register_id: u16) -> DataFlowResult {
        let query = DataFlowQuery::TraceBackward {
            address: start_addr,
            register_id,
        };
        let mut result = DataFlowResult::new(query);
        let location = Location::Register(register_id);

        // Find the use at this address
        let use_info = self.find_use_at_address(start_addr, &location);
        if use_info.is_none() {
            result.truncate(format!(
                "No use of register {} found at {:#x}",
                register_id, start_addr
            ));
            return result;
        }

        let use_info = use_info.unwrap();

        // Add the starting use
        if let Some(inst) = self.addr_to_inst.get(&start_addr) {
            result.add_step(
                DataFlowStep::new(
                    start_addr,
                    inst.to_string(),
                    DataFlowRole::Use,
                    location.clone(),
                )
                .with_description("Starting point"),
            );
        }

        // Track visited definitions to avoid cycles
        let mut visited: HashSet<DefId> = HashSet::new();
        let mut work_queue: VecDeque<(DefId, usize)> = VecDeque::new();

        // Add all reaching definitions to the work queue
        for def_id in &use_info.reaching_defs {
            work_queue.push_back((*def_id, 1));
        }

        while let Some((def_id, depth)) = work_queue.pop_front() {
            if depth > self.max_depth {
                result.truncate("Maximum trace depth reached");
                break;
            }

            if visited.contains(&def_id) {
                continue;
            }
            visited.insert(def_id);

            if let Some(def) = self.def_use.definitions.get(&def_id) {
                // Add this definition to the trace
                if let Some(inst) = self.addr_to_inst.get(&def.address) {
                    let role = self.classify_instruction_role(inst, &def.location);
                    let desc = self.describe_definition(inst, &def.location);

                    result.add_step(
                        DataFlowStep::new(
                            def.address,
                            inst.to_string(),
                            role,
                            def.location.clone(),
                        )
                        .with_description(desc),
                    );

                    // If this is a pass-through (e.g., mov rax, rbx), trace the source
                    if role == DataFlowRole::PassThrough {
                        let source_regs = self.get_source_registers(inst);
                        for src_reg in source_regs {
                            let src_loc = Location::Register(src_reg);
                            // Find uses of source registers in this instruction
                            for use_idx in 0..self.def_use.uses.len() {
                                let u = &self.def_use.uses[use_idx];
                                if u.address == def.address && u.location == src_loc {
                                    for reaching_def in &u.reaching_defs {
                                        if !visited.contains(reaching_def) {
                                            work_queue.push_back((*reaching_def, depth + 1));
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }

        // Check if we found the ultimate source
        if !result.steps.is_empty() {
            let last_step = result.steps.last().unwrap();
            if last_step.role == DataFlowRole::Source
                || last_step.role == DataFlowRole::Parameter
                || last_step.role == DataFlowRole::Definition
            {
                result.mark_complete();
            }
        }

        result
    }

    /// Trace a value forwards from a definition to its uses.
    fn trace_forward(&self, start_addr: u64, register_id: u16) -> DataFlowResult {
        let query = DataFlowQuery::TraceForward {
            address: start_addr,
            register_id,
        };
        let mut result = DataFlowResult::new(query);
        let location = Location::Register(register_id);

        // Find the definition at this address
        let def_id = self.find_def_at_address(start_addr, &location);
        if def_id.is_none() {
            result.truncate(format!(
                "No definition of register {} found at {:#x}",
                register_id, start_addr
            ));
            return result;
        }

        let def_id = def_id.unwrap();

        // Add the starting definition
        if let Some(inst) = self.addr_to_inst.get(&start_addr) {
            result.add_step(
                DataFlowStep::new(
                    start_addr,
                    inst.to_string(),
                    DataFlowRole::Definition,
                    location.clone(),
                )
                .with_description("Starting point"),
            );
        }

        // Track visited uses to avoid duplicates
        let mut visited_uses: HashSet<u64> = HashSet::new();
        let mut work_queue: VecDeque<(DefId, usize)> = VecDeque::new();
        work_queue.push_back((def_id, 1));

        let mut visited_defs: HashSet<DefId> = HashSet::new();

        while let Some((current_def_id, depth)) = work_queue.pop_front() {
            if depth > self.max_depth {
                result.truncate("Maximum trace depth reached");
                break;
            }

            if visited_defs.contains(&current_def_id) {
                continue;
            }
            visited_defs.insert(current_def_id);

            // Get all uses of this definition
            let uses = self.def_use.uses_of_definition(current_def_id);

            for use_info in uses {
                if visited_uses.contains(&use_info.address) {
                    continue;
                }
                visited_uses.insert(use_info.address);

                if let Some(inst) = self.addr_to_inst.get(&use_info.address) {
                    let role = self.classify_use_role(inst, &use_info.location);
                    let desc = self.describe_use(inst, &use_info.location);

                    result.add_step(
                        DataFlowStep::new(
                            use_info.address,
                            inst.to_string(),
                            role,
                            use_info.location.clone(),
                        )
                        .with_description(desc),
                    );

                    // If this instruction also defines a register (pass-through),
                    // follow the definition forward
                    if role == DataFlowRole::PassThrough {
                        let effects = InstructionEffects::from_instruction(inst);
                        for def_loc in &effects.defs {
                            if let Some(new_def_id) =
                                self.find_def_at_address(use_info.address, def_loc)
                            {
                                if !visited_defs.contains(&new_def_id) {
                                    work_queue.push_back((new_def_id, depth + 1));
                                }
                            }
                        }
                    }
                }
            }
        }

        if !result.steps.is_empty() {
            result.mark_complete();
        }

        result
    }

    /// Find all uses of a definition.
    fn find_uses(&self, def_address: u64, register_id: u16) -> DataFlowResult {
        let query = DataFlowQuery::FindUses {
            def_address,
            register_id,
        };
        let mut result = DataFlowResult::new(query);
        let location = Location::Register(register_id);

        let def_id = self.find_def_at_address(def_address, &location);
        if def_id.is_none() {
            result.truncate(format!(
                "No definition of register {} found at {:#x}",
                register_id, def_address
            ));
            return result;
        }

        let def_id = def_id.unwrap();
        let uses = self.def_use.uses_of_definition(def_id);

        for use_info in uses {
            if let Some(inst) = self.addr_to_inst.get(&use_info.address) {
                result.add_step(DataFlowStep::new(
                    use_info.address,
                    inst.to_string(),
                    DataFlowRole::Use,
                    use_info.location.clone(),
                ));
            }
        }

        result.mark_complete();
        result
    }

    /// Find all definitions reaching a use.
    fn find_defs(&self, use_address: u64, register_id: u16) -> DataFlowResult {
        let query = DataFlowQuery::FindDefs {
            use_address,
            register_id,
        };
        let mut result = DataFlowResult::new(query);
        let location = Location::Register(register_id);

        let use_info = self.find_use_at_address(use_address, &location);
        if use_info.is_none() {
            result.truncate(format!(
                "No use of register {} found at {:#x}",
                register_id, use_address
            ));
            return result;
        }

        let use_info = use_info.unwrap();

        for def_id in &use_info.reaching_defs {
            if let Some(def) = self.def_use.definitions.get(def_id) {
                if let Some(inst) = self.addr_to_inst.get(&def.address) {
                    result.add_step(DataFlowStep::new(
                        def.address,
                        inst.to_string(),
                        DataFlowRole::Definition,
                        def.location.clone(),
                    ));
                }
            }
        }

        result.mark_complete();
        result
    }

    // Helper methods

    fn find_use_at_address(&self, address: u64, location: &Location) -> Option<&Use> {
        self.def_use
            .uses
            .iter()
            .find(|u| u.address == address && &u.location == location)
    }

    fn find_def_at_address(&self, address: u64, location: &Location) -> Option<DefId> {
        self.def_use
            .definitions
            .iter()
            .find(|(_, d)| d.address == address && &d.location == location)
            .map(|(id, _)| *id)
    }

    fn classify_instruction_role(&self, inst: &Instruction, _location: &Location) -> DataFlowRole {
        use hexray_core::Operation;

        match inst.operation {
            // Move/Load from another register is a pass-through
            Operation::Move => {
                if inst.operands.len() >= 2 {
                    if let hexray_core::Operand::Register(_) = &inst.operands[1] {
                        return DataFlowRole::PassThrough;
                    }
                    if let hexray_core::Operand::Memory(_) = &inst.operands[1] {
                        return DataFlowRole::PassThrough;
                    }
                    if let hexray_core::Operand::Immediate(_) = &inst.operands[1] {
                        return DataFlowRole::Source;
                    }
                }
                DataFlowRole::Definition
            }
            Operation::Load => DataFlowRole::PassThrough,
            Operation::LoadEffectiveAddress => DataFlowRole::Source,
            _ => DataFlowRole::Definition,
        }
    }

    fn classify_use_role(&self, inst: &Instruction, _location: &Location) -> DataFlowRole {
        use hexray_core::Operation;

        match inst.operation {
            Operation::Move | Operation::Load => {
                // If using as source in a move, it's a pass-through
                if inst.operands.len() >= 2 {
                    return DataFlowRole::PassThrough;
                }
                DataFlowRole::Use
            }
            Operation::Store => DataFlowRole::Use,
            Operation::Call => DataFlowRole::Use,
            Operation::Return => DataFlowRole::Use,
            _ => DataFlowRole::Use,
        }
    }

    fn describe_definition(&self, inst: &Instruction, location: &Location) -> String {
        use hexray_core::Operation;

        let loc_str = match location {
            Location::Register(id) => format!("r{}", id),
            Location::Stack(off) => format!("[rbp{:+}]", off),
            Location::Memory(addr) => format!("[{:#x}]", addr),
            Location::Flags => "flags".to_string(),
        };

        match inst.operation {
            Operation::Move => {
                if inst.operands.len() >= 2 {
                    match &inst.operands[1] {
                        hexray_core::Operand::Immediate(imm) => {
                            format!("{} = {:#x} (constant)", loc_str, imm.value)
                        }
                        hexray_core::Operand::Register(reg) => {
                            format!("{} <- {} (copy)", loc_str, reg.name())
                        }
                        hexray_core::Operand::Memory(_) => {
                            format!("{} <- memory (load)", loc_str)
                        }
                        _ => format!("{} defined", loc_str),
                    }
                } else {
                    format!("{} defined", loc_str)
                }
            }
            Operation::LoadEffectiveAddress => format!("{} = address (lea)", loc_str),
            Operation::Add | Operation::Sub | Operation::Mul | Operation::Div => {
                format!("{} = arithmetic result", loc_str)
            }
            Operation::Call => format!("{} = function return value", loc_str),
            _ => format!("{} defined", loc_str),
        }
    }

    fn describe_use(&self, inst: &Instruction, location: &Location) -> String {
        use hexray_core::Operation;

        let loc_str = match location {
            Location::Register(id) => format!("r{}", id),
            Location::Stack(off) => format!("[rbp{:+}]", off),
            Location::Memory(addr) => format!("[{:#x}]", addr),
            Location::Flags => "flags".to_string(),
        };

        match inst.operation {
            Operation::Move => format!("{} copied to destination", loc_str),
            Operation::Store => format!("{} stored to memory", loc_str),
            Operation::Call => format!("{} passed as argument", loc_str),
            Operation::Return => format!("{} returned", loc_str),
            Operation::Compare | Operation::Test => format!("{} compared", loc_str),
            Operation::Add | Operation::Sub | Operation::Mul | Operation::Div => {
                format!("{} used in arithmetic", loc_str)
            }
            _ => format!("{} used", loc_str),
        }
    }

    fn get_source_registers(&self, inst: &Instruction) -> Vec<u16> {
        let mut regs = Vec::new();

        // For move instructions, the source is typically the second operand
        if inst.operands.len() >= 2 {
            if let hexray_core::Operand::Register(reg) = &inst.operands[1] {
                regs.push(reg.id);
            }
        }

        regs
    }
}

/// Display implementation for nice formatting of results.
impl std::fmt::Display for DataFlowResult {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let query_desc = match &self.query {
            DataFlowQuery::TraceBackward {
                address,
                register_id,
            } => {
                format!(
                    "Tracing backward from {:#x}, register {}",
                    address, register_id
                )
            }
            DataFlowQuery::TraceForward {
                address,
                register_id,
            } => {
                format!(
                    "Tracing forward from {:#x}, register {}",
                    address, register_id
                )
            }
            DataFlowQuery::FindUses {
                def_address,
                register_id,
            } => {
                format!(
                    "Finding uses of register {} defined at {:#x}",
                    register_id, def_address
                )
            }
            DataFlowQuery::FindDefs {
                use_address,
                register_id,
            } => {
                format!(
                    "Finding definitions of register {} used at {:#x}",
                    register_id, use_address
                )
            }
        };

        writeln!(f, "{}", query_desc)?;
        writeln!(f, "{}", "=".repeat(60))?;

        if self.steps.is_empty() {
            writeln!(f, "(no results)")?;
        } else {
            for (i, step) in self.steps.iter().enumerate() {
                let arrow = if i == 0 { "→" } else { "↓" };
                write!(
                    f,
                    "{} {:#010x} [{:6}] {}",
                    arrow, step.address, step.role, step.instruction
                )?;
                if let Some(desc) = &step.description {
                    write!(f, "  ; {}", desc)?;
                }
                writeln!(f)?;
            }
        }

        if let Some(reason) = &self.truncation_reason {
            writeln!(f, "\n(Truncated: {})", reason)?;
        }

        if self.complete {
            writeln!(f, "\nTrace complete ({} step(s))", self.steps.len())?;
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hexray_core::{
        Architecture, BasicBlock, BasicBlockId, Immediate, Instruction, Operand, Operation,
        Register, RegisterClass,
    };

    fn make_register(id: u16, _name: &str) -> Register {
        Register::new(Architecture::X86_64, RegisterClass::General, id, 64)
    }

    #[test]
    fn test_trace_backward_simple() {
        let mut cfg = ControlFlowGraph::new(BasicBlockId::new(0));
        let mut bb = BasicBlock::new(BasicBlockId::new(0), 0x1000);

        let rax = make_register(0, "rax");
        let rbx = make_register(3, "rbx");

        // mov rax, 42  (source: constant)
        let mut inst1 = Instruction::new(0x1000, 3, vec![0; 3], "mov rax, 42");
        inst1.operation = Operation::Move;
        inst1.operands = vec![
            Operand::Register(rax),
            Operand::Immediate(Immediate {
                value: 42,
                size: 8,
                signed: false,
            }),
        ];
        bb.push_instruction(inst1);

        // mov rbx, rax  (pass-through)
        let mut inst2 = Instruction::new(0x1003, 3, vec![0; 3], "mov rbx, rax");
        inst2.operation = Operation::Move;
        inst2.operands = vec![Operand::Register(rbx), Operand::Register(rax)];
        bb.push_instruction(inst2);

        // add rbx, 1  (use rbx)
        let mut inst3 = Instruction::new(0x1006, 3, vec![0; 3], "add rbx, 1");
        inst3.operation = Operation::Add;
        inst3.operands = vec![
            Operand::Register(rbx),
            Operand::Immediate(Immediate {
                value: 1,
                size: 8,
                signed: false,
            }),
        ];
        bb.push_instruction(inst3);

        cfg.add_block(bb);

        let engine = DataFlowQueryEngine::new(&cfg);
        let result = engine.query(&DataFlowQuery::TraceBackward {
            address: 0x1006,
            register_id: 3, // rbx
        });

        // Should trace: use at 0x1006 -> def at 0x1003 -> def at 0x1000
        assert!(result.has_results());
        assert!(result.steps.len() >= 2);
    }

    #[test]
    fn test_trace_forward_simple() {
        let mut cfg = ControlFlowGraph::new(BasicBlockId::new(0));
        let mut bb = BasicBlock::new(BasicBlockId::new(0), 0x1000);

        let rax = make_register(0, "rax");

        // mov rax, 42
        let mut inst1 = Instruction::new(0x1000, 3, vec![0; 3], "mov rax, 42");
        inst1.operation = Operation::Move;
        inst1.operands = vec![
            Operand::Register(rax),
            Operand::Immediate(Immediate {
                value: 42,
                size: 8,
                signed: false,
            }),
        ];
        bb.push_instruction(inst1);

        // add rax, 1  (use rax)
        let mut inst2 = Instruction::new(0x1003, 3, vec![0; 3], "add rax, 1");
        inst2.operation = Operation::Add;
        inst2.operands = vec![
            Operand::Register(rax),
            Operand::Immediate(Immediate {
                value: 1,
                size: 8,
                signed: false,
            }),
        ];
        bb.push_instruction(inst2);

        cfg.add_block(bb);

        let engine = DataFlowQueryEngine::new(&cfg);
        let result = engine.query(&DataFlowQuery::TraceForward {
            address: 0x1000,
            register_id: 0, // rax
        });

        // Should find the use at 0x1003
        assert!(result.has_results());
    }

    #[test]
    fn test_find_uses() {
        let mut cfg = ControlFlowGraph::new(BasicBlockId::new(0));
        let mut bb = BasicBlock::new(BasicBlockId::new(0), 0x1000);

        let rax = make_register(0, "rax");

        // mov rax, 42
        let mut inst1 = Instruction::new(0x1000, 3, vec![0; 3], "mov rax, 42");
        inst1.operation = Operation::Move;
        inst1.operands = vec![
            Operand::Register(rax),
            Operand::Immediate(Immediate {
                value: 42,
                size: 8,
                signed: false,
            }),
        ];
        bb.push_instruction(inst1);

        // add rax, 1
        let mut inst2 = Instruction::new(0x1003, 3, vec![0; 3], "add rax, 1");
        inst2.operation = Operation::Add;
        inst2.operands = vec![
            Operand::Register(rax),
            Operand::Immediate(Immediate {
                value: 1,
                size: 8,
                signed: false,
            }),
        ];
        bb.push_instruction(inst2);

        cfg.add_block(bb);

        let engine = DataFlowQueryEngine::new(&cfg);
        let result = engine.query(&DataFlowQuery::FindUses {
            def_address: 0x1000,
            register_id: 0,
        });

        assert!(result.complete);
    }

    // --- DataFlowRole Tests ---

    #[test]
    fn test_dataflow_role_display() {
        assert_eq!(format!("{}", DataFlowRole::Definition), "DEF");
        assert_eq!(format!("{}", DataFlowRole::Use), "USE");
        assert_eq!(format!("{}", DataFlowRole::PassThrough), "PASS");
        assert_eq!(format!("{}", DataFlowRole::Parameter), "PARAM");
        assert_eq!(format!("{}", DataFlowRole::Source), "SOURCE");
    }

    #[test]
    fn test_dataflow_role_equality() {
        assert_eq!(DataFlowRole::Definition, DataFlowRole::Definition);
        assert_ne!(DataFlowRole::Definition, DataFlowRole::Use);
        assert_ne!(DataFlowRole::PassThrough, DataFlowRole::Parameter);
    }

    #[test]
    fn test_dataflow_role_debug() {
        assert!(format!("{:?}", DataFlowRole::Definition).contains("Definition"));
        assert!(format!("{:?}", DataFlowRole::Source).contains("Source"));
    }

    // --- DataFlowStep Tests ---

    #[test]
    fn test_dataflow_step_new() {
        let step = DataFlowStep::new(
            0x1000,
            "mov rax, rbx".to_string(),
            DataFlowRole::PassThrough,
            Location::Register(0),
        );

        assert_eq!(step.address, 0x1000);
        assert_eq!(step.instruction, "mov rax, rbx");
        assert_eq!(step.role, DataFlowRole::PassThrough);
        assert!(step.description.is_none());
    }

    #[test]
    fn test_dataflow_step_with_description() {
        let step = DataFlowStep::new(
            0x1000,
            "mov rax, 42".to_string(),
            DataFlowRole::Source,
            Location::Register(0),
        )
        .with_description("Constant value assignment");

        assert!(step.description.is_some());
        assert_eq!(step.description.unwrap(), "Constant value assignment");
    }

    #[test]
    fn test_dataflow_step_with_stack_location() {
        let step = DataFlowStep::new(
            0x1000,
            "mov [rbp-8], rax".to_string(),
            DataFlowRole::Use,
            Location::Stack(-8),
        );

        assert!(matches!(step.location, Location::Stack(-8)));
    }

    #[test]
    fn test_dataflow_step_with_flags_location() {
        let step = DataFlowStep::new(
            0x1000,
            "cmp rax, rbx".to_string(),
            DataFlowRole::Definition,
            Location::Flags,
        );

        assert!(matches!(step.location, Location::Flags));
    }

    // --- DataFlowResult Tests ---

    #[test]
    fn test_dataflow_result_new() {
        let query = DataFlowQuery::TraceBackward {
            address: 0x1000,
            register_id: 0,
        };
        let result = DataFlowResult::new(query);

        assert!(!result.complete);
        assert!(result.truncation_reason.is_none());
        assert!(result.is_empty());
        assert_eq!(result.len(), 0);
        assert!(!result.has_results());
    }

    #[test]
    fn test_dataflow_result_add_step() {
        let query = DataFlowQuery::TraceForward {
            address: 0x1000,
            register_id: 0,
        };
        let mut result = DataFlowResult::new(query);

        let step = DataFlowStep::new(
            0x1000,
            "mov rax, 42".to_string(),
            DataFlowRole::Source,
            Location::Register(0),
        );
        result.add_step(step);

        assert_eq!(result.len(), 1);
        assert!(result.has_results());
        assert!(!result.is_empty());
    }

    #[test]
    fn test_dataflow_result_mark_complete() {
        let query = DataFlowQuery::FindUses {
            def_address: 0x1000,
            register_id: 0,
        };
        let mut result = DataFlowResult::new(query);
        assert!(!result.complete);

        result.mark_complete();
        assert!(result.complete);
    }

    #[test]
    fn test_dataflow_result_truncate() {
        let query = DataFlowQuery::FindDefs {
            use_address: 0x1000,
            register_id: 0,
        };
        let mut result = DataFlowResult::new(query);

        result.truncate("Maximum depth reached");
        assert!(result.truncation_reason.is_some());
        assert!(result.truncation_reason.unwrap().contains("Maximum depth"));
    }

    #[test]
    fn test_dataflow_result_display_empty() {
        let query = DataFlowQuery::TraceBackward {
            address: 0x1000,
            register_id: 0,
        };
        let result = DataFlowResult::new(query);

        let output = format!("{}", result);
        assert!(output.contains("no results"));
        assert!(output.contains("Tracing backward"));
    }

    #[test]
    fn test_dataflow_result_display_with_steps() {
        let query = DataFlowQuery::TraceForward {
            address: 0x1000,
            register_id: 0,
        };
        let mut result = DataFlowResult::new(query);

        let step = DataFlowStep::new(
            0x1000,
            "mov rax, 42".to_string(),
            DataFlowRole::Source,
            Location::Register(0),
        )
        .with_description("test desc");
        result.add_step(step);
        result.mark_complete();

        let output = format!("{}", result);
        assert!(output.contains("Tracing forward"));
        assert!(output.contains("0x00001000"));
        assert!(output.contains("SOURCE"));
        assert!(output.contains("test desc"));
        assert!(output.contains("Trace complete"));
    }

    #[test]
    fn test_dataflow_result_display_truncated() {
        let query = DataFlowQuery::FindUses {
            def_address: 0x1000,
            register_id: 5,
        };
        let mut result = DataFlowResult::new(query);
        result.truncate("Test truncation reason");

        let output = format!("{}", result);
        assert!(output.contains("Truncated"));
        assert!(output.contains("Test truncation reason"));
    }

    #[test]
    fn test_dataflow_result_display_find_defs() {
        let query = DataFlowQuery::FindDefs {
            use_address: 0x2000,
            register_id: 3,
        };
        let result = DataFlowResult::new(query);

        let output = format!("{}", result);
        assert!(output.contains("Finding definitions"));
        assert!(output.contains("register 3"));
        assert!(output.contains("0x2000"));
    }

    // --- DataFlowQuery Tests ---

    #[test]
    fn test_dataflow_query_debug() {
        let query = DataFlowQuery::TraceBackward {
            address: 0x1000,
            register_id: 0,
        };
        let debug = format!("{:?}", query);
        assert!(debug.contains("TraceBackward"));
        assert!(debug.contains("4096")); // 0x1000 in decimal
    }

    #[test]
    fn test_dataflow_query_clone() {
        let query = DataFlowQuery::TraceForward {
            address: 0x2000,
            register_id: 5,
        };
        let cloned = query.clone();

        if let DataFlowQuery::TraceForward {
            address,
            register_id,
        } = cloned
        {
            assert_eq!(address, 0x2000);
            assert_eq!(register_id, 5);
        } else {
            panic!("Clone didn't preserve variant");
        }
    }

    // --- Edge Case Tests ---

    #[test]
    fn test_trace_backward_nonexistent_address() {
        let mut cfg = ControlFlowGraph::new(BasicBlockId::new(0));
        let bb = BasicBlock::new(BasicBlockId::new(0), 0x1000);
        cfg.add_block(bb);

        let engine = DataFlowQueryEngine::new(&cfg);
        let result = engine.query(&DataFlowQuery::TraceBackward {
            address: 0x9999, // Non-existent
            register_id: 0,
        });

        assert!(!result.has_results());
        assert!(result.truncation_reason.is_some());
        assert!(result.truncation_reason.unwrap().contains("No use"));
    }

    #[test]
    fn test_trace_forward_nonexistent_address() {
        let mut cfg = ControlFlowGraph::new(BasicBlockId::new(0));
        let bb = BasicBlock::new(BasicBlockId::new(0), 0x1000);
        cfg.add_block(bb);

        let engine = DataFlowQueryEngine::new(&cfg);
        let result = engine.query(&DataFlowQuery::TraceForward {
            address: 0x9999,
            register_id: 0,
        });

        assert!(!result.has_results());
        assert!(result.truncation_reason.is_some());
        assert!(result.truncation_reason.unwrap().contains("No definition"));
    }

    #[test]
    fn test_find_uses_nonexistent_def() {
        let mut cfg = ControlFlowGraph::new(BasicBlockId::new(0));
        let bb = BasicBlock::new(BasicBlockId::new(0), 0x1000);
        cfg.add_block(bb);

        let engine = DataFlowQueryEngine::new(&cfg);
        let result = engine.query(&DataFlowQuery::FindUses {
            def_address: 0x9999,
            register_id: 0,
        });

        assert!(result.truncation_reason.is_some());
    }

    #[test]
    fn test_find_defs_nonexistent_use() {
        let mut cfg = ControlFlowGraph::new(BasicBlockId::new(0));
        let bb = BasicBlock::new(BasicBlockId::new(0), 0x1000);
        cfg.add_block(bb);

        let engine = DataFlowQueryEngine::new(&cfg);
        let result = engine.query(&DataFlowQuery::FindDefs {
            use_address: 0x9999,
            register_id: 0,
        });

        assert!(result.truncation_reason.is_some());
        assert!(result.truncation_reason.unwrap().contains("No use"));
    }

    #[test]
    fn test_engine_with_max_depth() {
        let mut cfg = ControlFlowGraph::new(BasicBlockId::new(0));
        let bb = BasicBlock::new(BasicBlockId::new(0), 0x1000);
        cfg.add_block(bb);

        let engine = DataFlowQueryEngine::new(&cfg).with_max_depth(10);

        // Just verify the engine was created with custom depth
        // (can't easily test max depth without complex CFG)
        let result = engine.query(&DataFlowQuery::TraceBackward {
            address: 0x9999,
            register_id: 0,
        });
        assert!(result.truncation_reason.is_some());
    }

    #[test]
    fn test_empty_cfg_query() {
        let mut cfg = ControlFlowGraph::new(BasicBlockId::new(0));
        let bb = BasicBlock::new(BasicBlockId::new(0), 0x1000);
        cfg.add_block(bb);

        let engine = DataFlowQueryEngine::new(&cfg);

        // Query on empty block
        let result = engine.query(&DataFlowQuery::TraceBackward {
            address: 0x1000,
            register_id: 0,
        });

        // Should handle gracefully
        assert!(!result.has_results() || result.truncation_reason.is_some());
    }
}
