//! Call graph construction and analysis.
//!
//! This module provides call graph construction from disassembled functions,
//! tracking caller-callee relationships for program analysis.

use std::collections::{hash_map::Entry, HashMap, HashSet};

use hexray_core::{
    register::x86, BasicBlock, ControlFlow, Instruction, Operand, Operation, Symbol,
};

/// A node in the call graph representing a function.
#[derive(Debug, Clone)]
pub struct CallGraphNode {
    /// The entry address of the function.
    pub address: u64,
    /// The function name (if known from symbols).
    pub name: Option<String>,
    /// Whether this is an external/imported function.
    pub is_external: bool,
}

/// Type of call relationship.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CallType {
    /// Direct call with known target address.
    Direct,
    /// Indirect call through register/memory.
    Indirect,
    /// Tail call (jump used as call).
    TailCall,
}

/// An edge in the call graph representing a call site.
#[derive(Debug, Clone)]
pub struct CallSite {
    /// Address of the call instruction.
    pub call_address: u64,
    /// Type of call.
    pub call_type: CallType,
}

/// An indirect memory call whose base register was materialized in the same function.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct MaterializedIndirectCall {
    /// Address of the indirect call instruction.
    pub call_address: u64,
    /// Materialized base address loaded into the call's base register.
    pub table_base: u64,
    /// Byte offset of the function-pointer field within the referenced record.
    pub deref_offset: u64,
}

/// A call graph representing function call relationships.
#[derive(Debug, Default)]
pub struct CallGraph {
    /// All nodes (functions) in the graph, keyed by entry address.
    nodes: HashMap<u64, CallGraphNode>,
    /// Edges from caller to callees: caller_addr -> [(callee_addr, call_site)].
    outgoing: HashMap<u64, Vec<(u64, CallSite)>>,
    /// Edges from callee to callers: callee_addr -> [(caller_addr, call_site)].
    incoming: HashMap<u64, Vec<(u64, CallSite)>>,
    /// Indirect call sites that couldn't be resolved.
    unresolved_calls: Vec<(u64, u64)>, // (caller_addr, call_instruction_addr)
}

impl CallGraph {
    /// Create a new empty call graph.
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a function node to the graph.
    pub fn add_node(&mut self, address: u64, name: Option<String>, is_external: bool) {
        match self.nodes.entry(address) {
            Entry::Vacant(entry) => {
                entry.insert(CallGraphNode {
                    address,
                    name,
                    is_external,
                });
            }
            Entry::Occupied(mut entry) => {
                let node = entry.get_mut();
                if node.name.is_none() && name.is_some() {
                    node.name = name;
                }
                if is_external {
                    node.is_external = true;
                }
            }
        }
    }

    /// Mark an existing node as external/imported.
    pub fn mark_node_external(&mut self, address: u64) {
        if let Some(node) = self.nodes.get_mut(&address) {
            node.is_external = true;
        }
    }

    /// Add a call edge from caller to callee.
    pub fn add_call(&mut self, caller: u64, callee: u64, call_site: CallSite) {
        self.outgoing
            .entry(caller)
            .or_default()
            .push((callee, call_site.clone()));
        self.incoming
            .entry(callee)
            .or_default()
            .push((caller, call_site));
    }

    /// Record an unresolved indirect call.
    pub fn add_unresolved_call(&mut self, caller: u64, call_address: u64) {
        self.unresolved_calls.push((caller, call_address));
    }

    /// Get a node by address.
    pub fn get_node(&self, address: u64) -> Option<&CallGraphNode> {
        self.nodes.get(&address)
    }

    /// Get all nodes in the graph.
    pub fn nodes(&self) -> impl Iterator<Item = &CallGraphNode> {
        self.nodes.values()
    }

    /// Get the number of functions in the graph.
    pub fn node_count(&self) -> usize {
        self.nodes.len()
    }

    /// Get all functions called by the given function.
    pub fn callees(&self, caller: u64) -> impl Iterator<Item = (u64, &CallSite)> {
        self.outgoing
            .get(&caller)
            .into_iter()
            .flat_map(|v| v.iter().map(|(addr, site)| (*addr, site)))
    }

    /// Get all functions that call the given function.
    pub fn callers(&self, callee: u64) -> impl Iterator<Item = (u64, &CallSite)> {
        self.incoming
            .get(&callee)
            .into_iter()
            .flat_map(|v| v.iter().map(|(addr, site)| (*addr, site)))
    }

    /// Get the number of call edges in the graph.
    pub fn edge_count(&self) -> usize {
        self.outgoing.values().map(|v| v.len()).sum()
    }

    /// Get unresolved indirect calls.
    pub fn unresolved_calls(&self) -> &[(u64, u64)] {
        &self.unresolved_calls
    }

    /// Check if a function is recursive (calls itself directly or indirectly).
    pub fn is_recursive(&self, address: u64) -> bool {
        let mut visited = HashSet::new();
        let mut stack = vec![address];

        while let Some(current) = stack.pop() {
            if !visited.insert(current) {
                continue;
            }

            for (callee, _) in self.callees(current) {
                if callee == address {
                    return true;
                }
                if !visited.contains(&callee) {
                    stack.push(callee);
                }
            }
        }

        false
    }

    /// Get all functions reachable from the given entry point.
    pub fn reachable_from(&self, entry: u64) -> HashSet<u64> {
        let mut reachable = HashSet::new();
        let mut stack = vec![entry];

        while let Some(current) = stack.pop() {
            if !reachable.insert(current) {
                continue;
            }

            for (callee, _) in self.callees(current) {
                if !reachable.contains(&callee) {
                    stack.push(callee);
                }
            }
        }

        reachable
    }

    /// Build a call graph containing only the nodes reachable from the entry.
    pub fn subgraph_from(&self, entry: u64) -> Self {
        let reachable = self.reachable_from(entry);
        let mut subgraph = Self::new();

        for address in &reachable {
            if let Some(node) = self.get_node(*address) {
                subgraph.add_node(node.address, node.name.clone(), node.is_external);
            }
        }

        for &caller in &reachable {
            for (callee, call_site) in self.callees(caller) {
                if reachable.contains(&callee) {
                    subgraph.add_call(caller, callee, call_site.clone());
                }
            }
        }

        for &(caller, call_address) in &self.unresolved_calls {
            if reachable.contains(&caller) {
                subgraph.add_unresolved_call(caller, call_address);
            }
        }

        subgraph
    }

    /// Find leaf functions (functions that don't call any other functions).
    pub fn leaf_functions(&self) -> Vec<u64> {
        self.nodes
            .keys()
            .filter(|&&addr| {
                self.outgoing
                    .get(&addr)
                    .map(|v| v.is_empty())
                    .unwrap_or(true)
            })
            .copied()
            .collect()
    }

    /// Find root functions (functions that are not called by any other function).
    pub fn root_functions(&self) -> Vec<u64> {
        self.nodes
            .keys()
            .filter(|&&addr| {
                self.incoming
                    .get(&addr)
                    .map(|v| v.is_empty())
                    .unwrap_or(true)
            })
            .copied()
            .collect()
    }

    /// Compute a topological order of functions (if acyclic).
    /// Returns None if the call graph contains cycles.
    pub fn topological_order(&self) -> Option<Vec<u64>> {
        let mut in_degree: HashMap<u64, usize> = HashMap::new();
        for &addr in self.nodes.keys() {
            in_degree.insert(addr, 0);
        }

        for edges in self.outgoing.values() {
            for (callee, _) in edges {
                *in_degree.entry(*callee).or_insert(0) += 1;
            }
        }

        let mut queue: Vec<u64> = in_degree
            .iter()
            .filter(|(_, &deg)| deg == 0)
            .map(|(&addr, _)| addr)
            .collect();

        let mut result = Vec::new();

        while let Some(node) = queue.pop() {
            result.push(node);
            if let Some(edges) = self.outgoing.get(&node) {
                for (callee, _) in edges {
                    if let Some(deg) = in_degree.get_mut(callee) {
                        *deg -= 1;
                        if *deg == 0 {
                            queue.push(*callee);
                        }
                    }
                }
            }
        }

        if result.len() == self.nodes.len() {
            Some(result)
        } else {
            None // Cycle detected
        }
    }
}

/// Builder for constructing a call graph from disassembled code.
pub struct CallGraphBuilder {
    call_graph: CallGraph,
    /// Maps function entry addresses to their instructions.
    function_instructions: HashMap<u64, Vec<Instruction>>,
    /// Optional indirect call resolver for resolving indirect calls.
    indirect_resolver: Option<crate::IndirectCallResolver>,
}

impl CallGraphBuilder {
    /// Create a new call graph builder.
    pub fn new() -> Self {
        Self {
            call_graph: CallGraph::new(),
            function_instructions: HashMap::new(),
            indirect_resolver: None,
        }
    }

    /// Sets an indirect call resolver for resolving indirect calls during build.
    ///
    /// When set, the builder will attempt to resolve indirect calls and add
    /// the resolved targets as edges in the call graph with `CallType::Indirect`.
    pub fn with_indirect_resolver(mut self, resolver: crate::IndirectCallResolver) -> Self {
        self.indirect_resolver = Some(resolver);
        self
    }

    /// Add symbols to populate function names.
    pub fn add_symbols(&mut self, symbols: &[Symbol]) {
        for symbol in symbols {
            if symbol.is_function() {
                self.call_graph.add_node(
                    symbol.address,
                    Some(symbol.name.clone()),
                    Self::symbol_is_external(symbol),
                );
            }
        }
    }

    fn symbol_is_external(symbol: &Symbol) -> bool {
        !symbol.is_defined() || symbol.is_plt()
    }

    /// Add a function's instructions for analysis.
    pub fn add_function(&mut self, entry: u64, instructions: Vec<Instruction>) {
        // Ensure the function node exists
        if !self.call_graph.nodes.contains_key(&entry) {
            self.call_graph.add_node(entry, None, false);
        }
        self.function_instructions.insert(entry, instructions);
    }

    /// Add a function from basic blocks.
    pub fn add_function_blocks(&mut self, entry: u64, blocks: &[BasicBlock]) {
        let mut instructions = Vec::new();
        for block in blocks {
            instructions.extend(block.instructions.iter().cloned());
        }
        self.add_function(entry, instructions);
    }

    /// Build the call graph by analyzing all added functions.
    pub fn build(mut self) -> CallGraph {
        // Analyze each function's instructions for calls
        let functions: Vec<_> = self.function_instructions.iter().collect();

        for (&caller_entry, instructions) in &functions {
            // First, try to resolve indirect calls using the resolver
            let resolved_indirect_calls = self
                .indirect_resolver
                .as_ref()
                .map(|resolver| resolver.analyze(instructions));

            for instr in *instructions {
                match &instr.control_flow {
                    ControlFlow::Call { target, .. } => {
                        // Ensure callee node exists
                        if !self.call_graph.nodes.contains_key(target) {
                            self.call_graph.add_node(*target, None, false);
                        }

                        self.call_graph.add_call(
                            caller_entry,
                            *target,
                            CallSite {
                                call_address: instr.address,
                                call_type: CallType::Direct,
                            },
                        );
                    }
                    ControlFlow::IndirectCall { .. } => {
                        // Try to find a resolution for this indirect call
                        let resolved = resolved_indirect_calls.as_ref().and_then(|resolutions| {
                            resolutions.iter().find(|r| r.call_site == instr.address)
                        });

                        if let Some(resolution) = resolved {
                            if resolution.is_resolved() {
                                // Add edges for all resolved targets
                                for &target in &resolution.possible_targets {
                                    if !self.call_graph.nodes.contains_key(&target) {
                                        self.call_graph.add_node(target, None, false);
                                    }
                                    self.call_graph.add_call(
                                        caller_entry,
                                        target,
                                        CallSite {
                                            call_address: instr.address,
                                            call_type: CallType::Indirect,
                                        },
                                    );
                                }
                            } else {
                                // Record as unresolved
                                self.call_graph
                                    .add_unresolved_call(caller_entry, instr.address);
                            }
                        } else {
                            // No resolver or no resolution found
                            self.call_graph
                                .add_unresolved_call(caller_entry, instr.address);
                        }
                    }
                    _ => {}
                }
            }

            for instr in *instructions {
                for target in self.materialized_function_targets(instr) {
                    self.call_graph.add_call(
                        caller_entry,
                        target,
                        CallSite {
                            call_address: instr.address,
                            call_type: CallType::Indirect,
                        },
                    );
                }
            }
        }

        self.call_graph
    }

    fn materialized_function_targets(&self, instr: &Instruction) -> Vec<u64> {
        materialized_source_address(instr)
            .filter(|addr| *addr != 0)
            .filter(|addr| self.is_known_internal_function(*addr))
            .into_iter()
            .collect()
    }

    fn is_known_internal_function(&self, addr: u64) -> bool {
        self.call_graph
            .get_node(addr)
            .is_some_and(|node| !node.is_external)
            || self.function_instructions.contains_key(&addr)
    }
}

impl Default for CallGraphBuilder {
    fn default() -> Self {
        Self::new()
    }
}

/// Discover indirect memory calls that dereference a register-backed materialized address.
pub fn discover_materialized_indirect_calls(
    instructions: &[Instruction],
) -> Vec<MaterializedIndirectCall> {
    let mut register_values = HashMap::new();
    let mut seen = HashSet::new();
    let mut discoveries = Vec::new();

    for instr in instructions {
        let tracked_assignment = tracked_register_assignment(instr, &register_values);

        for reg in &instr.writes {
            register_values.remove(&reg.id);
        }
        if let Some((dest_reg, value)) = tracked_assignment {
            register_values.insert(dest_reg, value);
        }

        let Some(Operand::Memory(mem)) = instr.operands.first() else {
            continue;
        };
        if !matches!(instr.control_flow, ControlFlow::IndirectCall { .. }) {
            continue;
        }
        let Some(base_reg) = mem.base.as_ref() else {
            continue;
        };
        let Some(table_base) = register_values.get(&base_reg.id).copied() else {
            continue;
        };
        let Ok(deref_offset) = u64::try_from(mem.displacement) else {
            continue;
        };

        let discovery = MaterializedIndirectCall {
            call_address: instr.address,
            table_base,
            deref_offset,
        };
        if seen.insert(discovery.clone()) {
            discoveries.push(discovery);
        }
    }

    discoveries
}

fn tracked_register_assignment(
    instr: &Instruction,
    register_values: &HashMap<u16, u64>,
) -> Option<(u16, u64)> {
    let dest_reg = match instr.operands.first() {
        Some(Operand::Register(reg)) => reg.id,
        _ => return None,
    };

    match instr.operation {
        Operation::Move | Operation::LoadEffectiveAddress => {
            let source = instr.operands.get(1)?;
            materialized_source_address(instr)
                .or_else(|| match source {
                    Operand::Register(reg) => register_values.get(&reg.id).copied(),
                    Operand::Memory(mem)
                        if matches!(instr.operation, Operation::LoadEffectiveAddress)
                            && mem.index.is_none() =>
                    {
                        mem.base
                            .as_ref()
                            .and_then(|reg| register_values.get(&reg.id).copied())
                    }
                    _ => None,
                })
                .map(|value| (dest_reg, value))
        }
        Operation::Add | Operation::Sub
            if matches!(instr.operands.get(1), Some(Operand::Immediate(_))) =>
        {
            register_values
                .get(&dest_reg)
                .copied()
                .map(|value| (dest_reg, value))
        }
        _ => None,
    }
}

fn materialized_source_address(instr: &Instruction) -> Option<u64> {
    let Some(Operand::Register(_)) = instr.operands.first() else {
        return None;
    };

    let source = match instr.operation {
        Operation::Move | Operation::LoadEffectiveAddress => instr.operands.get(1),
        _ => None,
    }?;

    match source {
        Operand::Immediate(imm) => Some(imm.value as u64),
        Operand::PcRelative { target, .. } => Some(*target),
        Operand::Memory(mem)
            if matches!(instr.operation, Operation::LoadEffectiveAddress)
                && mem.base.as_ref().map(|reg| reg.id) == Some(x86::RIP)
                && mem.index.is_none() =>
        {
            Some((instr.address + instr.size as u64).wrapping_add(mem.displacement as u64))
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hexray_core::{
        register::x86, Architecture, ControlFlow, Immediate, IndexMode, Instruction, MemoryRef,
        Operand, Operation, Register, RegisterClass, Symbol, SymbolKind,
    };

    fn make_call_instruction(addr: u64, target: u64) -> Instruction {
        Instruction {
            address: addr,
            size: 4,
            operation: Operation::Call,
            mnemonic: "call".to_string(),
            operands: vec![Operand::Immediate(Immediate {
                value: target as i128,
                size: 64,
                signed: false,
            })],
            control_flow: ControlFlow::Call {
                target,
                return_addr: addr + 4,
            },
            bytes: vec![0xe8, 0, 0, 0, 0],
            reads: vec![],
            writes: vec![],

            guard: None,
        }
    }

    fn make_ret_instruction(addr: u64) -> Instruction {
        Instruction {
            address: addr,
            size: 1,
            operation: Operation::Return,
            mnemonic: "ret".to_string(),
            operands: vec![],
            control_flow: ControlFlow::Return,
            bytes: vec![0xc3],
            reads: vec![],
            writes: vec![],

            guard: None,
        }
    }

    fn make_nop_instruction(addr: u64) -> Instruction {
        Instruction {
            address: addr,
            size: 1,
            operation: Operation::Nop,
            mnemonic: "nop".to_string(),
            operands: vec![],
            control_flow: ControlFlow::Sequential,
            bytes: vec![0x90],
            reads: vec![],
            writes: vec![],

            guard: None,
        }
    }

    fn make_stack_store_imm_instruction(addr: u64, imm_value: u64) -> Instruction {
        Instruction {
            address: addr,
            size: 8,
            operation: Operation::Move,
            mnemonic: "mov".to_string(),
            operands: vec![
                Operand::Memory(MemoryRef {
                    base: Some(Register::new(
                        Architecture::X86_64,
                        RegisterClass::General,
                        x86::RBP,
                        64,
                    )),
                    index: None,
                    scale: 1,
                    displacement: -8,
                    size: 8,
                    segment: None,
                    broadcast: false,
                    index_mode: IndexMode::None,
                    space: hexray_core::MemorySpace::Generic,
                }),
                Operand::Immediate(Immediate {
                    value: imm_value as i128,
                    size: 64,
                    signed: false,
                }),
            ],
            control_flow: ControlFlow::Sequential,
            bytes: vec![0; 8],
            reads: vec![],
            writes: vec![],

            guard: None,
        }
    }

    fn make_move_reg_reg_instruction(addr: u64, dest_id: u16, src_id: u16) -> Instruction {
        let dest = Register::new(Architecture::X86_64, RegisterClass::General, dest_id, 64);
        let src = Register::new(Architecture::X86_64, RegisterClass::General, src_id, 64);
        Instruction {
            address: addr,
            size: 3,
            operation: Operation::Move,
            mnemonic: "mov".to_string(),
            operands: vec![Operand::Register(dest), Operand::Register(src)],
            control_flow: ControlFlow::Sequential,
            bytes: vec![0; 3],
            reads: vec![src],
            writes: vec![dest],
            guard: None,
        }
    }

    fn make_move_reg_imm_instruction(addr: u64, dest_id: u16, imm_value: u64) -> Instruction {
        let dest = Register::new(Architecture::X86_64, RegisterClass::General, dest_id, 64);
        Instruction {
            address: addr,
            size: 7,
            operation: Operation::Move,
            mnemonic: "mov".to_string(),
            operands: vec![
                Operand::Register(dest),
                Operand::Immediate(Immediate {
                    value: imm_value as i128,
                    size: 64,
                    signed: false,
                }),
            ],
            control_flow: ControlFlow::Sequential,
            bytes: vec![0; 7],
            reads: vec![],
            writes: vec![dest],
            guard: None,
        }
    }

    fn make_load_effective_address_instruction(
        addr: u64,
        dest_id: u16,
        target: u64,
    ) -> Instruction {
        let dest = Register::new(Architecture::X86_64, RegisterClass::General, dest_id, 64);
        let next = addr + 7;
        let displacement = target.wrapping_sub(next) as i64;
        Instruction {
            address: addr,
            size: 7,
            operation: Operation::LoadEffectiveAddress,
            mnemonic: "lea".to_string(),
            operands: vec![
                Operand::Register(dest),
                Operand::Memory(MemoryRef {
                    base: Some(Register::new(
                        Architecture::X86_64,
                        RegisterClass::General,
                        x86::RIP,
                        64,
                    )),
                    index: None,
                    scale: 1,
                    displacement,
                    size: 8,
                    segment: None,
                    broadcast: false,
                    index_mode: IndexMode::None,
                    space: hexray_core::MemorySpace::Generic,
                }),
            ],
            control_flow: ControlFlow::Sequential,
            bytes: vec![0; 7],
            reads: vec![],
            writes: vec![dest],
            guard: None,
        }
    }

    fn make_indirect_call_instruction(
        addr: u64,
        base_id: u16,
        index_id: u16,
        displacement: i64,
    ) -> Instruction {
        let base = Register::new(Architecture::X86_64, RegisterClass::General, base_id, 64);
        let index = Register::new(Architecture::X86_64, RegisterClass::General, index_id, 64);
        Instruction {
            address: addr,
            size: 5,
            operation: Operation::Call,
            mnemonic: "call".to_string(),
            operands: vec![Operand::Memory(MemoryRef {
                base: Some(base),
                index: Some(index),
                scale: 1,
                displacement,
                size: 8,
                segment: None,
                broadcast: false,
                index_mode: IndexMode::None,
                space: hexray_core::MemorySpace::Generic,
            })],
            control_flow: ControlFlow::IndirectCall {
                return_addr: addr + 5,
            },
            bytes: vec![0; 5],
            reads: vec![base, index],
            writes: vec![],
            guard: None,
        }
    }

    fn make_add_reg_imm_instruction(addr: u64, reg_id: u16, imm_value: i64) -> Instruction {
        let dest = Register::new(Architecture::X86_64, RegisterClass::General, reg_id, 64);
        Instruction {
            address: addr,
            size: 4,
            operation: Operation::Add,
            mnemonic: "add".to_string(),
            operands: vec![
                Operand::Register(dest),
                Operand::Immediate(Immediate {
                    value: imm_value as i128,
                    size: 32,
                    signed: true,
                }),
            ],
            control_flow: ControlFlow::Sequential,
            bytes: vec![0; 4],
            reads: vec![dest],
            writes: vec![dest],
            guard: None,
        }
    }

    #[test]
    fn test_empty_call_graph() {
        let cg = CallGraph::new();
        assert_eq!(cg.node_count(), 0);
        assert_eq!(cg.edge_count(), 0);
    }

    #[test]
    fn test_add_nodes() {
        let mut cg = CallGraph::new();
        cg.add_node(0x1000, Some("main".to_string()), false);
        cg.add_node(0x2000, Some("helper".to_string()), false);
        cg.add_node(0x3000, None, true); // external

        assert_eq!(cg.node_count(), 3);
        assert_eq!(cg.get_node(0x1000).unwrap().name.as_deref(), Some("main"));
        assert!(cg.get_node(0x3000).unwrap().is_external);
    }

    #[test]
    fn test_add_calls() {
        let mut cg = CallGraph::new();
        cg.add_node(0x1000, Some("main".to_string()), false);
        cg.add_node(0x2000, Some("foo".to_string()), false);
        cg.add_node(0x3000, Some("bar".to_string()), false);

        cg.add_call(
            0x1000,
            0x2000,
            CallSite {
                call_address: 0x1010,
                call_type: CallType::Direct,
            },
        );
        cg.add_call(
            0x1000,
            0x3000,
            CallSite {
                call_address: 0x1020,
                call_type: CallType::Direct,
            },
        );
        cg.add_call(
            0x2000,
            0x3000,
            CallSite {
                call_address: 0x2010,
                call_type: CallType::Direct,
            },
        );

        assert_eq!(cg.edge_count(), 3);

        // main calls foo and bar
        let main_callees: Vec<_> = cg.callees(0x1000).map(|(a, _)| a).collect();
        assert_eq!(main_callees.len(), 2);
        assert!(main_callees.contains(&0x2000));
        assert!(main_callees.contains(&0x3000));

        // bar is called by main and foo
        let bar_callers: Vec<_> = cg.callers(0x3000).map(|(a, _)| a).collect();
        assert_eq!(bar_callers.len(), 2);
        assert!(bar_callers.contains(&0x1000));
        assert!(bar_callers.contains(&0x2000));
    }

    #[test]
    fn test_leaf_and_root_functions() {
        let mut cg = CallGraph::new();
        cg.add_node(0x1000, Some("main".to_string()), false);
        cg.add_node(0x2000, Some("foo".to_string()), false);
        cg.add_node(0x3000, Some("bar".to_string()), false);

        // main -> foo -> bar
        cg.add_call(
            0x1000,
            0x2000,
            CallSite {
                call_address: 0x1010,
                call_type: CallType::Direct,
            },
        );
        cg.add_call(
            0x2000,
            0x3000,
            CallSite {
                call_address: 0x2010,
                call_type: CallType::Direct,
            },
        );

        let leaves = cg.leaf_functions();
        assert_eq!(leaves.len(), 1);
        assert!(leaves.contains(&0x3000));

        let roots = cg.root_functions();
        assert_eq!(roots.len(), 1);
        assert!(roots.contains(&0x1000));
    }

    #[test]
    fn test_recursive_detection() {
        let mut cg = CallGraph::new();
        cg.add_node(0x1000, Some("recursive".to_string()), false);
        cg.add_node(0x2000, Some("helper".to_string()), false);

        // recursive calls itself
        cg.add_call(
            0x1000,
            0x1000,
            CallSite {
                call_address: 0x1010,
                call_type: CallType::Direct,
            },
        );
        // recursive also calls helper
        cg.add_call(
            0x1000,
            0x2000,
            CallSite {
                call_address: 0x1020,
                call_type: CallType::Direct,
            },
        );

        assert!(cg.is_recursive(0x1000));
        assert!(!cg.is_recursive(0x2000));
    }

    #[test]
    fn test_mutual_recursion() {
        let mut cg = CallGraph::new();
        cg.add_node(0x1000, Some("a".to_string()), false);
        cg.add_node(0x2000, Some("b".to_string()), false);

        // a calls b, b calls a
        cg.add_call(
            0x1000,
            0x2000,
            CallSite {
                call_address: 0x1010,
                call_type: CallType::Direct,
            },
        );
        cg.add_call(
            0x2000,
            0x1000,
            CallSite {
                call_address: 0x2010,
                call_type: CallType::Direct,
            },
        );

        assert!(cg.is_recursive(0x1000));
        assert!(cg.is_recursive(0x2000));
    }

    #[test]
    fn test_reachable_from() {
        let mut cg = CallGraph::new();
        cg.add_node(0x1000, Some("main".to_string()), false);
        cg.add_node(0x2000, Some("foo".to_string()), false);
        cg.add_node(0x3000, Some("bar".to_string()), false);
        cg.add_node(0x4000, Some("unreachable".to_string()), false);

        // main -> foo -> bar
        cg.add_call(
            0x1000,
            0x2000,
            CallSite {
                call_address: 0x1010,
                call_type: CallType::Direct,
            },
        );
        cg.add_call(
            0x2000,
            0x3000,
            CallSite {
                call_address: 0x2010,
                call_type: CallType::Direct,
            },
        );

        let reachable = cg.reachable_from(0x1000);
        assert!(reachable.contains(&0x1000));
        assert!(reachable.contains(&0x2000));
        assert!(reachable.contains(&0x3000));
        assert!(!reachable.contains(&0x4000));
    }

    #[test]
    fn test_subgraph_from_filters_unreachable_nodes() {
        let mut cg = CallGraph::new();
        cg.add_node(0x1000, Some("main".to_string()), false);
        cg.add_node(0x2000, Some("foo".to_string()), false);
        cg.add_node(0x3000, Some("bar".to_string()), false);
        cg.add_node(0x4000, Some("dead".to_string()), false);

        cg.add_call(
            0x1000,
            0x2000,
            CallSite {
                call_address: 0x1010,
                call_type: CallType::Direct,
            },
        );
        cg.add_call(
            0x2000,
            0x3000,
            CallSite {
                call_address: 0x2010,
                call_type: CallType::Direct,
            },
        );
        cg.add_call(
            0x4000,
            0x3000,
            CallSite {
                call_address: 0x4010,
                call_type: CallType::Direct,
            },
        );
        cg.add_unresolved_call(0x1000, 0x1020);
        cg.add_unresolved_call(0x4000, 0x4020);

        let subgraph = cg.subgraph_from(0x1000);

        assert_eq!(subgraph.node_count(), 3);
        assert_eq!(subgraph.edge_count(), 2);
        assert!(subgraph.get_node(0x1000).is_some());
        assert!(subgraph.get_node(0x2000).is_some());
        assert!(subgraph.get_node(0x3000).is_some());
        assert!(subgraph.get_node(0x4000).is_none());
        assert_eq!(subgraph.unresolved_calls(), &[(0x1000, 0x1020)]);
    }

    #[test]
    fn test_topological_order_acyclic() {
        let mut cg = CallGraph::new();
        cg.add_node(0x1000, Some("main".to_string()), false);
        cg.add_node(0x2000, Some("foo".to_string()), false);
        cg.add_node(0x3000, Some("bar".to_string()), false);

        // main -> foo -> bar
        cg.add_call(
            0x1000,
            0x2000,
            CallSite {
                call_address: 0x1010,
                call_type: CallType::Direct,
            },
        );
        cg.add_call(
            0x2000,
            0x3000,
            CallSite {
                call_address: 0x2010,
                call_type: CallType::Direct,
            },
        );

        let order = cg.topological_order();
        assert!(order.is_some());
        let order = order.unwrap();
        assert_eq!(order.len(), 3);

        // main should come before foo, foo before bar
        let main_pos = order.iter().position(|&x| x == 0x1000).unwrap();
        let foo_pos = order.iter().position(|&x| x == 0x2000).unwrap();
        let bar_pos = order.iter().position(|&x| x == 0x3000).unwrap();
        assert!(main_pos < foo_pos);
        assert!(foo_pos < bar_pos);
    }

    #[test]
    fn test_topological_order_cyclic() {
        let mut cg = CallGraph::new();
        cg.add_node(0x1000, Some("a".to_string()), false);
        cg.add_node(0x2000, Some("b".to_string()), false);

        // Cycle: a -> b -> a
        cg.add_call(
            0x1000,
            0x2000,
            CallSite {
                call_address: 0x1010,
                call_type: CallType::Direct,
            },
        );
        cg.add_call(
            0x2000,
            0x1000,
            CallSite {
                call_address: 0x2010,
                call_type: CallType::Direct,
            },
        );

        assert!(cg.topological_order().is_none());
    }

    #[test]
    fn test_builder_basic() {
        let mut builder = CallGraphBuilder::new();

        // main at 0x1000 calls foo at 0x2000
        let main_instrs = vec![
            make_nop_instruction(0x1000),
            make_call_instruction(0x1010, 0x2000),
            make_ret_instruction(0x1014),
        ];
        builder.add_function(0x1000, main_instrs);

        // foo at 0x2000 is a leaf
        let foo_instrs = vec![make_nop_instruction(0x2000), make_ret_instruction(0x2001)];
        builder.add_function(0x2000, foo_instrs);

        let cg = builder.build();

        assert_eq!(cg.node_count(), 2);
        assert_eq!(cg.edge_count(), 1);

        let main_callees: Vec<_> = cg.callees(0x1000).map(|(a, _)| a).collect();
        assert_eq!(main_callees, vec![0x2000]);
    }

    #[test]
    fn test_builder_with_symbols() {
        let mut builder = CallGraphBuilder::new();

        let symbols = vec![
            Symbol {
                name: "main".to_string(),
                address: 0x1000,
                size: 0x20,
                kind: SymbolKind::Function,
                binding: hexray_core::SymbolBinding::Global,
                section_index: Some(1),
            },
            Symbol {
                name: "printf".to_string(),
                address: 0x0,
                size: 0,
                kind: SymbolKind::Function,
                binding: hexray_core::SymbolBinding::Global,
                section_index: None, // undefined/external
            },
        ];

        builder.add_symbols(&symbols);

        let cg = builder.build();

        assert_eq!(cg.node_count(), 2);
        assert_eq!(cg.get_node(0x1000).unwrap().name.as_deref(), Some("main"));
        assert!(cg.get_node(0x0).unwrap().is_external);
    }

    #[test]
    fn test_add_node_upgrades_existing_name_and_externality() {
        let mut cg = CallGraph::new();

        cg.add_node(0x401000, None, false);
        cg.add_node(0x401000, Some("puts@GLIBC_2.2.5@plt".to_string()), true);

        let node = cg.get_node(0x401000).unwrap();
        assert_eq!(node.name.as_deref(), Some("puts@GLIBC_2.2.5@plt"));
        assert!(node.is_external);
    }

    #[test]
    fn test_builder_marks_plt_symbols_external() {
        let mut builder = CallGraphBuilder::new();

        builder.add_symbols(&[Symbol {
            name: "puts@GLIBC_2.2.5@plt".to_string(),
            address: 0x401020,
            size: 16,
            kind: SymbolKind::Function,
            binding: hexray_core::SymbolBinding::Global,
            section_index: None,
        }]);

        let cg = builder.build();

        assert!(cg.get_node(0x401020).unwrap().is_external);
    }

    #[test]
    fn test_builder_adds_materialized_register_function_pointer_edges() {
        let mut builder = CallGraphBuilder::new();
        builder.add_symbols(&[
            Symbol {
                name: "main".to_string(),
                address: 0x1000,
                size: 0x20,
                kind: SymbolKind::Function,
                binding: hexray_core::SymbolBinding::Global,
                section_index: Some(1),
            },
            Symbol {
                name: "dispatcher".to_string(),
                address: 0x2000,
                size: 0x20,
                kind: SymbolKind::Function,
                binding: hexray_core::SymbolBinding::Global,
                section_index: Some(1),
            },
            Symbol {
                name: "add_op".to_string(),
                address: 0x3000,
                size: 0x20,
                kind: SymbolKind::Function,
                binding: hexray_core::SymbolBinding::Global,
                section_index: Some(1),
            },
        ]);

        builder.add_function(
            0x1000,
            vec![
                make_move_reg_imm_instruction(0x1000, x86::RAX, 0x3000),
                make_call_instruction(0x1008, 0x2000),
                make_ret_instruction(0x100c),
            ],
        );
        builder.add_function(0x2000, vec![make_ret_instruction(0x2000)]);
        builder.add_function(0x3000, vec![make_ret_instruction(0x3000)]);

        let cg = builder.build();

        let main_callees: Vec<_> = cg.callees(0x1000).map(|(addr, _)| addr).collect();
        assert!(main_callees.contains(&0x2000));
        assert!(main_callees.contains(&0x3000));
    }

    #[test]
    fn test_builder_ignores_materialized_function_store_edges() {
        let mut builder = CallGraphBuilder::new();
        builder.add_symbols(&[
            Symbol {
                name: "main".to_string(),
                address: 0x1000,
                size: 0x20,
                kind: SymbolKind::Function,
                binding: hexray_core::SymbolBinding::Global,
                section_index: Some(1),
            },
            Symbol {
                name: "dispatcher".to_string(),
                address: 0x2000,
                size: 0x20,
                kind: SymbolKind::Function,
                binding: hexray_core::SymbolBinding::Global,
                section_index: Some(1),
            },
            Symbol {
                name: "helper".to_string(),
                address: 0x3000,
                size: 0x20,
                kind: SymbolKind::Function,
                binding: hexray_core::SymbolBinding::Global,
                section_index: Some(1),
            },
        ]);

        builder.add_function(
            0x1000,
            vec![
                make_stack_store_imm_instruction(0x1000, 0x3000),
                make_call_instruction(0x1008, 0x2000),
                make_ret_instruction(0x100c),
            ],
        );
        builder.add_function(0x2000, vec![make_ret_instruction(0x2000)]);
        builder.add_function(0x3000, vec![make_ret_instruction(0x3000)]);

        let cg = builder.build();

        let main_callees: Vec<_> = cg.callees(0x1000).map(|(addr, _)| addr).collect();
        assert!(main_callees.contains(&0x2000));
        assert!(!main_callees.contains(&0x3000));
    }

    #[test]
    fn test_builder_ignores_materialized_null_function_targets() {
        let mut builder = CallGraphBuilder::new();
        builder.add_symbols(&[
            Symbol {
                name: "main".to_string(),
                address: 0x1000,
                size: 0x20,
                kind: SymbolKind::Function,
                binding: hexray_core::SymbolBinding::Global,
                section_index: Some(1),
            },
            Symbol {
                name: "bogus_zero".to_string(),
                address: 0x0,
                size: 0x20,
                kind: SymbolKind::Function,
                binding: hexray_core::SymbolBinding::Global,
                section_index: Some(1),
            },
        ]);

        builder.add_function(
            0x1000,
            vec![
                make_move_reg_imm_instruction(0x1000, x86::RAX, 0),
                make_ret_instruction(0x1007),
            ],
        );

        let cg = builder.build();

        let main_callees: Vec<_> = cg.callees(0x1000).map(|(addr, _)| addr).collect();
        assert!(!main_callees.contains(&0x0));
    }

    #[test]
    fn test_discover_materialized_indirect_calls_tracks_lea_and_register_copies() {
        let discoveries = discover_materialized_indirect_calls(&[
            make_load_effective_address_instruction(0x1000, x86::R14, 0x1554c0),
            make_move_reg_reg_instruction(0x1007, x86::RBX, x86::R14),
            make_indirect_call_instruction(0x100a, x86::RBX, x86::R13, 0x8),
        ]);

        assert_eq!(
            discoveries,
            vec![MaterializedIndirectCall {
                call_address: 0x100a,
                table_base: 0x1554c0,
                deref_offset: 0x8,
            }]
        );
    }

    #[test]
    fn test_discover_materialized_indirect_calls_preserves_table_origin_through_add() {
        let discoveries = discover_materialized_indirect_calls(&[
            make_load_effective_address_instruction(0x1000, x86::RBX, 0x1554c0),
            make_add_reg_imm_instruction(0x1007, x86::RBX, 0x10),
            make_indirect_call_instruction(0x100b, x86::RBX, x86::R13, 0x8),
        ]);

        assert_eq!(
            discoveries,
            vec![MaterializedIndirectCall {
                call_address: 0x100b,
                table_base: 0x1554c0,
                deref_offset: 0x8,
            }]
        );
    }
}
