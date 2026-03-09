----------------------------- MODULE IncrementalInvalidation -----------------------------
EXTENDS Integers, TLC

CONSTANTS PatchAddresses, OldLens, NewLens

Funcs == 1..3

InitialFunc(f) ==
    CASE f = 1 -> [start |-> 10, size |-> 5]
         [] f = 2 -> [start |-> 20, size |-> 6]
         [] OTHER -> [start |-> 30, size |-> 4]
FuncEnd(fn) == fn.start + fn.size
PatchEnd(p) == p.addr + p.oldLen
PatchDelta(p) == p.newLen - p.oldLen
LayoutChange(p) == PatchDelta(p) /= 0
ReplacementEnd(p) == p.addr + p.newLen

PatchCases ==
    {
        [addr |-> addr, oldLen |-> oldLen, newLen |-> newLen] :
            addr \in PatchAddresses,
            oldLen \in OldLens,
            newLen \in NewLens
    }
    \ {
        [addr |-> addr, oldLen |-> 0, newLen |-> 0] :
            addr \in PatchAddresses
    }

Affected(fn, p) ==
    IF LayoutChange(p)
    THEN FuncEnd(fn) > p.addr
    ELSE fn.start < PatchEnd(p) /\ FuncEnd(fn) > p.addr

TransformStart(fn, p) ==
    IF ~LayoutChange(p) THEN
        fn.start
    ELSE IF FuncEnd(fn) <= p.addr THEN
        fn.start
    ELSE IF fn.start >= PatchEnd(p) THEN
        fn.start + PatchDelta(p)
    ELSE IF fn.start < p.addr THEN
        fn.start
    ELSE
        p.addr

TransformEnd(fn, p) ==
    IF ~LayoutChange(p) THEN
        FuncEnd(fn)
    ELSE IF FuncEnd(fn) <= p.addr THEN
        FuncEnd(fn)
    ELSE IF FuncEnd(fn) >= PatchEnd(p) THEN
        FuncEnd(fn) + PatchDelta(p)
    ELSE
        ReplacementEnd(p)

TransformFunc(fn, p) ==
    LET newStart == TransformStart(fn, p)
        newEnd == TransformEnd(fn, p)
    IN [
        start |-> newStart,
        size |-> IF newEnd > newStart THEN newEnd - newStart ELSE 0
    ]

VARIABLES phase, funcs, cache, patch

Init ==
    /\ phase = "init"
    /\ funcs = [f \in Funcs |-> InitialFunc(f)]
    /\ cache = Funcs
    /\ patch \in PatchCases

Apply ==
    /\ phase = "init"
    /\ phase' = "applied"
    /\ funcs' = [f \in Funcs |-> TransformFunc(funcs[f], patch)]
    /\ cache' = {f \in cache : ~Affected(funcs[f], patch)}
    /\ UNCHANGED patch

Next ==
    \/ Apply
    \/ /\ phase = "applied"
       /\ UNCHANGED <<phase, funcs, cache, patch>>

CacheSound ==
    phase = "applied" =>
        \A f \in Funcs : Affected(InitialFunc(f), patch) => ~(f \in cache)

NoFalseInvalidation ==
    phase = "applied" =>
        \A f \in Funcs : ~Affected(InitialFunc(f), patch) => f \in cache

BeforeFunctionsUnchanged ==
    phase = "applied" =>
        \A f \in Funcs :
            FuncEnd(InitialFunc(f)) <= patch.addr =>
                funcs[f] = InitialFunc(f)

AfterFunctionsShifted ==
    phase = "applied" /\ LayoutChange(patch) =>
        \A f \in Funcs :
            InitialFunc(f).start >= PatchEnd(patch) =>
                /\ funcs[f].start = InitialFunc(f).start + PatchDelta(patch)
                /\ FuncEnd(funcs[f]) = FuncEnd(InitialFunc(f)) + PatchDelta(patch)

OverlappingFunctionsCoverReplacement ==
    phase = "applied" /\ LayoutChange(patch) =>
        \A f \in Funcs :
            /\ InitialFunc(f).start < PatchEnd(patch)
            /\ FuncEnd(InitialFunc(f)) > patch.addr
            => /\ funcs[f].start <= patch.addr
               /\ FuncEnd(funcs[f]) >= ReplacementEnd(patch)

Spec == Init /\ [][Next]_<<phase, funcs, cache, patch>>

=============================================================================
