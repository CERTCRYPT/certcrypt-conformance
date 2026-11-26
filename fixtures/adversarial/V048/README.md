# V048 — Wrong Transaction Type

settlement_action.name is `consume`, not `payment`, the only settlement action the profile accepts (settlement.aggregated.xrpl/1 §9.2).
Expected: INDEPENDENT_INVALID (CAPACITY_BINDING_VALID)