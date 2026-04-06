from qiskit.quantum_info import state_fidelity
import numpy as np

def evaluate(output_state, target_state):
    fidelity = state_fidelity(output_state, target_state)
    return {
        "fidelity": fidelity,
        "score": fidelity
    }
