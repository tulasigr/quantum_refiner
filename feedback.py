def generate_feedback(eval_result):
    fidelity = eval_result["fidelity"]

    if fidelity > 0.9:
        return {
            "fidelity": fidelity,
            "error_type": "minor",
            "suggestion": "Optimize gate sequence for efficiency"
        }

    elif fidelity > 0.6:
        return {
            "fidelity": fidelity,
            "error_type": "medium",
            "suggestion": "Increase entanglement using CNOT gates"
        }

    else:
        return {
            "fidelity": fidelity,
            "error_type": "low_entanglement",
            "suggestion": "Add Hadamard and CNOT gates to build superposition and entanglement"
        }
