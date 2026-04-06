from qiskit import QuantumCircuit
from qiskit.quantum_info import Statevector

def bell_state_task():
    description = "Generate a Bell state circuit using Qiskit."
    qc = QuantumCircuit(2)
    qc.h(0)
    qc.cx(0, 1)
    target_state = Statevector.from_instruction(qc)
    return description, target_state

def ghz_task():
    description = "Generate a 3-qubit GHZ state."
    qc = QuantumCircuit(3)
    qc.h(0)
    qc.cx(0, 1)
    qc.cx(0, 2)
    target_state = Statevector.from_instruction(qc)
    return description, target_state

def grover_task():
    description = "Implement a simple 2-qubit Grover search."
    qc = QuantumCircuit(2)
    qc.h([0, 1])
    qc.cz(0, 1)
    qc.h([0, 1])
    target_state = Statevector.from_instruction(qc)
    return description, target_state

def qft_task():
    description = "Implement a 2-qubit Quantum Fourier Transform."
    qc = QuantumCircuit(2)
    qc.h(0)
    qc.cp(3.1415/2, 1, 0)
    qc.h(1)
    target_state = Statevector.from_instruction(qc)
    return description, target_state

    qc = QuantumCircuit(2)
    qc.h(0)
    qc.cp(3.1415/2, 1, 0)
    qc.h(1)

    target_state = Statevector.from_instruction(qc)
    return description, target_state
