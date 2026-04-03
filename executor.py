from qiskit import transpile
from qiskit_aer import Aer
from qiskit.quantum_info import Statevector


def execute_circuit(circuit):
    backend = Aer.get_backend('statevector_simulator')
    transpiled = transpile(circuit, backend)
    result = backend.run(transpiled).result()
    statevector = result.get_statevector()
    return Statevector(statevector)
