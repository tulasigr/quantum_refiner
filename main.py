import re
import matplotlib.pyplot as plt

from generator import generate_code
from executor import execute_circuit
from evaluator import evaluate
from feedback import generate_feedback
from tasks import bell_state_task, ghz_task, grover_task, qft_task
from config import MAX_ITERATIONS, FIDELITY_THRESHOLD


# ✅ Extract clean Python code from LLM output
def extract_code(llm_output):
    match = re.search(r"```python(.*?)```", llm_output, re.DOTALL)

    if match:
        code = match.group(1)
    import re
    import matplotlib.pyplot as plt
    from generator import generate_code
    from executor import execute_circuit
    from evaluator import evaluate
    from feedback import generate_feedback
    from tasks import bell_state_task, ghz_task, grover_task, qft_task
    from config import MAX_ITERATIONS, FIDELITY_THRESHOLD

    def extract_code(llm_output):
        match = re.search(r"```python(.*?)```", llm_output, re.DOTALL)
        if match:
            code = match.group(1)
        else:
            code = llm_output
        lines = code.split("\n")
        cleaned = []
        for line in lines:
            if "```" in line:
                continue
            cleaned.append(line)
        return "\n".join(cleaned)

    def run_task(task_func):
        description, target_state = task_func()
        prompt = f"""
    You are a quantum computing expert using Qiskit.

    Write VALID Python code to solve this task:
    {description}
    STRICT RULES:
    - Use only: QuantumCircuit from qiskit
    - DO NOT use: BellState, GHZ, GroverSearch, or any library shortcuts
    - Always import:
        from qiskit import QuantumCircuit
    - Store circuit in variable `qc`
    - No explanations
    - Only valid Python code
    """
        history = ""
        results = []
        fidelity_list = []
        for i in range(MAX_ITERATIONS):
            print(f"\n--- Iteration {i+1} ---")
            try:
                llm_output = generate_code(prompt + history)
                print("\nRAW OUTPUT:\n", llm_output)
                code = extract_code(llm_output)
                if "day" in code or len(code.strip()) < 10:
                    raise ValueError("Bad LLM output")
                if "from qiskit import QuantumCircuit" not in code:
                    code = "from qiskit import QuantumCircuit\n" + code
                local_env = {}
                exec(code, {}, local_env)
                circuit = local_env.get("qc")
                if circuit is None:
                    raise ValueError("No circuit generated")
            except Exception as e:
                print("⚠️ Error:", e)
                print("⚠️ Using fallback circuit")
                circuit = fallback_circuit(task_func.__name__)
                history += f"""
    Error occurred:
    {str(e)}

    Fix the code and regenerate.
    """
                continue
            output_state = execute_circuit(circuit)
            eval_result = evaluate(output_state, target_state)
            fidelity = eval_result["fidelity"]
            print("Fidelity:", fidelity)
            results.append({
                "iteration": i,
                "fidelity": fidelity
            })
            fidelity_list.append(fidelity)
            if fidelity >= FIDELITY_THRESHOLD:
                print("✅ Converged!")
                break
            feedback = generate_feedback(eval_result)
            history += f"""
    Previous attempt failed.

    Feedback:
    - Fidelity: {feedback['fidelity']}
    - Error Type: {feedback['error_type']}
    - Suggestion: {feedback['suggestion']}

    Fix the circuit and try again.
    """
        plot_results(fidelity_list, task_func.__name__)
        return results

    def fallback_circuit(task_name):
        from qiskit import QuantumCircuit
        if task_name == "bell_state_task":
            qc = QuantumCircuit(2)
            qc.h(0)
            qc.cx(0, 1)
        elif task_name == "ghz_task":
            qc = QuantumCircuit(3)
            qc.h(0)
            qc.cx(0, 1)
            qc.cx(0, 2)
        elif task_name == "grover_task":
            qc = QuantumCircuit(2)
            qc.h([0, 1])
            qc.cz(0, 1)
            qc.h([0, 1])
        elif task_name == "qft_task":
            qc = QuantumCircuit(2)
            qc.h(0)
            qc.cp(3.1415/2, 1, 0)
            qc.h(1)
        return qc

    def plot_results(fidelity_list, task_name):
        plt.figure()
        plt.plot(fidelity_list)
        plt.xlabel("Iteration")
        plt.ylabel("Fidelity")
        plt.title(f"Improvement Curve - {task_name}")
        plt.show()

    if __name__ == "__main__":
        print("Running Bell Task")
        run_task(bell_state_task)
        print("\nRunning GHZ Task")
        run_task(ghz_task)
        print("\nRunning Grover Task")
        run_task(grover_task)
        print("\nRunning QFT Task")
        run_task(qft_task)