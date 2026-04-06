# Self-Refining Quantum Code Generation

This project implements a closed-loop system where an LLM generates quantum code, a simulator evaluates it, and feedback is used to iteratively refine the code until it converges to a high-fidelity solution.

## Architecture

- **generator.py**: Uses an LLM (e.g., HuggingFace Transformers) to generate Qiskit code from a prompt and feedback.
- **executor.py**: Runs the generated quantum circuit on Qiskit Aer’s statevector simulator.
- **evaluator.py**: Compares the output statevector to the target state using fidelity.
- **feedback.py**: Translates evaluation results into actionable feedback for the LLM.
- **tasks.py**: Defines quantum tasks (Bell, GHZ, Grover, QFT) and their expected outputs.
- **main.py**: Orchestrates the closed loop: prompt → generate → execute → evaluate → feedback → refine.
- **config.py**: Configuration for model, device, and loop parameters.

## Requirements

- Python 3.8+
- Qiskit
- matplotlib
- torch
- transformers
- huggingface_hub

Install dependencies:

```bash
pip install qiskit matplotlib torch transformers huggingface_hub
```

## Usage

Run all tasks:

```bash
python main.py
```

## How it Works

1. The LLM generates quantum code for a given task.
2. The code is executed on a simulator.
3. The output is evaluated for fidelity against the target state.
4. Feedback is generated and appended to the prompt.
5. The loop repeats until the code converges (high fidelity) or max iterations are reached.
6. Results are plotted for each task.

## Example Tasks
- Bell state generation
- GHZ state
- Grover search
- Quantum Fourier Transform (QFT)

## Extending
- Add new tasks in `tasks.py`.
- Improve feedback logic in `feedback.py`.
- Add advanced evaluation metrics in `evaluator.py`.

## Troubleshooting
If you encounter import errors with `transformers` or `huggingface_hub`, ensure both are upgraded to the latest version:

```bash
pip install --upgrade transformers huggingface_hub
```

## License
MIT
