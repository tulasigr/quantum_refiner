from transformers import AutoTokenizer, AutoModelForCausalLM
import torch
from config import MODEL_NAME, DEVICE
from transformers import AutoTokenizer, AutoModelForCausalLM
import torch
from config import MODEL_NAME, DEVICE

tokenizer = AutoTokenizer.from_pretrained(MODEL_NAME)

model = AutoModelForCausalLM.from_pretrained(
    MODEL_NAME, torch_dtype=torch.float32)

model.to(DEVICE)

def generate_code(prompt):
    inputs = tokenizer(prompt, return_tensors="pt").to(DEVICE)

    outputs = model.generate(
        **inputs,
        max_new_tokens=256,
        do_sample=False,   # 🔥 IMPORTANT: turn OFF sampling
        pad_token_id=tokenizer.eos_token_id
    )

    text = tokenizer.decode(outputs[0], skip_special_tokens=True)

    return text
