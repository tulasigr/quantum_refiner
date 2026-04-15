#!/usr/bin/env python3
"""Script to remove emojis from example files."""

import re
from pathlib import Path

# Files to clean
files_to_clean = [
    'examples/example_workflow.py',
    'examples/example_attacks.py',
]

# Emoji replacements
replacements = {
    '📝': '[*]',
    '✅': '[OK]',
    '🔐': '[>>]',
    '🔑': '[*]',
    '🔧': '[*]',
    '📌': '[>>]',
    '🔒': '[*]',
    '📊': '[*]',
    '🤖': '[*]',
    '📋': '[*]',
    '🔄': '[*]',
    '🎯': '[*]',
    '❌': '[!]',
    '🔓': '[*]',
    '⚠️': '[!]',
    '→': '->',
    '✓': '[+]',
    '✗': '[-]',
    '🚀': '[>>]',
}

for file_path in files_to_clean:
    if not Path(file_path).exists():
        print(f"[SKIP] File not found: {file_path}")
        continue
    
    # Read the file
    with open(file_path, 'r', encoding='utf-8') as f:
        content = f.read()
    
    # Apply replacements
    for emoji, replacement in replacements.items():
        content = content.replace(emoji, replacement)
    
    # Also handle any remaining emojis using regex
    # Remove any emoji-range Unicode characters
    content = re.sub(r'[\U0001F300-\U0001F9FF]', '', content)
    content = re.sub(r'[\U0001F600-\U0001F64F]', '', content)  # Emoticons
    content = re.sub(r'[\U0001F1E0-\U0001F1FF]', '', content)  # Flags
    
    # Write back
    with open(file_path, 'w', encoding='utf-8') as f:
        f.write(content)
    
    print(f"[OK] Cleaned: {file_path}")

print("[OK] All files cleaned!")
