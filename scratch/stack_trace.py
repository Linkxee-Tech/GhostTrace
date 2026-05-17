
import sys
import os
import re

path = r"c:\Users\HP\Desktop\GhostTrace\frontend\src\GhostTrace.jsx"
with open(path, "r", encoding="utf-8") as f:
    lines = f.readlines()

stack = []
for i, line in enumerate(lines):
    # This is a very rough JSX tag balancer
    # We find all <div and <>, and all </div and </>
    
    # Ignore comments and strings as much as possible
    stripped = line.strip()
    if stripped.startswith("//") or stripped.startswith("/*"): continue
    
    # Find all opening tags
    openings = re.findall(r"<(div|>)[\s>]", line)
    for op in openings:
        stack.append((op, i+1))
        
    # Find all closing tags
    closings = re.findall(r"</(div|>)[\s>]", line)
    for cl in closings:
        if not stack:
            print(f"Line {i+1}: Extra closing tag </{cl}>")
            continue
        last_op, last_line = stack.pop()
        if cl != last_op:
            print(f"Line {i+1}: Mismatch! Closing </{cl}> but last open was <{last_op}> from line {last_line}")

if stack:
    for op, line in stack:
        print(f"Unclosed <{op}> from line {line}")
