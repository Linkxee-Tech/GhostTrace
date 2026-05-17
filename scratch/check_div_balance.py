
import sys
import os
import re

path = r"c:\Users\HP\Desktop\GhostTrace\frontend\src\GhostTrace.jsx"
with open(path, "r", encoding="utf-8") as f:
    content = f.read()

functions = re.finditer(r"function\s+(\w+)\s*\([^)]*\)\s*\{", content)

for func in functions:
    name = func.group(1)
    start = func.start()
    
    stack = 0
    body_end = -1
    for i in range(start, len(content)):
        if content[i] == '{': stack += 1
        elif content[i] == '}':
            stack -= 1
            if stack == 0:
                body_end = i + 1
                break
    
    if body_end != -1:
        body = content[start:body_end]
        open_divs = body.count("<div")
        close_divs = body.count("</div>")
        
        if open_divs != close_divs:
            print(f"Function {name}: divs {open_divs}/{close_divs} (Diff: {open_divs - close_divs})")
