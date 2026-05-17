
import sys
import os
import re

path = r"c:\Users\HP\Desktop\GhostTrace\frontend\src\GhostTrace.jsx"
with open(path, "r", encoding="utf-8") as f:
    content = f.read()

# Simple regex to find functions and their bodies
# We'll assume functions start with "function Name(...) {" or "const Name = (...) => {"
functions = re.finditer(r"function\s+(\w+)\s*\([^)]*\)\s*\{", content)

for func in functions:
    name = func.group(1)
    start = func.start()
    
    # Find the matching closing brace for the function
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
        open_frags = body.count("<>")
        close_frags = body.count("</>")
        
        if open_divs != close_divs or open_frags != close_frags:
            print(f"Function {name}: divs {open_divs}/{close_divs}, frags {open_frags}/{close_frags}")
