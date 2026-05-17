
import sys
import os
import re

path = r"c:\Users\HP\Desktop\GhostTrace\frontend\src\GhostTrace.jsx"
with open(path, "r", encoding="utf-8") as f:
    content = f.read()

# Remove comments
content = re.sub(r"//.*", "", content)
content = re.sub(r"/\*.*?\*/", "", content, flags=re.DOTALL)

# Remove strings
content = re.sub(r'["\'].*?["\']', '""', content)
content = re.sub(r'`.*?`', '``', content, flags=re.DOTALL)

# Now count tags
stack = []
tokens = re.finditer(r"<(div|>)[\s>]|</(div|>)[\s>]", content)

for match in tokens:
    tag = match.group(0)
    pos = match.start()
    
    # Find line number
    line_no = content.count('\n', 0, pos) + 1
    
    if tag.startswith("</"):
        tag_name = match.group(2)
        if not stack:
            print(f"Line {line_no}: Extra closing </{tag_name}>")
            continue
        last_tag, last_line = stack.pop()
        if tag_name != last_tag:
            print(f"Line {line_no}: Mismatch! Closing </{tag_name}> but last open was <{last_tag}> from line {last_line}")
    else:
        tag_name = match.group(1)
        # Check for self-closing div (not common but possible)
        if tag.endswith("/>"): continue
        stack.append((tag_name, line_no))

if stack:
    for tag, line in stack:
        print(f"Unclosed <{tag}> from line {line}")
