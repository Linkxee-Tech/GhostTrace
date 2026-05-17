
import sys
import os
import re

path = r"c:\Users\HP\Desktop\GhostTrace\frontend\src\GhostTrace.jsx"
with open(path, "r", encoding="utf-8") as f:
    lines = f.readlines()

new_lines = []
in_multiline = False
current_quote = ""

for line in lines:
    # This is a very simplistic multiline fixer for JS string literals
    # We look for lines that have an odd number of quotes and don't end with a closing quote/comma/semicolon properly
    
    stripped = line.strip()
    
    # If we find evidence:" or fix:" or detail:" or d:" or evidence: " etc.
    # and it doesn't end with ", or "}, or ";
    
    # Specifically targeting the blocks I know are broken:
    if 'evidence:"' in line and not stripped.endswith('",') and not stripped.endswith('"}') and not stripped.endswith('");'):
        line = line.replace('evidence:"', 'evidence:`').replace('",', '`,')
        if not '`' in line: # if it didn't have a closing quote
             in_multiline = True
             current_quote = '"'
    elif 'fix:"' in line and not stripped.endswith('",') and not stripped.endswith('"}'):
        line = line.replace('fix:"', 'fix:`').replace('",', '`,')
    elif 'detail:"' in line and not stripped.endswith('",') and not stripped.endswith('"}'):
        line = line.replace('detail:"', 'detail:`').replace('",', '`,')
    elif 'ai:"' in line and not stripped.endswith('",') and not stripped.endswith('"}'):
        line = line.replace('ai:"', 'ai:`').replace('",', '`,')

    # If we are inside a multiline block, check for the end
    if in_multiline:
        if current_quote + ',' in line or current_quote + '}' in line:
            line = line.replace(current_quote + ',', '`,').replace(current_quote + '}', '`}')
            in_multiline = False
            
    new_lines.append(line)

# Let's do a more robust replacement for the specific blocks we saw
final_content = "".join(new_lines)

# Fix the specific D_URL vulns block which is definitely broken
final_content = final_content.replace(
    'evidence:"Server: Apache/2.2\\nX-Powered-By: PHP/5.6.40\\n\\nEOL software with no security patches since 2018."',
    'evidence:`Server: Apache/2.2\\nX-Powered-By: PHP/5.6.40\\n\\nEOL software with no security patches since 2018.`'
)

# Actually, the problem is that my previous replace('\\n', '\n') converted literals to real newlines.
# So I should search for evidence:" followed by a newline.

with open(path, "w", encoding="utf-8") as f:
    f.write(final_content)
print("Attempted to fix multiline strings in GhostTrace.jsx")
