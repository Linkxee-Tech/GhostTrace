
import sys
import os

path = r"c:\Users\HP\Desktop\GhostTrace\frontend\src\GhostTrace.jsx"
with open(path, "r", encoding="utf-8") as f:
    content = f.read()

open_divs = content.count("<div")
close_divs = content.count("</div>")
open_frags = content.count("<>")
close_frags = content.count("</>")

print(f"Open divs: {open_divs}, Close divs: {close_divs}")
print(f"Open frags: {open_frags}, Close frags: {close_frags}")
