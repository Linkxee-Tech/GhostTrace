
import sys
import os
import re

path = r"c:\Users\HP\Desktop\GhostTrace\frontend\src\GhostTrace.jsx"
with open(path, "r", encoding="utf-8") as f:
    lines = f.readlines()

for i, line in enumerate(lines):
    if "<>" in line:
        print(f"OPEN fragment at line {i+1}: {line.strip()}")
    if "</>" in line:
        print(f"CLOSE fragment at line {i+1}: {line.strip()}")
