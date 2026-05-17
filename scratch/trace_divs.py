
import sys
import os

path = r"c:\Users\HP\Desktop\GhostTrace\frontend\src\GhostTrace.jsx"
with open(path, "r", encoding="utf-8") as f:
    lines = f.readlines()

balance = 0
for i, line in enumerate(lines):
    # Count <div but NOT </div
    opens = line.count("<div") - line.count("</div")
    balance += opens
    if balance < 0:
        print(f"Line {i+1}: Balance went negative ({balance})! {line.strip()}")
        # Reset balance to 0 for tracking further errors
        balance = 0
