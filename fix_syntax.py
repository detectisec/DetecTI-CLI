file_path = "/home/ls4ss/dev/DetecTI-CLI/web/static/js/graph.js"
with open(file_path, "r") as f:
    lines = f.readlines()

# Find the end of my new function
new_func_end = -1
for i, line in enumerate(lines):
    if "return topDownPositions;" in line:
        new_func_end = i + 1
        break

# Find the start of the next function
next_func_start = -1
for i in range(new_func_end, len(lines)):
    if "getLayoutOptions(layoutName" in line:
        next_func_start = i
        break

if new_func_end != -1 and next_func_start != -1:
    new_lines = lines[:new_func_end] + ["    }\n\n"] + lines[next_func_start:]
    with open(file_path, "w") as f:
        f.writelines(new_lines)
    print("Fixed syntax error successfully!")
else:
    print(f"Could not find markers: {new_func_end}, {next_func_start}")
