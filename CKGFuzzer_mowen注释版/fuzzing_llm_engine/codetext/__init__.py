## agent_repo.py
import sys
from pathlib import Path
# Add the project root to the Python path
root_path = str(Path(__file__).resolve().parent.parent.parent)  # Adjust the number of parents based on submodule depth
print(root_path)
if root_path not in sys.path:
    sys.path.append(root_path)
    