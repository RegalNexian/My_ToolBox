import os
from datetime import datetime

# Root save path for results
RESULTS_ROOT = r"D:\Projects\My_ToolBox\Results"

def ensure_results_subfolder(tool_name: str) -> str:
    """
    Ensure that the results subfolder exists for the given tool.
    Returns the absolute path to the subfolder.
    """
    folder = os.path.join(RESULTS_ROOT, tool_name)
    os.makedirs(folder, exist_ok=True)
    return folder

def get_save_path(tool_name: str, filename: str, timestamp: bool = True) -> str:
    """
    Get the full file path to save a result for a given tool.
    If timestamp=True, append a timestamp to the filename.
    """
    folder = ensure_results_subfolder(tool_name)

    if timestamp:
        name, ext = os.path.splitext(filename)
        filename = f"{name}_{datetime.now().strftime('%Y%m%d_%H%M%S')}{ext}"

    return os.path.join(folder, filename)
