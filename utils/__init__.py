# utils package for advanced toolbox functionality
from .database import db_manager, DatabaseManager
from .security_utils import security_utils, SecurityUtils, SecurityToolBase

# Import functions from the root utils.py file to maintain compatibility
import sys
import os
import importlib.util

# Get the parent directory and import utils.py
parent_dir = os.path.dirname(os.path.dirname(__file__))
utils_py_path = os.path.join(parent_dir, "utils.py")

if os.path.exists(utils_py_path):
    spec = importlib.util.spec_from_file_location("utils_file", utils_py_path)
    utils_file = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(utils_file)
    
    # Export the functions
    ensure_results_subfolder = utils_file.ensure_results_subfolder
    get_save_path = utils_file.get_save_path
    RESULTS_ROOT = utils_file.RESULTS_ROOT
else:
    # Fallback definitions if utils.py doesn't exist
    RESULTS_ROOT = os.path.join(os.path.dirname(os.path.dirname(__file__)), "Results")
    
    def ensure_results_subfolder(tool_name: str) -> str:
        folder = os.path.join(RESULTS_ROOT, tool_name)
        os.makedirs(folder, exist_ok=True)
        return folder
    
    def get_save_path(tool_name: str, filename: str, timestamp: bool = True) -> str:
        from datetime import datetime
        folder = ensure_results_subfolder(tool_name)
        if timestamp:
            name, ext = os.path.splitext(filename)
            filename = f"{name}_{datetime.now().strftime('%Y%m%d_%H%M%S')}{ext}"
        return os.path.join(folder, filename)

__all__ = ['db_manager', 'DatabaseManager', 'security_utils', 'SecurityUtils', 'SecurityToolBase',
           'ensure_results_subfolder', 'get_save_path', 'RESULTS_ROOT']