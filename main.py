import tkinter as tk
import importlib
import os
import sys
from utils import ensure_results_subfolder, RESULTS_ROOT
from theme import BG_COLOR, PANEL_COLOR, TEXT_COLOR, TITLE_FONT, style_button #type: ignore

ICON_MAP = {
    "QR Tools": "📷",
    "Graph Analyzer": "📊",
    "Password Generator": "🔑",
    "Text Formatter": "✏️",
    "File Renamer": "📂",
    "Unit Converter": "📏",
    "Text Encryptor": "🛡",
    "Text Counter": "📝",
    "Color Picker": "🎨",
    "Steganography Tool": "🖼",
    "Dataset Finder": "🌐",
    "Research Paper Finder": "🔎",
    "Network Mapper": "🌐",
    "Disk Space Visualizer": "💽",
    "Data Profiler": "📈",
    "Experiment Tracker Lite": "🧪",
    "Prompt Evaluator": "🧠"
}

class ToolboxApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("🚀 My Toolbox")
        self.geometry("1000x700")
        self.configure(bg=BG_COLOR)

        self.container = tk.Frame(self, bg=BG_COLOR)
        self.container.pack(fill="both", expand=True)

        self.tools = self.load_tools()
        self.setup_results_folders()
        self.show_main_menu()

    def load_tools(self):
        tools_folder = os.path.join(os.path.dirname(__file__), "tools")
        if tools_folder not in sys.path:
            sys.path.insert(0, tools_folder)

        tools_list = []
        for file in sorted(os.listdir(tools_folder)):
            if file.endswith(".py") and file != "__init__.py":
                module_name = file[:-3]
                try:
                    module = importlib.import_module(module_name)
                    if hasattr(module, "ToolFrame"):
                        tab_name = getattr(module, "TAB_NAME", 
                                           module_name.replace("_", " ").title())
                        tools_list.append((tab_name, module))
                except (ImportError, AttributeError) as e:
                    print(f"Error loading {module_name}: {e}")
        return tools_list

    def setup_results_folders(self):
        os.makedirs(RESULTS_ROOT, exist_ok=True)
        for tool_name, _ in self.tools:
            ensure_results_subfolder(tool_name.replace(" ", "_"))

    def show_main_menu(self):
        for widget in self.container.winfo_children():
            widget.destroy()

        title = tk.Label(
            self.container,
            text="🛠 MY TOOLBOX",
            font=TITLE_FONT,
            fg=TEXT_COLOR,
            bg=BG_COLOR
        )
        title.pack(pady=30)

        btn_frame = tk.Frame(self.container, bg=BG_COLOR)
        btn_frame.pack(expand=True)

        for idx, (name, module) in enumerate(self.tools):
            icon = ICON_MAP.get(name, "🛠")
            btn_text = f"{icon}\n{name}"

            btn = tk.Button(
                btn_frame,
                text=btn_text,
                width=22,
                height=4,
                wraplength=150,
                justify="center",
                command=lambda m=module: self.load_tool(m)
            )
            style_button(btn)
            btn.grid(row=idx // 3, column=idx % 3, padx=20, pady=20)

    def load_tool(self, module):
        for widget in self.container.winfo_children():
            widget.destroy()

        back_btn = tk.Button(self.container, text="⬅ Back to Menu", command=self.show_main_menu)
        style_button(back_btn)
        back_btn.pack(anchor="w", pady=10, padx=10)

        tool_frame = module.ToolFrame(self.container)
        tool_frame.pack(fill="both", expand=True)


if __name__ == "__main__":
    app = ToolboxApp()
    app.mainloop()
