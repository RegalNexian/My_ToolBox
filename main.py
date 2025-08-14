import tkinter as tk
import importlib
import os
import sys
from utils import ensure_results_subfolder, RESULTS_ROOT

BG_COLOR = "#1E1E1E"
FG_COLOR = "#FFFFFF"
BTN_COLOR = "#333333"
BTN_HOVER = "#444444"

ICON_MAP = {
    "QR Tools": "📷",
    "Graph Analyzer": "📊",
    "Password Generator": "🔑",
    "Text Formatter": "✏️",
    "File Renamer": "📂",
    "Unit Converter": "📏",
    "Text Encryptor": "🛡",
    "Text Counter": "📝",
    "Color Picker": "🎨"
}

class ToolboxApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("My Toolbox")
        self.geometry("1000x700")
        self.configure(bg=BG_COLOR)

        self.container = tk.Frame(self, bg=BG_COLOR)
        self.container.pack(fill="both", expand=True)

        # Load tools
        self.tools = self.load_tools()

        # Ensure Results folder structure
        self.setup_results_folders()

        # Show main menu
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
                        tab_name = getattr(module, "TAB_NAME", module_name.replace("_", " ").title())
                        tools_list.append((tab_name, module))
                except (ImportError, AttributeError) as e:
                    print(f"Error loading {module_name}: {e}")
        return tools_list

    def setup_results_folders(self):
        """Ensure Results root and subfolders for each tool exist."""
        os.makedirs(RESULTS_ROOT, exist_ok=True)
        for tool_name, _ in self.tools:
            ensure_results_subfolder(tool_name.replace(" ", "_"))

    def show_main_menu(self):
        for widget in self.container.winfo_children():
            widget.destroy()

        tk.Label(self.container, text="🛠 My Toolbox", font=("Segoe UI", 20, "bold"),
                 bg=BG_COLOR, fg=FG_COLOR).pack(pady=30)

        btn_frame = tk.Frame(self.container, bg=BG_COLOR)
        btn_frame.pack(expand=True)

        for idx, (name, module) in enumerate(self.tools):
            icon = ICON_MAP.get(name, "🛠")
            btn_text = f"{icon}  {name}"
            btn = tk.Button(btn_frame, text=btn_text, font=("Segoe UI", 12, "bold"),
                            bg=BTN_COLOR, fg=FG_COLOR, relief="flat", width=30, height=2,
                            command=lambda m=module: self.load_tool(m))
            btn.grid(row=idx // 2, column=idx % 2, padx=20, pady=20)
            btn.bind("<Enter>", lambda e, b=btn: b.config(bg=BTN_HOVER))
            btn.bind("<Leave>", lambda e, b=btn: b.config(bg=BTN_COLOR))

    def load_tool(self, module):
        for widget in self.container.winfo_children():
            widget.destroy()

        back_btn = tk.Button(self.container, text="⬅ Back to Menu", bg=BTN_COLOR, fg=FG_COLOR,
                             relief="flat", command=self.show_main_menu)
        back_btn.pack(anchor="w", pady=10, padx=10)

        tool_frame = module.ToolFrame(self.container)
        tool_frame.pack(fill="both", expand=True)


if __name__ == "__main__":
    app = ToolboxApp()
    app.mainloop()
