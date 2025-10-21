import tkinter as tk
from tkinter import ttk
import importlib
import os
import sys
from utils import ensure_results_subfolder, RESULTS_ROOT
from theme import BG_COLOR, PANEL_COLOR, TEXT_COLOR, TITLE_FONT, style_button #type: ignore

ICON_MAP = {
    # Original tools
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
    "Research Finder": "🔎",
    "Network Security Scanner": "🌐",
    "Disk Space Visualizer": "💽",
    "Data Profiler": "📈",
    "Experiment Tracker Lite": "🧪",
    "Prompt Evaluator": "🧠",
    "Code Formatter": "💻",
    "API Tester": "🌐",
    "JSON/YAML Converter": "🔄",
    "Log Analyzer": "📊",
    "Dependency Checker": "📦",
    "Git Helper": "🔧",
    "Docker Helper": "🐳",
    "Regex Tester": "🔍",
    
    # Advanced development tools
    "Model Performance Tracker": "🤖",
    "Cognitive Complexity Analyzer": "🧠",
    "Technical Debt Calculator": "💳",
    "Refactoring Opportunity Identifier": "🔧",
    "Code Clone Detector": "👥",
    "Memory Leak Detector": "🧠",
    "Performance Bottleneck Analyzer": "⚡",
    "Commit Pattern Analyzer": "📈",
    "Test Coverage Gap Analyzer": "🎯",
    "License Compatibility Checker": "📜",
    "Configuration Drift Detector": "⚙️",
    "Code Review Complexity Estimator": "📋",
    "Dependency Vulnerability Tracker": "🔍",
    "Security Vulnerability Scanner": "🛡️",
    
    # AI/ML tools
    "Dataset Bias Detector": "⚖️",
    "Hyperparameter Optimizer": "🎛️",
    "Feature Importance Analyzer": "📊",
    "Data Drift Detector": "📉",
    "Experiment Comparison Tool": "🔬",
    
    # Security tools
    "Network Reconnaissance Tool": "🕵️",
    "Secrets Scanner": "🔐",
    "Web App Security Scanner": "🌐",
    "Cryptographic Analyzer": "🔒",
    "Threat Intelligence Aggregator": "🛡️",
    "OSINT Information Gatherer": "🔍"
}

class ToolboxApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("🚀 My Toolbox")
        self.geometry("1000x700")
        self.configure(bg=BG_COLOR)

        self.container = tk.Frame(self, bg=BG_COLOR)
        self.container.pack(fill="both", expand=True)

        # Scrollable interface components
        self.canvas = None
        self.scrollbar = None
        self.scrollable_frame = None
        self.scroll_position = 0
        
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

        # Title (fixed at top)
        title = tk.Label(
            self.container,
            text="🛠 MY TOOLBOX",
            font=TITLE_FONT,
            fg=TEXT_COLOR,
            bg=BG_COLOR
        )
        title.pack(pady=30)

        # Create scrollable area
        self.setup_scrollable_interface()
        
        # Add tools to scrollable frame
        self.populate_tools_grid()

    def setup_scrollable_interface(self):
        """Create canvas-based scrollable interface for tool grid"""
        # Main frame for scrollable area
        scroll_container = tk.Frame(self.container, bg=BG_COLOR)
        scroll_container.pack(fill="both", expand=True, padx=20, pady=10)
        
        # Create canvas and scrollbar
        self.canvas = tk.Canvas(
            scroll_container,
            bg=BG_COLOR,
            highlightthickness=0,
            bd=0
        )
        
        self.scrollbar = ttk.Scrollbar(
            scroll_container,
            orient="vertical",
            command=self.canvas.yview
        )
        
        # Configure scrollbar style
        style = ttk.Style()
        style.theme_use('clam')
        style.configure("Vertical.TScrollbar",
                       background=PANEL_COLOR,
                       troughcolor=BG_COLOR,
                       bordercolor=BG_COLOR,
                       arrowcolor=TEXT_COLOR,
                       darkcolor=PANEL_COLOR,
                       lightcolor=PANEL_COLOR)
        
        # Create scrollable frame
        self.scrollable_frame = tk.Frame(self.canvas, bg=BG_COLOR)
        
        # Configure canvas scrolling
        self.canvas.configure(yscrollcommand=self.scrollbar.set)
        
        # Pack scrollbar and canvas
        self.scrollbar.pack(side="right", fill="y")
        self.canvas.pack(side="left", fill="both", expand=True)
        
        # Create window in canvas for scrollable frame
        self.canvas_window = self.canvas.create_window(
            (0, 0), 
            window=self.scrollable_frame, 
            anchor="nw"
        )
        
        # Bind events for scrolling and resizing
        self.bind_scroll_events()
        
        # Update scroll region when frame changes
        self.scrollable_frame.bind(
            "<Configure>",
            lambda e: self.update_scroll_region()
        )
        
        # Bind canvas resize to update frame width
        self.canvas.bind(
            "<Configure>",
            lambda e: self.on_canvas_configure(e)
        )

    def bind_scroll_events(self):
        """Bind mouse wheel and keyboard events for scrolling"""
        # Mouse wheel scrolling
        def on_mousewheel(event):
            if self.canvas.winfo_exists():
                self.canvas.yview_scroll(int(-1 * (event.delta / 120)), "units")
        
        # Bind mouse wheel to canvas and all child widgets
        def bind_to_mousewheel(widget):
            widget.bind("<MouseWheel>", on_mousewheel)
            for child in widget.winfo_children():
                bind_to_mousewheel(child)
        
        bind_to_mousewheel(self.canvas)
        bind_to_mousewheel(self.scrollable_frame)
        
        # Keyboard navigation
        def on_key_press(event):
            if not self.canvas.winfo_exists():
                return
                
            if event.keysym == "Up":
                self.canvas.yview_scroll(-1, "units")
            elif event.keysym == "Down":
                self.canvas.yview_scroll(1, "units")
            elif event.keysym == "Prior":  # Page Up
                self.canvas.yview_scroll(-1, "pages")
            elif event.keysym == "Next":   # Page Down
                self.canvas.yview_scroll(1, "pages")
            elif event.keysym == "Home":
                self.canvas.yview_moveto(0)
            elif event.keysym == "End":
                self.canvas.yview_moveto(1)
        
        # Bind keyboard events
        self.bind("<Key>", on_key_press)
        self.focus_set()

    def update_scroll_region(self):
        """Update the scroll region to encompass all widgets"""
        if self.canvas and self.canvas.winfo_exists():
            self.canvas.configure(scrollregion=self.canvas.bbox("all"))

    def on_canvas_configure(self, event):
        """Handle canvas resize to update scrollable frame width"""
        if self.canvas and self.scrollable_frame:
            # Update the width of the scrollable frame to match canvas width
            canvas_width = event.width
            self.canvas.itemconfig(self.canvas_window, width=canvas_width)

    def populate_tools_grid(self):
        """Populate the scrollable frame with tool buttons in a dynamic grid"""
        if not self.scrollable_frame:
            return
            
        # Calculate dynamic grid layout based on window width
        self.update_idletasks()  # Ensure geometry is calculated
        
        # Get available width (accounting for scrollbar and padding)
        available_width = self.canvas.winfo_width() if self.canvas.winfo_width() > 1 else 940
        button_width = 200  # Approximate button width including padding
        columns = max(1, available_width // button_width)
        
        for idx, (name, module) in enumerate(self.tools):
            icon = ICON_MAP.get(name, "🛠")
            btn_text = f"{icon}\n{name}"

            btn = tk.Button(
                self.scrollable_frame,
                text=btn_text,
                width=22,
                height=4,
                wraplength=150,
                justify="center",
                command=lambda m=module: self.load_tool(m)
            )
            style_button(btn)
            
            row = idx // columns
            col = idx % columns
            btn.grid(row=row, column=col, padx=20, pady=20, sticky="ew")
        
        # Configure column weights for responsive layout
        for col in range(columns):
            self.scrollable_frame.grid_columnconfigure(col, weight=1)
        
        # Update scroll region after adding all widgets
        self.after(100, self.update_scroll_region)
        
        # Restore scroll position if returning from a tool
        if hasattr(self, 'scroll_position') and self.scroll_position > 0:
            self.after(200, lambda: self.restore_scroll_position())

    def load_tool(self, module):
        # Store current scroll position
        if self.canvas and self.canvas.winfo_exists():
            self.scroll_position = self.canvas.canvasy(0)
        
        for widget in self.container.winfo_children():
            widget.destroy()

        back_btn = tk.Button(self.container, text="⬅ Back to Menu", command=self.show_main_menu)
        style_button(back_btn)
        back_btn.pack(anchor="w", pady=10, padx=10)

        tool_frame = module.ToolFrame(self.container)
        tool_frame.pack(fill="both", expand=True)

    def restore_scroll_position(self):
        """Restore the previous scroll position when returning to main menu"""
        if self.canvas and self.canvas.winfo_exists() and hasattr(self, 'scroll_position'):
            try:
                # Calculate the scroll fraction based on stored position
                bbox = self.canvas.bbox("all")
                if bbox and bbox[3] > self.canvas.winfo_height():
                    scroll_fraction = self.scroll_position / (bbox[3] - self.canvas.winfo_height())
                    scroll_fraction = max(0, min(1, scroll_fraction))
                    self.canvas.yview_moveto(scroll_fraction)
            except:
                pass  # Ignore errors during scroll restoration


if __name__ == "__main__":
    app = ToolboxApp()
    app.mainloop()
