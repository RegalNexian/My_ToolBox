import tkinter as tk
from tkinter import filedialog, messagebox, ttk
from base_tool import BaseToolFrame
from theme import style_button, style_label, style_entry, style_textbox, BG_COLOR, PANEL_COLOR
import json
import re

TAB_NAME = "Code Formatter"

class ToolFrame(BaseToolFrame):
    def __init__(self, master):
        super().__init__(master)

        # ===== MAIN PANELS =====
        self.left_panel = tk.Frame(self, bg=PANEL_COLOR, width=400)
        self.left_panel.pack(side="left", fill="y", padx=5, pady=5)

        self.right_panel = tk.Frame(self, bg=BG_COLOR)
        self.right_panel.pack(side="right", fill="both", expand=True, padx=5, pady=5)

        # ===== LEFT: INPUT =====
        style_label(tk.Label(self.left_panel, text="💻 Code Formatter"))
        
        # Language selection
        lang_frame = tk.Frame(self.left_panel, bg=PANEL_COLOR)
        lang_frame.pack(fill="x", pady=5)
        
        style_label(tk.Label(lang_frame, text="Language:"))
        self.language_var = tk.StringVar(value="json")
        self.language_combo = ttk.Combobox(lang_frame, textvariable=self.language_var, 
                                         values=["json", "python", "javascript", "html", "css", "xml"])
        self.language_combo.pack(fill="x", pady=2)

        # Input text area
        style_label(tk.Label(self.left_panel, text="Input Code:"))
        self.input_text = tk.Text(self.left_panel, height=15)
        style_textbox(self.input_text)
        self.input_text.pack(fill="both", expand=True, pady=5)

        # Buttons
        load_btn = tk.Button(self.left_panel, text="Load from File", command=self.load_file)
        style_button(load_btn)
        load_btn.pack(pady=2, fill="x")

        format_btn = tk.Button(self.left_panel, text="Format Code", command=self.format_code)
        style_button(format_btn)
        format_btn.pack(pady=2, fill="x")

        minify_btn = tk.Button(self.left_panel, text="Minify Code", command=self.minify_code)
        style_button(minify_btn)
        minify_btn.pack(pady=2, fill="x")

        # ===== RIGHT: OUTPUT =====
        style_label(tk.Label(self.right_panel, text="✨ Formatted Output"))
        self.output_text = tk.Text(self.right_panel, height=20)
        style_textbox(self.output_text)
        self.output_text.pack(fill="both", expand=True, pady=5)

        save_btn = tk.Button(self.right_panel, text="Save to File", command=self.save_file)
        style_button(save_btn)
        save_btn.pack(pady=5)

    def load_file(self):
        file_path = filedialog.askopenfilename(
            title="Select Code File",
            filetypes=[
                ("All Code Files", "*.py;*.js;*.html;*.css;*.json;*.xml"),
                ("Python Files", "*.py"),
                ("JavaScript Files", "*.js"),
                ("HTML Files", "*.html"),
                ("CSS Files", "*.css"),
                ("JSON Files", "*.json"),
                ("XML Files", "*.xml"),
                ("All Files", "*.*")
            ]
        )
        if not file_path:
            return
        try:
            with open(file_path, "r", encoding="utf-8") as f:
                content = f.read()
            self.input_text.delete("1.0", tk.END)
            self.input_text.insert(tk.END, content)
            
            # Auto-detect language from file extension
            ext = file_path.split('.')[-1].lower()
            if ext in ["py"]: self.language_var.set("python")
            elif ext in ["js"]: self.language_var.set("javascript")
            elif ext in ["html", "htm"]: self.language_var.set("html")
            elif ext in ["css"]: self.language_var.set("css")
            elif ext in ["json"]: self.language_var.set("json")
            elif ext in ["xml"]: self.language_var.set("xml")
            
        except Exception as e:
            messagebox.showerror("Error", f"Failed to load file: {e}")

    def format_code(self):
        code = self.input_text.get("1.0", tk.END).strip()
        if not code:
            messagebox.showerror("Error", "No code entered.")
            return

        language = self.language_var.get()
        try:
            if language == "json":
                formatted = self.format_json(code)
            elif language == "python":
                formatted = self.format_python(code)
            elif language == "javascript":
                formatted = self.format_javascript(code)
            elif language == "html":
                formatted = self.format_html(code)
            elif language == "css":
                formatted = self.format_css(code)
            elif language == "xml":
                formatted = self.format_xml(code)
            else:
                formatted = code  # No formatting for unknown types
            
            self.output_text.delete("1.0", tk.END)
            self.output_text.insert(tk.END, formatted)
        except Exception as e:
            messagebox.showerror("Error", f"Failed to format code: {e}")

    def minify_code(self):
        code = self.input_text.get("1.0", tk.END).strip()
        if not code:
            messagebox.showerror("Error", "No code entered.")
            return

        language = self.language_var.get()
        try:
            if language == "json":
                minified = json.dumps(json.loads(code), separators=(',', ':'))
            elif language == "css":
                minified = self.minify_css(code)
            elif language == "javascript":
                minified = self.minify_javascript(code)
            else:
                # Basic minification - remove extra whitespace
                minified = re.sub(r'\s+', ' ', code).strip()
            
            self.output_text.delete("1.0", tk.END)
            self.output_text.insert(tk.END, minified)
        except Exception as e:
            messagebox.showerror("Error", f"Failed to minify code: {e}")

    def format_json(self, code):
        parsed = json.loads(code)
        return json.dumps(parsed, indent=2, ensure_ascii=False)

    def format_python(self, code):
        # Basic Python formatting
        lines = code.split('\n')
        formatted_lines = []
        indent_level = 0
        
        for line in lines:
            stripped = line.strip()
            if not stripped:
                formatted_lines.append('')
                continue
                
            # Decrease indent for certain keywords
            if stripped.startswith(('except', 'elif', 'else', 'finally')):
                indent_level = max(0, indent_level - 1)
            elif stripped.startswith(('def ', 'class ')) and indent_level > 0:
                indent_level = 0
                
            formatted_lines.append('    ' * indent_level + stripped)
            
            # Increase indent after certain keywords
            if stripped.endswith(':') and any(stripped.startswith(kw) for kw in 
                ['if ', 'for ', 'while ', 'def ', 'class ', 'try:', 'except', 'elif', 'else:', 'finally:', 'with ']):
                indent_level += 1
                
        return '\n'.join(formatted_lines)

    def format_javascript(self, code):
        # Basic JavaScript formatting
        formatted = code
        formatted = re.sub(r'{\s*', '{\n    ', formatted)
        formatted = re.sub(r';\s*', ';\n    ', formatted)
        formatted = re.sub(r'}\s*', '\n}\n', formatted)
        return formatted

    def format_html(self, code):
        # Basic HTML formatting
        formatted = code
        formatted = re.sub(r'><', '>\n<', formatted)
        return formatted

    def format_css(self, code):
        # Basic CSS formatting
        formatted = code
        formatted = re.sub(r'{\s*', ' {\n    ', formatted)
        formatted = re.sub(r';\s*', ';\n    ', formatted)
        formatted = re.sub(r'}\s*', '\n}\n\n', formatted)
        return formatted

    def format_xml(self, code):
        # Basic XML formatting
        formatted = code
        formatted = re.sub(r'><', '>\n<', formatted)
        return formatted

    def minify_css(self, code):
        # Remove comments and extra whitespace
        minified = re.sub(r'/\*.*?\*/', '', code, flags=re.DOTALL)
        minified = re.sub(r'\s+', ' ', minified)
        minified = re.sub(r';\s*}', '}', minified)
        return minified.strip()

    def minify_javascript(self, code):
        # Basic JS minification
        minified = re.sub(r'//.*?\n', '\n', code)  # Remove single-line comments
        minified = re.sub(r'/\*.*?\*/', '', minified, flags=re.DOTALL)  # Remove multi-line comments
        minified = re.sub(r'\s+', ' ', minified)  # Collapse whitespace
        return minified.strip()

    def save_file(self):
        content = self.output_text.get("1.0", tk.END).strip()
        if not content:
            messagebox.showerror("Error", "No formatted code to save.")
            return
            
        file_path = filedialog.asksaveasfilename(
            title="Save Formatted Code",
            defaultextension=".txt",
            filetypes=[
                ("Text Files", "*.txt"),
                ("Python Files", "*.py"),
                ("JavaScript Files", "*.js"),
                ("HTML Files", "*.html"),
                ("CSS Files", "*.css"),
                ("JSON Files", "*.json"),
                ("XML Files", "*.xml"),
                ("All Files", "*.*")
            ]
        )
        if not file_path:
            return
            
        try:
            with open(file_path, "w", encoding="utf-8") as f:
                f.write(content)
            messagebox.showinfo("Success", f"Code saved to {file_path}")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to save file: {e}")