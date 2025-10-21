import tkinter as tk
from tkinter import filedialog, messagebox, ttk
from base_tool import BaseToolFrame
from theme import style_button, style_label, style_entry, style_textbox, BG_COLOR, PANEL_COLOR
import json
import yaml

TAB_NAME = "JSON/YAML Converter"

class ToolFrame(BaseToolFrame):
    def __init__(self, master):
        super().__init__(master)

        # ===== MAIN PANELS =====
        self.left_panel = tk.Frame(self, bg=PANEL_COLOR, width=400)
        self.left_panel.pack(side="left", fill="y", padx=5, pady=5)

        self.right_panel = tk.Frame(self, bg=BG_COLOR)
        self.right_panel.pack(side="right", fill="both", expand=True, padx=5, pady=5)

        # ===== LEFT: INPUT =====
        style_label(tk.Label(self.left_panel, text="🔄 JSON ↔ YAML Converter"))
        
        # Format selection
        format_frame = tk.Frame(self.left_panel, bg=PANEL_COLOR)
        format_frame.pack(fill="x", pady=5)
        
        style_label(tk.Label(format_frame, text="Input Format:"))
        self.input_format = tk.StringVar(value="json")
        self.format_combo = ttk.Combobox(format_frame, textvariable=self.input_format, 
                                       values=["json", "yaml"])
        self.format_combo.pack(fill="x", pady=2)

        # Input text area
        style_label(tk.Label(self.left_panel, text="Input Data:"))
        self.input_text = tk.Text(self.left_panel, height=15, bg="#111111", fg="#00ff00", insertbackground="#00ff00")
        self.input_text.pack(fill="both", expand=True, pady=5)
        
        # Sample JSON data
        sample_json = '''{
  "name": "John Doe",
  "age": 30,
  "city": "New York",
  "skills": ["Python", "JavaScript", "Docker"],
  "active": true,
  "projects": {
    "web_app": {
      "status": "completed",
      "technologies": ["React", "Node.js"]
    },
    "api_service": {
      "status": "in_progress",
      "technologies": ["FastAPI", "PostgreSQL"]
    }
  }
}'''
        self.input_text.insert("1.0", sample_json)

        # Buttons
        load_btn = tk.Button(self.left_panel, text="Load from File", command=self.load_file)
        style_button(load_btn)
        load_btn.pack(pady=2, fill="x")

        convert_btn = tk.Button(self.left_panel, text="Convert", command=self.convert_data)
        style_button(convert_btn)
        convert_btn.pack(pady=2, fill="x")

        validate_btn = tk.Button(self.left_panel, text="Validate Input", command=self.validate_input)
        style_button(validate_btn)
        validate_btn.pack(pady=2, fill="x")

        # ===== RIGHT: OUTPUT =====
        style_label(tk.Label(self.right_panel, text="✨ Converted Output"))
        
        self.output_format_label = tk.Label(self.right_panel, text="Output: YAML", 
                                          bg=BG_COLOR, fg="#00ff00", font=("Consolas", 10))
        self.output_format_label.pack(pady=2)
        
        self.output_text = tk.Text(self.right_panel, height=20, bg="#111111", fg="#00ff00", insertbackground="#00ff00")
        self.output_text.pack(fill="both", expand=True, pady=5)

        save_btn = tk.Button(self.right_panel, text="Save Output", command=self.save_file)
        style_button(save_btn)
        save_btn.pack(pady=5)

    def load_file(self):
        file_path = filedialog.askopenfilename(
            title="Select JSON/YAML File",
            filetypes=[
                ("JSON Files", "*.json"),
                ("YAML Files", "*.yaml;*.yml"),
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
            
            # Auto-detect format
            ext = file_path.split('.')[-1].lower()
            if ext in ["json"]:
                self.input_format.set("json")
            elif ext in ["yaml", "yml"]:
                self.input_format.set("yaml")
                
        except Exception as e:
            messagebox.showerror("Error", f"Failed to load file: {e}")

    def validate_input(self):
        content = self.input_text.get("1.0", tk.END).strip()
        if not content:
            messagebox.showerror("Error", "No data to validate")
            return

        input_fmt = self.input_format.get()
        try:
            if input_fmt == "json":
                json.loads(content)
                messagebox.showinfo("Valid", "Valid JSON format!")
            else:  # yaml
                yaml.safe_load(content)
                messagebox.showinfo("Valid", "Valid YAML format!")
        except Exception as e:
            messagebox.showerror("Invalid Format", f"Invalid {input_fmt.upper()}: {e}")

    def convert_data(self):
        content = self.input_text.get("1.0", tk.END).strip()
        if not content:
            messagebox.showerror("Error", "No data to convert")
            return

        input_fmt = self.input_format.get()
        try:
            if input_fmt == "json":
                # JSON to YAML
                data = json.loads(content)
                converted = yaml.dump(data, default_flow_style=False, indent=2, sort_keys=False)
                self.output_format_label.config(text="Output: YAML")
            else:
                # YAML to JSON
                data = yaml.safe_load(content)
                converted = json.dumps(data, indent=2, ensure_ascii=False)
                self.output_format_label.config(text="Output: JSON")
            
            self.output_text.delete("1.0", tk.END)
            self.output_text.insert(tk.END, converted)
            
        except json.JSONDecodeError as e:
            messagebox.showerror("JSON Error", f"Invalid JSON: {e}")
        except yaml.YAMLError as e:
            messagebox.showerror("YAML Error", f"Invalid YAML: {e}")
        except Exception as e:
            messagebox.showerror("Error", f"Conversion failed: {e}")

    def save_file(self):
        content = self.output_text.get("1.0", tk.END).strip()
        if not content:
            messagebox.showerror("Error", "No converted data to save")
            return
            
        # Determine file extension based on output format
        output_fmt = "yaml" if self.input_format.get() == "json" else "json"
        default_ext = f".{output_fmt}"
        
        file_path = filedialog.asksaveasfilename(
            title="Save Converted Data",
            defaultextension=default_ext,
            filetypes=[
                ("JSON Files", "*.json"),
                ("YAML Files", "*.yaml"),
                ("YML Files", "*.yml"),
                ("Text Files", "*.txt"),
                ("All Files", "*.*")
            ]
        )
        if file_path:
            try:
                with open(file_path, "w", encoding="utf-8") as f:
                    f.write(content)
                messagebox.showinfo("Success", f"Data saved to {file_path}")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to save: {e}")