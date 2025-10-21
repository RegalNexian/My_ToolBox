import tkinter as tk
from tkinter import messagebox, ttk
from base_tool import BaseToolFrame
from theme import style_button, style_label, style_entry, style_textbox, BG_COLOR, PANEL_COLOR
import json
import urllib.request
import urllib.parse
import urllib.error

TAB_NAME = "API Tester"

class ToolFrame(BaseToolFrame):
    def __init__(self, master):
        super().__init__(master)

        # ===== MAIN PANELS =====
        self.left_panel = tk.Frame(self, bg=PANEL_COLOR, width=400)
        self.left_panel.pack(side="left", fill="y", padx=5, pady=5)

        self.right_panel = tk.Frame(self, bg=BG_COLOR)
        self.right_panel.pack(side="right", fill="both", expand=True, padx=5, pady=5)

        # ===== LEFT: REQUEST SETUP =====
        style_label(tk.Label(self.left_panel, text="🌐 API Tester"))
        
        # Method selection
        method_frame = tk.Frame(self.left_panel, bg=PANEL_COLOR)
        method_frame.pack(fill="x", pady=5)
        
        style_label(tk.Label(method_frame, text="Method:"))
        self.method_var = tk.StringVar(value="GET")
        self.method_combo = ttk.Combobox(method_frame, textvariable=self.method_var, 
                                       values=["GET", "POST", "PUT", "DELETE", "PATCH"])
        self.method_combo.pack(fill="x", pady=2)

        # URL input
        style_label(tk.Label(self.left_panel, text="URL:"))
        self.url_entry = tk.Entry(self.left_panel, bg="#111111", fg="#00ff00", insertbackground="#00ff00")
        self.url_entry.pack(fill="x", pady=2)
        self.url_entry.insert(0, "https://jsonplaceholder.typicode.com/posts/1")

        # Headers
        style_label(tk.Label(self.left_panel, text="Headers (JSON):"))
        self.headers_text = tk.Text(self.left_panel, height=4, bg="#111111", fg="#00ff00", insertbackground="#00ff00")
        self.headers_text.pack(fill="x", pady=2)
        self.headers_text.insert("1.0", '{\n  "Content-Type": "application/json"\n}')

        # Request body
        style_label(tk.Label(self.left_panel, text="Request Body:"))
        self.body_text = tk.Text(self.left_panel, height=8, bg="#111111", fg="#00ff00", insertbackground="#00ff00")
        self.body_text.pack(fill="both", expand=True, pady=2)

        # Send button
        send_btn = tk.Button(self.left_panel, text="Send Request", command=self.send_request)
        style_button(send_btn)
        send_btn.pack(pady=10, fill="x")

        # ===== RIGHT: RESPONSE =====
        style_label(tk.Label(self.right_panel, text="📡 Response"))
        
        # Status info
        self.status_label = tk.Label(self.right_panel, text="Ready to send request", 
                                   bg=BG_COLOR, fg="#00ff00", font=("Consolas", 10))
        self.status_label.pack(pady=5)

        # Response text
        self.response_text = tk.Text(self.right_panel, height=25, bg="#111111", fg="#00ff00", insertbackground="#00ff00")
        self.response_text.pack(fill="both", expand=True, pady=5)

        # Save response button
        save_btn = tk.Button(self.right_panel, text="Save Response", command=self.save_response)
        style_button(save_btn)
        save_btn.pack(pady=5)

    def send_request(self):
        url = self.url_entry.get().strip()
        if not url:
            messagebox.showerror("Error", "Please enter a URL")
            return

        method = self.method_var.get()
        
        try:
            # Parse headers
            headers_text = self.headers_text.get("1.0", tk.END).strip()
            headers = {}
            if headers_text:
                headers = json.loads(headers_text)

            # Get request body
            body = self.body_text.get("1.0", tk.END).strip()
            data = None
            if body and method in ["POST", "PUT", "PATCH"]:
                data = body.encode('utf-8')

            # Create request
            req = urllib.request.Request(url, data=data, headers=headers, method=method)
            
            self.status_label.config(text="Sending request...")
            self.update()

            # Send request
            with urllib.request.urlopen(req) as response:
                status_code = response.getcode()
                response_headers = dict(response.headers)
                response_body = response.read().decode('utf-8')

                # Try to format JSON response
                try:
                    json_data = json.loads(response_body)
                    formatted_body = json.dumps(json_data, indent=2)
                except:
                    formatted_body = response_body

                # Display response
                self.status_label.config(text=f"Status: {status_code}")
                
                response_display = f"Status Code: {status_code}\n\n"
                response_display += "Response Headers:\n"
                response_display += json.dumps(response_headers, indent=2)
                response_display += "\n\nResponse Body:\n"
                response_display += formatted_body

                self.response_text.delete("1.0", tk.END)
                self.response_text.insert(tk.END, response_display)

        except urllib.error.HTTPError as e:
            error_body = e.read().decode('utf-8') if e.fp else "No error body"
            self.status_label.config(text=f"HTTP Error: {e.code}")
            self.response_text.delete("1.0", tk.END)
            self.response_text.insert(tk.END, f"HTTP Error {e.code}: {e.reason}\n\n{error_body}")
        except Exception as e:
            self.status_label.config(text="Request failed")
            self.response_text.delete("1.0", tk.END)
            self.response_text.insert(tk.END, f"Error: {str(e)}")

    def save_response(self):
        from tkinter import filedialog
        content = self.response_text.get("1.0", tk.END).strip()
        if not content:
            messagebox.showerror("Error", "No response to save")
            return
            
        file_path = filedialog.asksaveasfilename(
            title="Save API Response",
            defaultextension=".json",
            filetypes=[("JSON Files", "*.json"), ("Text Files", "*.txt"), ("All Files", "*.*")]
        )
        if file_path:
            try:
                with open(file_path, "w", encoding="utf-8") as f:
                    f.write(content)
                messagebox.showinfo("Success", f"Response saved to {file_path}")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to save: {e}")