import tkinter as tk
from tkinter import messagebox, ttk, filedialog, scrolledtext
from base_tool import BaseToolFrame
from theme import style_button, style_label, style_entry, style_textbox, BG_COLOR, PANEL_COLOR
import subprocess
import json
import threading

TAB_NAME = "Docker Helper"

class ToolFrame(BaseToolFrame):
    def __init__(self, master):
        super().__init__(master)

        # ===== MAIN PANELS =====
        self.left_panel = tk.Frame(self, bg=PANEL_COLOR, width=400)
        self.left_panel.pack(side="left", fill="y", padx=5, pady=5)

        self.right_panel = tk.Frame(self, bg=BG_COLOR)
        self.right_panel.pack(side="right", fill="both", expand=True, padx=5, pady=5)

        # ===== LEFT: DOCKER OPERATIONS =====
        style_label(tk.Label(self.left_panel, text="🐳 Docker Helper"))
        
        # Docker status
        status_btn = tk.Button(self.left_panel, text="Docker Status", command=self.docker_status)
        style_button(status_btn)
        status_btn.pack(fill="x", pady=2)

        # Container operations
        style_label(tk.Label(self.left_panel, text="Container Operations:"))
        
        containers_frame = tk.Frame(self.left_panel, bg=PANEL_COLOR)
        containers_frame.pack(fill="x", pady=2)
        
        list_containers_btn = tk.Button(containers_frame, text="List Containers", command=self.list_containers)
        style_button(list_containers_btn)
        list_containers_btn.pack(side="left", fill="x", expand=True, padx=(0, 2))
        
        list_all_btn = tk.Button(containers_frame, text="List All", command=self.list_all_containers)
        style_button(list_all_btn)
        list_all_btn.pack(side="right", fill="x", expand=True, padx=(2, 0))

        # Container management
        style_label(tk.Label(self.left_panel, text="Container ID/Name:"))
        self.container_entry = tk.Entry(self.left_panel, bg="#111111", fg="#00ff00", insertbackground="#00ff00")
        self.container_entry.pack(fill="x", pady=2)

        container_ops_frame = tk.Frame(self.left_panel, bg=PANEL_COLOR)
        container_ops_frame.pack(fill="x", pady=2)
        
        start_btn = tk.Button(container_ops_frame, text="Start", command=self.start_container)
        style_button(start_btn)
        start_btn.pack(side="left", fill="x", expand=True, padx=(0, 1))
        
        stop_btn = tk.Button(container_ops_frame, text="Stop", command=self.stop_container)
        style_button(stop_btn)
        stop_btn.pack(side="left", fill="x", expand=True, padx=(1, 1))
        
        restart_btn = tk.Button(container_ops_frame, text="Restart", command=self.restart_container)
        style_button(restart_btn)
        restart_btn.pack(side="right", fill="x", expand=True, padx=(1, 0))

        # Container logs and exec
        logs_frame = tk.Frame(self.left_panel, bg=PANEL_COLOR)
        logs_frame.pack(fill="x", pady=2)
        
        logs_btn = tk.Button(logs_frame, text="View Logs", command=self.view_logs)
        style_button(logs_btn)
        logs_btn.pack(side="left", fill="x", expand=True, padx=(0, 2))
        
        inspect_btn = tk.Button(logs_frame, text="Inspect", command=self.inspect_container)
        style_button(inspect_btn)
        inspect_btn.pack(side="right", fill="x", expand=True, padx=(2, 0))

        # Image operations
        style_label(tk.Label(self.left_panel, text="Image Operations:"))
        
        images_frame = tk.Frame(self.left_panel, bg=PANEL_COLOR)
        images_frame.pack(fill="x", pady=2)
        
        list_images_btn = tk.Button(images_frame, text="List Images", command=self.list_images)
        style_button(list_images_btn)
        list_images_btn.pack(side="left", fill="x", expand=True, padx=(0, 2))
        
        prune_btn = tk.Button(images_frame, text="Prune Images", command=self.prune_images)
        style_button(prune_btn)
        prune_btn.pack(side="right", fill="x", expand=True, padx=(2, 0))

        # Build operations
        style_label(tk.Label(self.left_panel, text="Build Operations:"))
        
        # Dockerfile selection
        dockerfile_frame = tk.Frame(self.left_panel, bg=PANEL_COLOR)
        dockerfile_frame.pack(fill="x", pady=2)
        
        select_dockerfile_btn = tk.Button(dockerfile_frame, text="Select Dockerfile", command=self.select_dockerfile)
        style_button(select_dockerfile_btn)
        select_dockerfile_btn.pack(fill="x")

        self.dockerfile_label = tk.Label(self.left_panel, text="No Dockerfile selected", 
                                       bg=PANEL_COLOR, fg="#00ff00", font=("Consolas", 9))
        self.dockerfile_label.pack(pady=2)

        # Image name and tag
        style_label(tk.Label(self.left_panel, text="Image Name:Tag"))
        self.image_name_entry = tk.Entry(self.left_panel, bg="#111111", fg="#00ff00", insertbackground="#00ff00")
        self.image_name_entry.pack(fill="x", pady=2)
        self.image_name_entry.insert(0, "myapp:latest")

        build_btn = tk.Button(self.left_panel, text="Build Image", command=self.build_image)
        style_button(build_btn)
        build_btn.pack(fill="x", pady=2)

        # Docker Compose
        style_label(tk.Label(self.left_panel, text="Docker Compose:"))
        
        compose_frame = tk.Frame(self.left_panel, bg=PANEL_COLOR)
        compose_frame.pack(fill="x", pady=2)
        
        compose_up_btn = tk.Button(compose_frame, text="Compose Up", command=self.compose_up)
        style_button(compose_up_btn)
        compose_up_btn.pack(side="left", fill="x", expand=True, padx=(0, 2))
        
        compose_down_btn = tk.Button(compose_frame, text="Compose Down", command=self.compose_down)
        style_button(compose_down_btn)
        compose_down_btn.pack(side="right", fill="x", expand=True, padx=(2, 0))

        # System cleanup
        cleanup_btn = tk.Button(self.left_panel, text="System Prune", command=self.system_prune)
        style_button(cleanup_btn)
        cleanup_btn.pack(fill="x", pady=5)

        # ===== RIGHT: OUTPUT =====
        style_label(tk.Label(self.right_panel, text="🖥️ Docker Output"))
        
        self.output_text = scrolledtext.ScrolledText(self.right_panel, height=25, bg="#111111", fg="#00ff00", insertbackground="#00ff00")
        self.output_text.pack(fill="both", expand=True, pady=5)

        # Save output button
        save_btn = tk.Button(self.right_panel, text="Save Output", command=self.save_output)
        style_button(save_btn)
        save_btn.pack(pady=5)

        self.dockerfile_path = None

    def run_docker_command(self, command, show_command=True, async_run=False):
        try:
            if show_command:
                self.output_text.insert(tk.END, f"$ docker {command}\n")
                self.output_text.see(tk.END)
                self.update()
            
            if async_run:
                # Run command in background thread for long-running operations
                thread = threading.Thread(target=self._run_command_async, args=(f"docker {command}",))
                thread.daemon = True
                thread.start()
            else:
                result = subprocess.run(
                    f"docker {command}",
                    shell=True,
                    capture_output=True,
                    text=True,
                    timeout=30
                )
                
                if result.stdout:
                    self.output_text.insert(tk.END, result.stdout)
                if result.stderr:
                    self.output_text.insert(tk.END, f"Error: {result.stderr}")
                
                self.output_text.insert(tk.END, "\n" + "="*50 + "\n\n")
                self.output_text.see(tk.END)
                
                return result
                
        except subprocess.TimeoutExpired:
            self.output_text.insert(tk.END, "Command timed out (30s limit)\n\n")
        except Exception as e:
            self.output_text.insert(tk.END, f"Error executing command: {e}\n\n")
            return None

    def _run_command_async(self, command):
        try:
            process = subprocess.Popen(
                command,
                shell=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                bufsize=1,
                universal_newlines=True
            )
            
            for line in process.stdout:
                self.output_text.insert(tk.END, line)
                self.output_text.see(tk.END)
                self.update()
            
            process.wait()
            self.output_text.insert(tk.END, "\n" + "="*50 + "\n\n")
            
        except Exception as e:
            self.output_text.insert(tk.END, f"Error in async command: {e}\n\n")

    def docker_status(self):
        self.run_docker_command("version")
        self.run_docker_command("info --format '{{json .}}' | python -m json.tool", show_command=False)

    def list_containers(self):
        self.run_docker_command("ps")

    def list_all_containers(self):
        self.run_docker_command("ps -a")

    def start_container(self):
        container = self.container_entry.get().strip()
        if not container:
            messagebox.showerror("Error", "Please enter a container ID or name")
            return
        self.run_docker_command(f"start {container}")

    def stop_container(self):
        container = self.container_entry.get().strip()
        if not container:
            messagebox.showerror("Error", "Please enter a container ID or name")
            return
        self.run_docker_command(f"stop {container}")

    def restart_container(self):
        container = self.container_entry.get().strip()
        if not container:
            messagebox.showerror("Error", "Please enter a container ID or name")
            return
        self.run_docker_command(f"restart {container}")

    def view_logs(self):
        container = self.container_entry.get().strip()
        if not container:
            messagebox.showerror("Error", "Please enter a container ID or name")
            return
        self.run_docker_command(f"logs --tail 50 {container}")

    def inspect_container(self):
        container = self.container_entry.get().strip()
        if not container:
            messagebox.showerror("Error", "Please enter a container ID or name")
            return
        self.run_docker_command(f"inspect {container}")

    def list_images(self):
        self.run_docker_command("images")

    def prune_images(self):
        if messagebox.askyesno("Confirm", "This will remove all unused images. Continue?"):
            self.run_docker_command("image prune -f")

    def select_dockerfile(self):
        file_path = filedialog.askopenfilename(
            title="Select Dockerfile",
            filetypes=[("Dockerfile", "Dockerfile"), ("All Files", "*.*")]
        )
        if file_path:
            self.dockerfile_path = file_path
            filename = file_path.split("/")[-1] if "/" in file_path else file_path.split("\\")[-1]
            self.dockerfile_label.config(text=f"Selected: {filename}")

    def build_image(self):
        image_name = self.image_name_entry.get().strip()
        if not image_name:
            messagebox.showerror("Error", "Please enter an image name")
            return
        
        if self.dockerfile_path:
            dockerfile_dir = "/".join(self.dockerfile_path.split("/")[:-1]) if "/" in self.dockerfile_path else "\\".join(self.dockerfile_path.split("\\")[:-1])
            command = f"build -t {image_name} {dockerfile_dir}"
        else:
            # Build from current directory
            command = f"build -t {image_name} ."
        
        self.run_docker_command(command, async_run=True)

    def compose_up(self):
        self.run_docker_command("compose up -d", async_run=True)

    def compose_down(self):
        self.run_docker_command("compose down")

    def system_prune(self):
        if messagebox.askyesno("Confirm", "This will remove all unused containers, networks, and images. Continue?"):
            self.run_docker_command("system prune -f")

    def save_output(self):
        content = self.output_text.get("1.0", tk.END).strip()
        if not content:
            messagebox.showerror("Error", "No output to save")
            return
            
        file_path = filedialog.asksaveasfilename(
            title="Save Docker Output",
            defaultextension=".txt",
            filetypes=[("Text Files", "*.txt"), ("Log Files", "*.log"), ("All Files", "*.*")]
        )
        if file_path:
            try:
                with open(file_path, "w", encoding="utf-8") as f:
                    f.write(content)
                messagebox.showinfo("Success", f"Output saved to {file_path}")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to save: {e}")