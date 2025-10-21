import tkinter as tk
from tkinter import messagebox, ttk, filedialog
from base_tool import BaseToolFrame
from theme import style_button, style_label, style_entry, style_textbox, BG_COLOR, PANEL_COLOR
import subprocess
import os

TAB_NAME = "Git Helper"

class ToolFrame(BaseToolFrame):
    def __init__(self, master):
        super().__init__(master)

        # ===== MAIN PANELS =====
        self.left_panel = tk.Frame(self, bg=PANEL_COLOR, width=400)
        self.left_panel.pack(side="left", fill="y", padx=5, pady=5)

        self.right_panel = tk.Frame(self, bg=BG_COLOR)
        self.right_panel.pack(side="right", fill="both", expand=True, padx=5, pady=5)

        # ===== LEFT: GIT OPERATIONS =====
        style_label(tk.Label(self.left_panel, text="🔧 Git Helper"))
        
        # Repository selection
        repo_frame = tk.Frame(self.left_panel, bg=PANEL_COLOR)
        repo_frame.pack(fill="x", pady=5)
        
        select_repo_btn = tk.Button(repo_frame, text="Select Repository", command=self.select_repository)
        style_button(select_repo_btn)
        select_repo_btn.pack(fill="x", pady=2)

        self.repo_label = tk.Label(self.left_panel, text="No repository selected", 
                                 bg=PANEL_COLOR, fg="#00ff00", font=("Consolas", 9))
        self.repo_label.pack(pady=2)

        # Quick status
        status_btn = tk.Button(self.left_panel, text="Git Status", command=self.git_status)
        style_button(status_btn)
        status_btn.pack(fill="x", pady=2)

        # Branch operations
        style_label(tk.Label(self.left_panel, text="Branch Operations:"))
        
        branch_frame = tk.Frame(self.left_panel, bg=PANEL_COLOR)
        branch_frame.pack(fill="x", pady=2)
        
        list_branches_btn = tk.Button(branch_frame, text="List Branches", command=self.list_branches)
        style_button(list_branches_btn)
        list_branches_btn.pack(side="left", fill="x", expand=True, padx=(0, 2))
        
        current_branch_btn = tk.Button(branch_frame, text="Current Branch", command=self.current_branch)
        style_button(current_branch_btn)
        current_branch_btn.pack(side="right", fill="x", expand=True, padx=(2, 0))

        # Branch creation
        branch_create_frame = tk.Frame(self.left_panel, bg=PANEL_COLOR)
        branch_create_frame.pack(fill="x", pady=2)
        
        self.new_branch_entry = tk.Entry(branch_create_frame, bg="#111111", fg="#00ff00", insertbackground="#00ff00")
        self.new_branch_entry.pack(side="left", fill="x", expand=True, padx=(0, 2))
        self.new_branch_entry.insert(0, "feature/new-feature")
        
        create_branch_btn = tk.Button(branch_create_frame, text="Create Branch", command=self.create_branch)
        style_button(create_branch_btn)
        create_branch_btn.pack(side="right")

        # Commit operations
        style_label(tk.Label(self.left_panel, text="Commit Operations:"))
        
        # Commit message
        style_label(tk.Label(self.left_panel, text="Commit Message:"))
        self.commit_msg_text = tk.Text(self.left_panel, height=3, bg="#111111", fg="#00ff00", insertbackground="#00ff00")
        self.commit_msg_text.pack(fill="x", pady=2)
        self.commit_msg_text.insert("1.0", "feat: add new feature")

        commit_frame = tk.Frame(self.left_panel, bg=PANEL_COLOR)
        commit_frame.pack(fill="x", pady=2)
        
        add_all_btn = tk.Button(commit_frame, text="Add All", command=self.git_add_all)
        style_button(add_all_btn)
        add_all_btn.pack(side="left", fill="x", expand=True, padx=(0, 2))
        
        commit_btn = tk.Button(commit_frame, text="Commit", command=self.git_commit)
        style_button(commit_btn)
        commit_btn.pack(side="right", fill="x", expand=True, padx=(2, 0))

        # Log and diff
        log_frame = tk.Frame(self.left_panel, bg=PANEL_COLOR)
        log_frame.pack(fill="x", pady=2)
        
        log_btn = tk.Button(log_frame, text="Git Log", command=self.git_log)
        style_button(log_btn)
        log_btn.pack(side="left", fill="x", expand=True, padx=(0, 2))
        
        diff_btn = tk.Button(log_frame, text="Git Diff", command=self.git_diff)
        style_button(diff_btn)
        diff_btn.pack(side="right", fill="x", expand=True, padx=(2, 0))

        # Remote operations
        style_label(tk.Label(self.left_panel, text="Remote Operations:"))
        
        remote_frame = tk.Frame(self.left_panel, bg=PANEL_COLOR)
        remote_frame.pack(fill="x", pady=2)
        
        pull_btn = tk.Button(remote_frame, text="Pull", command=self.git_pull)
        style_button(pull_btn)
        pull_btn.pack(side="left", fill="x", expand=True, padx=(0, 2))
        
        push_btn = tk.Button(remote_frame, text="Push", command=self.git_push)
        style_button(push_btn)
        push_btn.pack(side="right", fill="x", expand=True, padx=(2, 0))

        # Advanced operations
        style_label(tk.Label(self.left_panel, text="Advanced:"))
        
        stash_frame = tk.Frame(self.left_panel, bg=PANEL_COLOR)
        stash_frame.pack(fill="x", pady=2)
        
        stash_btn = tk.Button(stash_frame, text="Stash Changes", command=self.git_stash)
        style_button(stash_btn)
        stash_btn.pack(side="left", fill="x", expand=True, padx=(0, 2))
        
        stash_pop_btn = tk.Button(stash_frame, text="Stash Pop", command=self.git_stash_pop)
        style_button(stash_pop_btn)
        stash_pop_btn.pack(side="right", fill="x", expand=True, padx=(2, 0))

        # ===== RIGHT: OUTPUT =====
        style_label(tk.Label(self.right_panel, text="📋 Git Output"))
        
        self.output_text = tk.Text(self.right_panel, height=25, bg="#111111", fg="#00ff00", insertbackground="#00ff00")
        self.output_text.pack(fill="both", expand=True, pady=5)

        # Save output button
        save_btn = tk.Button(self.right_panel, text="Save Output", command=self.save_output)
        style_button(save_btn)
        save_btn.pack(pady=5)

        self.repo_path = None

    def select_repository(self):
        directory = filedialog.askdirectory(title="Select Git Repository")
        if directory:
            # Check if it's a git repository
            if os.path.exists(os.path.join(directory, ".git")):
                self.repo_path = directory
                repo_name = os.path.basename(directory)
                self.repo_label.config(text=f"Repository: {repo_name}")
                self.output_text.delete("1.0", tk.END)
                self.output_text.insert(tk.END, f"✅ Selected repository: {directory}\n\n")
            else:
                messagebox.showerror("Error", "Selected directory is not a Git repository")

    def run_git_command(self, command, show_command=True):
        if not self.repo_path:
            messagebox.showerror("Error", "Please select a Git repository first")
            return None

        try:
            if show_command:
                self.output_text.insert(tk.END, f"$ git {command}\n")
            
            result = subprocess.run(
                f"git {command}",
                cwd=self.repo_path,
                shell=True,
                capture_output=True,
                text=True
            )
            
            if result.stdout:
                self.output_text.insert(tk.END, result.stdout)
            if result.stderr:
                self.output_text.insert(tk.END, f"Error: {result.stderr}")
            
            self.output_text.insert(tk.END, "\n" + "="*50 + "\n\n")
            self.output_text.see(tk.END)
            
            return result
            
        except Exception as e:
            self.output_text.insert(tk.END, f"Error executing command: {e}\n\n")
            return None

    def git_status(self):
        self.run_git_command("status")

    def list_branches(self):
        self.run_git_command("branch -a")

    def current_branch(self):
        self.run_git_command("branch --show-current")

    def create_branch(self):
        branch_name = self.new_branch_entry.get().strip()
        if not branch_name:
            messagebox.showerror("Error", "Please enter a branch name")
            return
        
        # Create and switch to new branch
        result = self.run_git_command(f"checkout -b {branch_name}")
        if result and result.returncode == 0:
            self.output_text.insert(tk.END, f"✅ Created and switched to branch: {branch_name}\n\n")

    def git_add_all(self):
        self.run_git_command("add .")

    def git_commit(self):
        commit_msg = self.commit_msg_text.get("1.0", tk.END).strip()
        if not commit_msg:
            messagebox.showerror("Error", "Please enter a commit message")
            return
        
        # Escape quotes in commit message
        commit_msg = commit_msg.replace('"', '\\"')
        self.run_git_command(f'commit -m "{commit_msg}"')

    def git_log(self):
        self.run_git_command("log --oneline -10")

    def git_diff(self):
        self.run_git_command("diff")

    def git_pull(self):
        self.run_git_command("pull")

    def git_push(self):
        # First check current branch
        result = subprocess.run(
            "git branch --show-current",
            cwd=self.repo_path,
            shell=True,
            capture_output=True,
            text=True
        )
        
        if result.stdout:
            current_branch = result.stdout.strip()
            self.run_git_command(f"push origin {current_branch}")
        else:
            self.run_git_command("push")

    def git_stash(self):
        self.run_git_command("stash")

    def git_stash_pop(self):
        self.run_git_command("stash pop")

    def save_output(self):
        content = self.output_text.get("1.0", tk.END).strip()
        if not content:
            messagebox.showerror("Error", "No output to save")
            return
            
        file_path = filedialog.asksaveasfilename(
            title="Save Git Output",
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