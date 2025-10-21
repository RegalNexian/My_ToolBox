import tkinter as tk
from tkinter import messagebox, ttk, filedialog
from base_tool import BaseToolFrame
from theme import style_button, style_label, style_entry, style_textbox, BG_COLOR, PANEL_COLOR
import re

TAB_NAME = "Regex Tester"

class ToolFrame(BaseToolFrame):
    def __init__(self, master):
        super().__init__(master)

        # ===== MAIN PANELS =====
        self.left_panel = tk.Frame(self, bg=PANEL_COLOR, width=400)
        self.left_panel.pack(side="left", fill="y", padx=5, pady=5)

        self.right_panel = tk.Frame(self, bg=BG_COLOR)
        self.right_panel.pack(side="right", fill="both", expand=True, padx=5, pady=5)

        # ===== LEFT: REGEX INPUT =====
        style_label(tk.Label(self.left_panel, text="🔍 Regex Tester"))
        
        # Regex pattern input
        style_label(tk.Label(self.left_panel, text="Regular Expression Pattern:"))
        self.pattern_entry = tk.Entry(self.left_panel, bg="#111111", fg="#00ff00", insertbackground="#00ff00")
        self.pattern_entry.pack(fill="x", pady=2)
        self.pattern_entry.insert(0, r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b")
        self.pattern_entry.bind('<KeyRelease>', self.on_pattern_change)

        # Flags
        flags_frame = tk.Frame(self.left_panel, bg=PANEL_COLOR)
        flags_frame.pack(fill="x", pady=5)
        
        style_label(tk.Label(flags_frame, text="Flags:"))
        
        self.ignore_case = tk.BooleanVar(value=False)
        tk.Checkbutton(flags_frame, text="Ignore Case (i)", variable=self.ignore_case,
                      bg=PANEL_COLOR, fg="#00ff00", selectcolor="#111111",
                      command=self.test_regex).pack(anchor="w")
        
        self.multiline = tk.BooleanVar(value=False)
        tk.Checkbutton(flags_frame, text="Multiline (m)", variable=self.multiline,
                      bg=PANEL_COLOR, fg="#00ff00", selectcolor="#111111",
                      command=self.test_regex).pack(anchor="w")
        
        self.dotall = tk.BooleanVar(value=False)
        tk.Checkbutton(flags_frame, text="Dot matches all (s)", variable=self.dotall,
                      bg=PANEL_COLOR, fg="#00ff00", selectcolor="#111111",
                      command=self.test_regex).pack(anchor="w")

        # Test string input
        style_label(tk.Label(self.left_panel, text="Test String:"))
        self.test_string_text = tk.Text(self.left_panel, height=8, bg="#111111", fg="#00ff00", insertbackground="#00ff00")
        self.test_string_text.pack(fill="both", expand=True, pady=2)
        
        # Sample test string
        sample_text = """john.doe@example.com
invalid-email@
test@domain.co.uk
user123@test-site.org
not_an_email_address
admin@company.com
support@help.center"""
        self.test_string_text.insert("1.0", sample_text)
        self.test_string_text.bind('<KeyRelease>', self.on_text_change)

        # Buttons
        test_btn = tk.Button(self.left_panel, text="Test Regex", command=self.test_regex)
        style_button(test_btn)
        test_btn.pack(fill="x", pady=5)

        load_file_btn = tk.Button(self.left_panel, text="Load Text File", command=self.load_text_file)
        style_button(load_file_btn)
        load_file_btn.pack(fill="x", pady=2)

        # Common patterns dropdown
        style_label(tk.Label(self.left_panel, text="Common Patterns:"))
        self.common_patterns = {
            "Email": r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b",
            "Phone (US)": r"\b\d{3}-\d{3}-\d{4}\b",
            "URL": r"https?://(?:[-\w.])+(?:\:[0-9]+)?(?:/(?:[\w/_.])*(?:\?(?:[\w&=%.])*)?(?:\#(?:[\w.])*)?)?",
            "IPv4 Address": r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b",
            "Date (YYYY-MM-DD)": r"\b\d{4}-\d{2}-\d{2}\b",
            "Time (HH:MM)": r"\b\d{2}:\d{2}\b",
            "Credit Card": r"\b\d{4}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}\b",
            "Hex Color": r"#[0-9A-Fa-f]{6}\b",
            "Word Boundaries": r"\b\w+\b",
            "Numbers Only": r"\b\d+\b"
        }
        
        self.pattern_var = tk.StringVar()
        pattern_combo = ttk.Combobox(self.left_panel, textvariable=self.pattern_var,
                                   values=list(self.common_patterns.keys()))
        pattern_combo.pack(fill="x", pady=2)
        pattern_combo.bind('<<ComboboxSelected>>', self.load_common_pattern)

        # ===== RIGHT: RESULTS =====
        # Create notebook for different result views
        self.notebook = ttk.Notebook(self.right_panel)
        self.notebook.pack(fill="both", expand=True, pady=5)

        # Matches tab
        self.matches_frame = tk.Frame(self.notebook, bg=BG_COLOR)
        self.notebook.add(self.matches_frame, text="Matches")
        
        style_label(tk.Label(self.matches_frame, text="🎯 Matches Found"))
        self.matches_text = tk.Text(self.matches_frame, height=20, bg="#111111", fg="#00ff00", insertbackground="#00ff00")
        self.matches_text.pack(fill="both", expand=True, pady=5)

        # Groups tab
        self.groups_frame = tk.Frame(self.notebook, bg=BG_COLOR)
        self.notebook.add(self.groups_frame, text="Groups")
        
        style_label(tk.Label(self.groups_frame, text="📋 Capture Groups"))
        self.groups_text = tk.Text(self.groups_frame, height=20, bg="#111111", fg="#00ff00", insertbackground="#00ff00")
        self.groups_text.pack(fill="both", expand=True, pady=5)

        # Replace tab
        self.replace_frame = tk.Frame(self.notebook, bg=BG_COLOR)
        self.notebook.add(self.replace_frame, text="Replace")
        
        style_label(tk.Label(self.replace_frame, text="🔄 Find & Replace"))
        
        # Replacement string
        replace_input_frame = tk.Frame(self.replace_frame, bg=BG_COLOR)
        replace_input_frame.pack(fill="x", pady=5)
        
        tk.Label(replace_input_frame, text="Replace with:", bg=BG_COLOR, fg="#00ff00").pack(anchor="w")
        self.replace_entry = tk.Entry(replace_input_frame, bg="#111111", fg="#00ff00", insertbackground="#00ff00")
        self.replace_entry.pack(fill="x", pady=2)
        self.replace_entry.insert(0, "[REDACTED]")
        
        replace_btn = tk.Button(replace_input_frame, text="Replace All", command=self.replace_matches)
        style_button(replace_btn)
        replace_btn.pack(pady=2)
        
        self.replace_text = tk.Text(self.replace_frame, height=15, bg="#111111", fg="#00ff00", insertbackground="#00ff00")
        self.replace_text.pack(fill="both", expand=True, pady=5)

        # Info tab
        self.info_frame = tk.Frame(self.notebook, bg=BG_COLOR)
        self.notebook.add(self.info_frame, text="Pattern Info")
        
        style_label(tk.Label(self.info_frame, text="ℹ️ Pattern Information"))
        self.info_text = tk.Text(self.info_frame, height=20, bg="#111111", fg="#00ff00", insertbackground="#00ff00")
        self.info_text.pack(fill="both", expand=True, pady=5)
        
        # Load pattern explanation
        self.load_pattern_info()

        # Auto-test on startup
        self.test_regex()

    def on_pattern_change(self, event=None):
        self.test_regex()

    def on_text_change(self, event=None):
        self.test_regex()

    def load_common_pattern(self, event=None):
        selected = self.pattern_var.get()
        if selected in self.common_patterns:
            self.pattern_entry.delete(0, tk.END)
            self.pattern_entry.insert(0, self.common_patterns[selected])
            self.test_regex()

    def get_regex_flags(self):
        flags = 0
        if self.ignore_case.get():
            flags |= re.IGNORECASE
        if self.multiline.get():
            flags |= re.MULTILINE
        if self.dotall.get():
            flags |= re.DOTALL
        return flags

    def test_regex(self):
        pattern = self.pattern_entry.get()
        test_string = self.test_string_text.get("1.0", tk.END)
        
        if not pattern:
            return
        
        try:
            flags = self.get_regex_flags()
            compiled_pattern = re.compile(pattern, flags)
            
            # Find all matches
            matches = list(compiled_pattern.finditer(test_string))
            
            # Display matches
            self.display_matches(matches, test_string)
            
            # Display groups
            self.display_groups(matches)
            
            # Update pattern info
            self.update_pattern_info(pattern, len(matches))
            
        except re.error as e:
            self.matches_text.delete("1.0", tk.END)
            self.matches_text.insert(tk.END, f"❌ Regex Error: {e}")
            
            self.groups_text.delete("1.0", tk.END)
            self.groups_text.insert(tk.END, f"❌ Regex Error: {e}")

    def display_matches(self, matches, test_string):
        self.matches_text.delete("1.0", tk.END)
        
        if not matches:
            self.matches_text.insert(tk.END, "❌ No matches found\n")
            return
        
        self.matches_text.insert(tk.END, f"✅ Found {len(matches)} matches:\n\n")
        
        for i, match in enumerate(matches, 1):
            start, end = match.span()
            matched_text = match.group(0)
            
            # Show context around the match
            context_start = max(0, start - 20)
            context_end = min(len(test_string), end + 20)
            context = test_string[context_start:context_end]
            
            self.matches_text.insert(tk.END, f"Match {i}:\n")
            self.matches_text.insert(tk.END, f"  Text: '{matched_text}'\n")
            self.matches_text.insert(tk.END, f"  Position: {start}-{end}\n")
            self.matches_text.insert(tk.END, f"  Context: ...{context}...\n")
            self.matches_text.insert(tk.END, "-" * 40 + "\n")

    def display_groups(self, matches):
        self.groups_text.delete("1.0", tk.END)
        
        if not matches:
            self.groups_text.insert(tk.END, "❌ No matches found\n")
            return
        
        # Check if pattern has groups
        has_groups = any(match.groups() for match in matches)
        
        if not has_groups:
            self.groups_text.insert(tk.END, "ℹ️ No capture groups in this pattern\n")
            self.groups_text.insert(tk.END, "Add parentheses () to create capture groups\n")
            return
        
        self.groups_text.insert(tk.END, f"📋 Capture Groups from {len(matches)} matches:\n\n")
        
        for i, match in enumerate(matches, 1):
            self.groups_text.insert(tk.END, f"Match {i}:\n")
            self.groups_text.insert(tk.END, f"  Full match: '{match.group(0)}'\n")
            
            for j, group in enumerate(match.groups(), 1):
                self.groups_text.insert(tk.END, f"  Group {j}: '{group}'\n")
            
            # Named groups
            if match.groupdict():
                self.groups_text.insert(tk.END, "  Named groups:\n")
                for name, value in match.groupdict().items():
                    self.groups_text.insert(tk.END, f"    {name}: '{value}'\n")
            
            self.groups_text.insert(tk.END, "-" * 40 + "\n")

    def replace_matches(self):
        pattern = self.pattern_entry.get()
        test_string = self.test_string_text.get("1.0", tk.END)
        replacement = self.replace_entry.get()
        
        if not pattern:
            return
        
        try:
            flags = self.get_regex_flags()
            result = re.sub(pattern, replacement, test_string, flags=flags)
            
            self.replace_text.delete("1.0", tk.END)
            self.replace_text.insert(tk.END, "🔄 Replacement Result:\n\n")
            self.replace_text.insert(tk.END, result)
            
        except re.error as e:
            self.replace_text.delete("1.0", tk.END)
            self.replace_text.insert(tk.END, f"❌ Regex Error: {e}")

    def update_pattern_info(self, pattern, match_count):
        self.info_text.delete("1.0", tk.END)
        
        self.info_text.insert(tk.END, "🔍 PATTERN ANALYSIS\n")
        self.info_text.insert(tk.END, "=" * 40 + "\n\n")
        
        self.info_text.insert(tk.END, f"Pattern: {pattern}\n")
        self.info_text.insert(tk.END, f"Matches found: {match_count}\n")
        self.info_text.insert(tk.END, f"Pattern length: {len(pattern)} characters\n\n")
        
        # Analyze pattern components
        self.info_text.insert(tk.END, "Pattern Components:\n")
        
        if '(' in pattern:
            group_count = pattern.count('(') - pattern.count(r'\(')
            self.info_text.insert(tk.END, f"• Capture groups: {group_count}\n")
        
        if '[' in pattern:
            self.info_text.insert(tk.END, "• Character classes found\n")
        
        if '+' in pattern or '*' in pattern or '?' in pattern:
            self.info_text.insert(tk.END, "• Quantifiers found\n")
        
        if '^' in pattern:
            self.info_text.insert(tk.END, "• Start anchor (^) found\n")
        
        if '$' in pattern:
            self.info_text.insert(tk.END, "• End anchor ($) found\n")
        
        if '\\b' in pattern:
            self.info_text.insert(tk.END, "• Word boundaries (\\b) found\n")
        
        if '\\d' in pattern:
            self.info_text.insert(tk.END, "• Digit class (\\d) found\n")
        
        if '\\w' in pattern:
            self.info_text.insert(tk.END, "• Word class (\\w) found\n")
        
        if '\\s' in pattern:
            self.info_text.insert(tk.END, "• Whitespace class (\\s) found\n")

    def load_pattern_info(self):
        info_text = """
🔍 REGEX QUICK REFERENCE

BASIC PATTERNS:
• .        - Any character (except newline)
• \\d       - Any digit (0-9)
• \\w       - Any word character (a-z, A-Z, 0-9, _)
• \\s       - Any whitespace character
• [abc]    - Any character in brackets
• [^abc]   - Any character NOT in brackets
• [a-z]    - Any character in range

QUANTIFIERS:
• *        - 0 or more
• +        - 1 or more
• ?        - 0 or 1
• {n}      - Exactly n times
• {n,}     - n or more times
• {n,m}    - Between n and m times

ANCHORS:
• ^        - Start of string/line
• $        - End of string/line
• \\b       - Word boundary
• \\B       - Not word boundary

GROUPS:
• (abc)    - Capture group
• (?:abc)  - Non-capture group
• (?P<name>abc) - Named group

SPECIAL CHARACTERS:
• \\        - Escape character
• |        - OR operator
• ()       - Grouping
• []       - Character class
• {}       - Quantifier
• ^$.*+?   - Special characters (escape with \\)

FLAGS:
• i        - Case insensitive
• m        - Multiline mode
• s        - Dot matches all (including newline)
"""
        
        self.info_text.delete("1.0", tk.END)
        self.info_text.insert(tk.END, info_text)

    def load_text_file(self):
        file_path = filedialog.askopenfilename(
            title="Select Text File",
            filetypes=[("Text Files", "*.txt"), ("Log Files", "*.log"), ("All Files", "*.*")]
        )
        if file_path:
            try:
                with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                    content = f.read()
                self.test_string_text.delete("1.0", tk.END)
                self.test_string_text.insert(tk.END, content)
                self.test_regex()
            except Exception as e:
                messagebox.showerror("Error", f"Failed to load file: {e}")