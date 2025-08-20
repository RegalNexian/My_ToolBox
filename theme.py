# theme.py — Universal Sci-Fi UI Theme for Toolbox

# 🎨 Color Palette
BG_COLOR = "#0D0D0D"           # Deep space black
PANEL_COLOR = "#1B2735"        # Dark steel blue
TEXT_COLOR = "#E0FFFF"         # Light cyan
HIGHLIGHT_TEXT = "#00FF9F"     # Neon green
BTN_COLOR = "#00F5FF"          # Neon blue
BTN_HOVER = "#00CFFF"          # Lighter neon blue
BTN_BORDER_COLOR = "#00F5FF"   # Glow outline

# 🔠 Fonts
TITLE_FONT = ("Orbitron", 22, "bold")   # Tool titles
BTN_FONT = ("Consolas", 12, "bold")     # Buttons
LABEL_FONT = ("Consolas", 12, "bold")   # Labels
TEXTBOX_FONT = ("Consolas", 11)         # Text widgets

# 🔘 Button Styling Function
def style_button(btn):
    btn.config(
        bg=BTN_COLOR,
        fg=BG_COLOR,
        activebackground=BTN_HOVER,
        activeforeground=BG_COLOR,
        font=BTN_FONT,
        relief="flat",
        bd=0,
        highlightbackground=BTN_BORDER_COLOR,
        highlightthickness=2,
        cursor="hand2"
    )
    btn.bind("<Enter>", lambda e: btn.config(bg=BTN_HOVER))
    btn.bind("<Leave>", lambda e: btn.config(bg=BTN_COLOR))

# 🖋 Label Styling
def style_label(label):
    label.config(bg=BG_COLOR, fg=TEXT_COLOR, font=LABEL_FONT)

# 📝 Entry/Textbox Styling
def style_entry(entry, placeholder=None):
    entry.config(bg="#111111", fg=TEXT_COLOR, insertbackground=TEXT_COLOR,
                 relief="flat", font=TEXTBOX_FONT, highlightbackground=BTN_BORDER_COLOR)
    
    if placeholder:
        entry.insert(0, placeholder)
        entry.config(fg="gray")

        def on_focus_in(e):
            if entry.get() == placeholder:
                entry.delete(0, "end")
                entry.config(fg=TEXT_COLOR)

        def on_focus_out(e):
            if not entry.get():
                entry.insert(0, placeholder)
                entry.config(fg="gray")

        entry.bind("<FocusIn>", on_focus_in)
        entry.bind("<FocusOut>", on_focus_out)

def style_textbox(textbox):
    textbox.config(bg="#111111", fg=TEXT_COLOR, insertbackground=TEXT_COLOR,
                   relief="flat", font=TEXTBOX_FONT, wrap="word",
                   highlightbackground=BTN_BORDER_COLOR)
