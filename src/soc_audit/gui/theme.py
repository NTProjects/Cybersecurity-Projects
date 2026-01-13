"""Dark theme configuration for the SOC Audit GUI.

This module provides a dark theme that matches the Activity Timeline
and Details panels for a consistent, eye-friendly appearance.

To revert to the default light theme, simply remove the apply_dark_theme()
call from main_window.py.
"""
from __future__ import annotations

import tkinter as tk
from tkinter import ttk


# Dark theme color palette
COLORS = {
    "bg": "#1e1e1e",           # Main background
    "bg_light": "#252526",     # Slightly lighter background
    "bg_lighter": "#2d2d30",   # Panel backgrounds
    "bg_highlight": "#3e3e42", # Hover/selection background
    "fg": "#d4d4d4",           # Main text
    "fg_dim": "#888888",       # Dimmed text
    "border": "#3e3e42",       # Border color
    "accent": "#4a90d9",       # Accent color (blue)
    "green": "#4ec9b0",        # Success/positive
    "orange": "#ffa726",       # Warning
    "red": "#ff6b6b",          # Error/critical
}


def apply_dark_theme(root: tk.Tk) -> None:
    """
    Apply dark theme to the entire application.
    
    This configures ttk styles and the root window background
    to use a dark color scheme matching the SOC dashboard panels.
    
    Args:
        root: The Tkinter root window.
    """
    # Configure root window
    root.configure(bg=COLORS["bg"])
    
    # Create and configure ttk style
    style = ttk.Style()
    
    # Try to use 'clam' theme as base (works well with custom colors)
    try:
        style.theme_use("clam")
    except tk.TclError:
        pass  # Use default if clam not available
    
    # Configure ttk Frame
    style.configure(
        "TFrame",
        background=COLORS["bg"],
    )
    
    # Configure ttk LabelFrame
    style.configure(
        "TLabelframe",
        background=COLORS["bg_lighter"],
        bordercolor=COLORS["border"],
    )
    style.configure(
        "TLabelframe.Label",
        background=COLORS["bg_lighter"],
        foreground=COLORS["fg"],
        font=("Segoe UI", 9, "bold"),
    )
    
    # Configure ttk Label
    style.configure(
        "TLabel",
        background=COLORS["bg_lighter"],
        foreground=COLORS["fg"],
    )
    
    # Configure ttk Button
    style.configure(
        "TButton",
        background=COLORS["bg_highlight"],
        foreground=COLORS["fg"],
        bordercolor=COLORS["border"],
        padding=(10, 5),
    )
    style.map(
        "TButton",
        background=[("active", COLORS["accent"]), ("pressed", COLORS["bg"])],
        foreground=[("active", "#ffffff")],
    )
    
    # Configure ttk Entry
    style.configure(
        "TEntry",
        fieldbackground=COLORS["bg"],
        foreground=COLORS["fg"],
        insertcolor=COLORS["fg"],
        bordercolor=COLORS["border"],
    )
    
    # Configure ttk Combobox
    style.configure(
        "TCombobox",
        fieldbackground=COLORS["bg"],
        background=COLORS["bg_highlight"],
        foreground=COLORS["fg"],
        arrowcolor=COLORS["fg"],
        bordercolor=COLORS["border"],
    )
    style.map(
        "TCombobox",
        fieldbackground=[("readonly", COLORS["bg"])],
        foreground=[("readonly", COLORS["fg"])],
    )
    
    # Configure ttk Treeview
    style.configure(
        "Treeview",
        background=COLORS["bg"],
        foreground=COLORS["fg"],
        fieldbackground=COLORS["bg"],
        bordercolor=COLORS["border"],
        rowheight=25,
    )
    style.configure(
        "Treeview.Heading",
        background=COLORS["bg_lighter"],
        foreground=COLORS["fg"],
        bordercolor=COLORS["border"],
    )
    style.map(
        "Treeview",
        background=[("selected", COLORS["bg_highlight"])],
        foreground=[("selected", "#ffffff")],
    )
    style.map(
        "Treeview.Heading",
        background=[("active", COLORS["bg_highlight"])],
    )
    
    # Configure ttk Notebook (tabs)
    style.configure(
        "TNotebook",
        background=COLORS["bg"],
        bordercolor=COLORS["border"],
    )
    style.configure(
        "TNotebook.Tab",
        background=COLORS["bg_lighter"],
        foreground=COLORS["fg"],
        padding=(10, 5),
        bordercolor=COLORS["border"],
    )
    style.map(
        "TNotebook.Tab",
        background=[("selected", COLORS["bg_highlight"]), ("active", COLORS["bg_highlight"])],
        foreground=[("selected", "#ffffff")],
    )
    
    # Configure ttk Progressbar
    style.configure(
        "TProgressbar",
        background=COLORS["green"],
        troughcolor=COLORS["bg"],
        bordercolor=COLORS["border"],
    )
    
    # Configure ttk Separator
    style.configure(
        "TSeparator",
        background=COLORS["border"],
    )
    
    # Configure ttk Scrollbar
    style.configure(
        "TScrollbar",
        background=COLORS["bg_lighter"],
        troughcolor=COLORS["bg"],
        bordercolor=COLORS["border"],
        arrowcolor=COLORS["fg"],
    )
    style.map(
        "TScrollbar",
        background=[("active", COLORS["bg_highlight"])],
    )
    
    # Configure ttk PanedWindow
    style.configure(
        "TPanedwindow",
        background=COLORS["bg"],
    )
    
    # Configure ttk Menubutton
    style.configure(
        "TMenubutton",
        background=COLORS["bg_lighter"],
        foreground=COLORS["fg"],
    )
