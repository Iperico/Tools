"""Visual milestone browser with a lightweight gradient UI.

Shows milestones/steps from forensic_config.json with a gray circular gradient
background and yellow text. This is a read-only viewer for now; it focuses on
quick visibility of what exists and where.
"""
from __future__ import annotations

import json
import math
import os
from dataclasses import dataclass, asdict, field
from pathlib import Path
from typing import Dict, List, Optional
import tkinter as tk
from tkinter import messagebox, ttk

CONFIG_FILE = Path(__file__).with_name("forensic_config.json")

# Palette (neon-inspired background with cyan accents)
BG_DARK = "#050816"
BG_BASE = "#090c1f"
CARD_BG = "#121b3a"
TEXT_MAIN = "#9fffe0"
ACCENT = "#00e5ff"

# Typography choices for a sleeker look on Windows
FONT_TITLE = ("Bahnschrift", 22, "bold")
FONT_SECTION = ("Bahnschrift", 12, "bold")
FONT_BODY = ("Bahnschrift", 11)
FONT_MONO = ("Cascadia Code", 10)


@dataclass
class Step:
    name: str
    description: str
    script_path: Optional[str] = None

    def display(self) -> str:
        script = self.script_path if self.script_path else "<not set>"
        return f"- {self.name}: {self.description} (script: {script})"


@dataclass
class Milestone:
    name: str
    folder: Optional[str] = None
    steps: List[Step] = field(default_factory=list)


@dataclass
class GlobalSettings:
    workspace_folder: Optional[str] = None
    mysql_host: str = "localhost"
    mysql_port: int = 3306
    mysql_user: str = "root"
    mysql_password: Optional[str] = None
    mysql_database: str = "forensic"


@dataclass
class ForensicConfig:
    globals: GlobalSettings = field(default_factory=GlobalSettings)
    milestones: Dict[str, Milestone] = field(default_factory=dict)

    def to_json(self) -> str:
        serializable = asdict(self)
        return json.dumps(serializable, indent=4)

    @classmethod
    def from_json(cls, payload: str) -> "ForensicConfig":
        data = json.loads(payload)
        globals_cfg = GlobalSettings(**data.get("globals", {}))
        milestones_data = data.get("milestones", {})
        milestones = {
            name: Milestone(
                name=milestone["name"],
                folder=milestone.get("folder"),
                steps=[Step(**step) for step in milestone.get("steps", [])],
            )
            for name, milestone in milestones_data.items()
        }
        return cls(globals=globals_cfg, milestones=milestones)

    @classmethod
    def load(cls, path: Path = CONFIG_FILE) -> "ForensicConfig":
        if not path.exists():
            return cls()
        with path.open("r", encoding="utf-8") as fh:
            return cls.from_json(fh.read())

    def save(self, path: Path = CONFIG_FILE) -> None:
        with path.open("w", encoding="utf-8") as fh:
            fh.write(self.to_json())


def draw_radial_gradient(canvas: tk.Canvas, width: int, height: int) -> None:
    """Draw a neon-inspired circular gradient on the canvas."""
    canvas.delete("gradient")
    radius = max(width, height) * 0.75
    cx, cy = width / 2, height / 2
    steps = 30
    for i in range(steps):
        ratio = i / steps
        base = 20 + int(35 * ratio)
        red = max(0, base - 12)
        green = max(0, base - 4)
        blue = min(255, base + 90)
        color = f"#{red:02x}{green:02x}{blue:02x}"
        r = radius * (1 - ratio * 0.95)
        canvas.create_oval(
            cx - r,
            cy - r,
            cx + r,
            cy + r,
            fill=color,
            outline="",
            tags="gradient",
        )


class ForensicApp:
    def __init__(self, root: tk.Tk) -> None:
        self.root = root
        self.config = ForensicConfig.load()
        self.root.title("Forensic Milestones")
        self.root.geometry("1200x720")
        self.root.configure(bg=BG_BASE)
        self.root.attributes("-alpha", 0.94)

        self.bg_canvas = tk.Canvas(
            self.root,
            highlightthickness=0,
            bd=0,
            bg=BG_DARK,
        )
        self.bg_canvas.pack(fill="both", expand=True)
        self.bg_canvas.bind("<Configure>", self._on_resize)

        self.container = tk.Frame(self.bg_canvas, bg=BG_BASE, highlightthickness=0, bd=0)
        self.bg_canvas.create_window(0, 0, anchor="nw", window=self.container, tags="content")

        self._build_header()
        self._build_layout()
        self._populate_globals()
        self._populate_milestones()

    def _on_resize(self, event) -> None:
        draw_radial_gradient(self.bg_canvas, event.width, event.height)
        # Keep content pinned to canvas
        self.bg_canvas.coords("content", 0, 0)
        self.bg_canvas.itemconfig("content", width=event.width, height=event.height)

    def _build_header(self) -> None:
        header = tk.Frame(self.container, bg=BG_BASE, pady=10)
        header.pack(fill="x")
        title = tk.Label(
            header,
            text="Forensic Bebboloidi Investigations - FangoShit",
            fg=TEXT_MAIN,
            bg=BG_BASE,
            font=FONT_TITLE,
        )
        title.pack(side="left", padx=16)
        settings_btn = tk.Button(
            header,
            text="Settings",
            command=self._open_settings,
            fg=BG_DARK,
            bg=TEXT_MAIN,
            activebackground=ACCENT,
            activeforeground=BG_DARK,
            relief="flat",
            padx=12,
            pady=6,
            font=FONT_SECTION,
        )
        settings_btn.pack(side="right", padx=4)
        refresh = tk.Button(
            header,
            text="Refresh",
            command=self._refresh,
            fg=BG_DARK,
            bg=TEXT_MAIN,
            activebackground=ACCENT,
            activeforeground=BG_DARK,
            relief="flat",
            padx=12,
            pady=6,
            font=FONT_SECTION,
        )
        refresh.pack(side="right", padx=4)
        quit_btn = tk.Button(
            header,
            text="Quit",
            command=self.root.destroy,
            fg=BG_DARK,
            bg=TEXT_MAIN,
            activebackground=ACCENT,
            activeforeground=BG_DARK,
            relief="flat",
            padx=10,
            pady=6,
            font=FONT_SECTION,
        )
        quit_btn.pack(side="right", padx=4)

    def _build_layout(self) -> None:
        main = tk.Frame(self.container, bg=BG_BASE, padx=16, pady=10)
        main.pack(fill="both", expand=True)

        # Left: milestones list
        left = tk.Frame(main, bg=BG_BASE, padx=8)
        left.pack(side="left", fill="y")
        lbl = tk.Label(left, text="Milestones", fg=TEXT_MAIN, bg=BG_BASE, font=FONT_SECTION)
        lbl.pack(anchor="w")
        self.milestone_list = tk.Listbox(
            left,
            bg=CARD_BG,
            fg=TEXT_MAIN,
            selectbackground=ACCENT,
            selectforeground=BG_DARK,
            font=FONT_BODY,
            height=20,
            activestyle="none",
        )
        self.milestone_list.pack(fill="y", expand=True, pady=6)
        self.milestone_list.bind("<<ListboxSelect>>", self._on_select_milestone)

        # Right: details
        right = tk.Frame(main, bg=BG_BASE, padx=8)
        right.pack(side="left", fill="both", expand=True)

        globals_card = tk.Frame(
            right,
            bg=CARD_BG,
            padx=14,
            pady=10,
            highlightbackground=ACCENT,
            highlightcolor=ACCENT,
            highlightthickness=1,
        )
        globals_card.pack(fill="x", pady=(0, 10))
        tk.Label(
            globals_card,
            text="Global Settings",
            fg=TEXT_MAIN,
            bg=CARD_BG,
            font=FONT_SECTION,
        ).pack(anchor="w")
        self.global_text = tk.Label(
            globals_card,
            text="",
            fg=TEXT_MAIN,
            bg=CARD_BG,
            justify="left",
            font=FONT_MONO,
        )
        self.global_text.pack(anchor="w", pady=(4, 0))

        steps_card = tk.Frame(
            right,
            bg=CARD_BG,
            padx=14,
            pady=10,
            highlightbackground="#162447",
            highlightcolor="#162447",
            highlightthickness=1,
        )
        steps_card.pack(fill="both", expand=True)
        tk.Label(
            steps_card,
            text="Steps",
            fg=TEXT_MAIN,
            bg=CARD_BG,
            font=FONT_SECTION,
        ).pack(anchor="w")
        self.steps_tree = ttk.Treeview(
            steps_card,
            columns=("description", "script"),
            show="headings",
            selectmode="browse",
            height=12,
        )
        self.steps_tree.heading("description", text="Description")
        self.steps_tree.heading("script", text="Script")
        self.steps_tree.column("description", width=260, anchor="w")
        self.steps_tree.column("script", width=320, anchor="w")
        self.steps_tree.pack(fill="both", expand=True, pady=(6, 0))
        style = ttk.Style()
        style.theme_use("default")
        style.configure(
            "Treeview",
            background=CARD_BG,
            foreground=TEXT_MAIN,
            fieldbackground=CARD_BG,
            rowheight=26,
            bordercolor=CARD_BG,
            font=FONT_BODY,
        )
        style.configure("Treeview.Heading", background=BG_DARK, foreground=TEXT_MAIN, font=FONT_SECTION)
        style.map("Treeview", background=[("selected", ACCENT)], foreground=[("selected", BG_DARK)])

    def _populate_globals(self) -> None:
        g = self.config.globals
        workspace = g.workspace_folder or "<not set>"
        info = (
            f"Workspace: {workspace}\n"
            f"MySQL host: {g.mysql_host}:{g.mysql_port}\n"
            f"User/DB: {g.mysql_user} / {g.mysql_database}"
        )
        self.global_text.config(text=info)

    def _populate_milestones(self) -> None:
        self.milestone_list.delete(0, tk.END)
        for name in sorted(self.config.milestones):
            self.milestone_list.insert(tk.END, name)
        if self.config.milestones:
            self.milestone_list.selection_set(0)
            self._on_select_milestone()

    def _on_select_milestone(self, event=None) -> None:
        self.steps_tree.delete(*self.steps_tree.get_children())
        selection = self.milestone_list.curselection()
        if not selection:
            return
        name = self.milestone_list.get(selection[0])
        milestone = self.config.milestones.get(name)
        if not milestone:
            return
        for step in milestone.steps:
            script = step.script_path or "<not set>"
            self.steps_tree.insert("", tk.END, values=(step.description, script))

    def _refresh(self) -> None:
        try:
            self.config = ForensicConfig.load()
            self._populate_globals()
            self._populate_milestones()
            messagebox.showinfo("Refresh", "Configuration reloaded.")
        except Exception as exc:
            messagebox.showerror("Error", f"Could not reload config:\n{exc}")

    def _open_settings(self) -> None:
        """Modal window to edit project settings (DB + dataset folders)."""
        win = tk.Toplevel(self.root)
        win.title("Settings")
        win.configure(bg=BG_BASE)
        win.geometry("560x520")
        win.grab_set()

        section_title = lambda text: tk.Label(
            win,
            text=text,
            fg=TEXT_MAIN,
            bg=BG_BASE,
            font=FONT_SECTION,
        )

        def add_field(parent, label, value):
            row = tk.Frame(parent, bg=BG_BASE, pady=4)
            row.pack(fill="x")
            tk.Label(
                row,
                text=label,
                fg=TEXT_MAIN,
                bg=BG_BASE,
                width=18,
                anchor="w",
                font=FONT_BODY,
            ).pack(side="left")
            entry = tk.Entry(
                row,
                fg=TEXT_MAIN,
                bg=CARD_BG,
                insertbackground=TEXT_MAIN,
                relief="flat",
                width=46,
                font=FONT_BODY,
            )
            entry.insert(0, value or "")
            entry.pack(side="left", fill="x", expand=True, padx=(6, 0))
            return entry

        # Globals
        section_title("SQL DB Server / Globals").pack(anchor="w", pady=(10, 2))
        globals_frame = tk.Frame(win, bg=BG_BASE)
        globals_frame.pack(fill="x", padx=6)
        g = self.config.globals
        ent_workspace = add_field(globals_frame, "Workspace folder", g.workspace_folder or "")
        ent_host = add_field(globals_frame, "MySQL host", g.mysql_host)
        ent_port = add_field(globals_frame, "MySQL port", str(g.mysql_port))
        ent_user = add_field(globals_frame, "MySQL user", g.mysql_user)
        ent_password = add_field(globals_frame, "MySQL password", g.mysql_password or "")
        ent_db = add_field(globals_frame, "Database", g.mysql_database)
        ent_password.config(show="*")

        # Milestone folders
        section_title("Dataset folders per milestone").pack(anchor="w", pady=(16, 2))
        ms_frame = tk.Frame(win, bg=BG_BASE)
        ms_frame.pack(fill="x", padx=6)
        milestone_entries: Dict[str, tk.Entry] = {}
        for name, milestone in sorted(self.config.milestones.items()):
            milestone_entries[name] = add_field(ms_frame, name, milestone.folder or "")

        btn_row = tk.Frame(win, bg=BG_BASE, pady=14)
        btn_row.pack(fill="x")

        def on_save():
            # Update globals
            g.workspace_folder = ent_workspace.get().strip() or None
            g.mysql_host = ent_host.get().strip() or g.mysql_host
            g.mysql_user = ent_user.get().strip() or g.mysql_user
            g.mysql_password = ent_password.get().strip() or None
            g.mysql_database = ent_db.get().strip() or g.mysql_database
            port_val = ent_port.get().strip()
            try:
                g.mysql_port = int(port_val) if port_val else g.mysql_port
            except ValueError:
                messagebox.showerror("Invalid port", "MySQL port must be a number.")
                return

            # Update milestone folders
            for name, entry in milestone_entries.items():
                val = entry.get().strip()
                if name in self.config.milestones:
                    self.config.milestones[name].folder = val or None

            try:
                self.config.save()
                self._populate_globals()
                self._populate_milestones()
                messagebox.showinfo("Saved", "Settings updated and saved.")
                win.destroy()
            except Exception as exc:
                messagebox.showerror("Error", f"Could not save settings:\n{exc}")

        save_btn = tk.Button(
            btn_row,
            text="Save",
            command=on_save,
            fg=BG_DARK,
            bg=TEXT_MAIN,
            activebackground=ACCENT,
            activeforeground=BG_DARK,
            relief="flat",
            padx=14,
            pady=6,
            font=FONT_SECTION,
        )
        save_btn.pack(side="right", padx=6)

        cancel_btn = tk.Button(
            btn_row,
            text="Cancel",
            command=win.destroy,
            fg=TEXT_MAIN,
            bg=BG_DARK,
            activebackground=ACCENT,
            activeforeground=BG_DARK,
            relief="flat",
            padx=12,
            pady=6,
            font=FONT_SECTION,
        )
        cancel_btn.pack(side="right", padx=6)


def main() -> None:
    root = tk.Tk()
    app = ForensicApp(root)
    root.mainloop()


if __name__ == "__main__":
    main()
