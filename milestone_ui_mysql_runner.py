"""
SAFENET Milestone UI (MySQL runner edition)

Adds:
- Stage 0 Bootstrap execution (mysql_forensic_init.sql or optimized)
- Run buttons to execute SQL/Python steps from the UI
- Output console panel

Assumptions (per ReadUI.md):
- workspace_folder contains: DataSetGlobal/, Tools/, DbScripts/ (or scripts live in Tools/)
- script_path in forensic_config.json is usually relative (e.g. "m02_windows_logs_01_log_dump.py")
"""
from __future__ import annotations

import json
import math
import os
import re
import shlex
import subprocess
import sys
import time
from types import SimpleNamespace
from dataclasses import dataclass, asdict, field
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Tuple

import tkinter as tk
from tkinter import messagebox, ttk, filedialog, simpledialog

CONFIG_FILE = Path(__file__).with_name("forensic_config.json")
STATE_FILE = Path(__file__).with_name("forensic_state.json")

# Palette
BG_DARK = "#050816"
BG_BASE = "#090c1f"
CARD_BG = "#121b3a"
TEXT_MAIN = "#9fffe0"
ACCENT = "#00e5ff"
DANGER = "#ff5c5c"

FONT_TITLE = ("Bahnschrift", 20, "bold")
FONT_SECTION = ("Bahnschrift", 12, "bold")
FONT_BODY = ("Bahnschrift", 11)
FONT_MONO = ("Cascadia Code", 10)

OP_ALL = "ALL"
OP_INIT = "INIT"
OP_DUMP = "DUMP"
OP_VALIDATE = "VALIDATE"
OP_INSERT = "INSERT"
OP_SHOW = "SHOW"
OP_UNKNOWN = "UNSET"
OP_DISPLAY = [OP_INIT, OP_DUMP, OP_INSERT, OP_VALIDATE, OP_SHOW]
OP_FILTERS = [OP_ALL] + OP_DISPLAY

try:
    import mysql_live_schema_view as live_view
    LIVE_VIEW_IMPORT_ERROR: Optional[str] = None
except Exception as exc:
    live_view = None
    LIVE_VIEW_IMPORT_ERROR = str(exc)

# ------------- Config models -------------
@dataclass
class Step:
    name: str
    description: str
    script_path: Optional[str] = None
    operation: Optional[str] = None

@dataclass
class Milestone:
    name: str
    folder: Optional[str] = None
    steps: List[Step] = field(default_factory=list)
    external_collect: bool = False
    source_root: Optional[str] = None
    db_tables: List[str] = field(default_factory=list)
    raw_milestone_code: Optional[str] = None

@dataclass
class GlobalSettings:
    workspace_folder: Optional[str] = None
    mysql_host: str = "127.0.0.1"
    mysql_port: int = 3306
    mysql_user: str = "forensic"
    mysql_password: Optional[str] = None
    mysql_database: str = "forensic"
    # Optional: explicit mysql client path (otherwise uses "mysql" in PATH)
    mysql_cli: Optional[str] = None
    # Optional: explicit python executable path
    python_exe: Optional[str] = None
    # Debug: allow destructive DB reset from UI
    allow_db_reset: bool = False

@dataclass
class ForensicConfig:
    globals: GlobalSettings = field(default_factory=GlobalSettings)
    milestones: Dict[str, Milestone] = field(default_factory=dict)

    def to_json(self) -> str:
        return json.dumps(asdict(self), indent=4)

    @classmethod
    def from_json(cls, payload: str) -> "ForensicConfig":
        data = json.loads(payload)
        globals_cfg = GlobalSettings(**data.get("globals", {}))
        milestones_data = data.get("milestones", {})
        milestones: Dict[str, Milestone] = {}
        for key, ms in milestones_data.items():
            milestones[key] = Milestone(
                name=ms["name"],
                folder=ms.get("folder"),
                external_collect=bool(ms.get("external_collect", False)),
                source_root=ms.get("source_root"),
                db_tables=ms.get("db_tables", []),
                raw_milestone_code=ms.get("raw_milestone_code"),
                steps=[Step(**s) for s in ms.get("steps", [])],
            )
        return cls(globals=globals_cfg, milestones=milestones)

    @classmethod
    def load(cls, path: Path = CONFIG_FILE) -> "ForensicConfig":
        if not path.exists():
            return cls()
        return cls.from_json(path.read_text(encoding="utf-8"))

    def save(self, path: Path = CONFIG_FILE) -> None:
        path.write_text(self.to_json(), encoding="utf-8")

# ------------- Local state -------------
@dataclass
class ForensicState:
    init_runs: Dict[str, Dict[str, str]] = field(default_factory=dict)
    init_milestones: Dict[str, str] = field(default_factory=dict)
    last_runs: Dict[str, Dict[str, str]] = field(default_factory=dict)

    def to_json(self) -> str:
        return json.dumps(asdict(self), indent=4)

    @classmethod
    def load(cls, path: Path = STATE_FILE) -> "ForensicState":
        if not path.exists():
            return cls()
        data = json.loads(path.read_text(encoding="utf-8"))
        return cls(
            init_runs=data.get("init_runs", {}),
            init_milestones=data.get("init_milestones", {}),
            last_runs=data.get("last_runs", {}),
        )

    def save(self, path: Path = STATE_FILE) -> None:
        path.write_text(self.to_json(), encoding="utf-8")

# ------------- Helpers -------------
def draw_radial_gradient(canvas: tk.Canvas, width: int, height: int) -> None:
    canvas.delete("gradient")
    radius = max(width, height) * 0.75
    cx, cy = width / 2, height / 2

    steps = 48
    for i in range(steps, 0, -1):
        frac = i / steps
        r = radius * frac
        val = int(8 + 40 * (1 - frac))  # subtle
        color = f"#{val:02x}{val:02x}{(val+12):02x}"
        canvas.create_oval(cx - r, cy - r, cx + r, cy + r, fill=color, outline="", tags="gradient")

def safe_join(*parts: str) -> Path:
    return Path(*[p for p in parts if p])

def resolve_script_path(workspace: Optional[str], script_path: str) -> Path:
    """Resolve relative script_path into workspace folder (Tools/ by default)."""
    p = Path(script_path)
    if p.is_absolute():
        return p
    # common layout: C:\SAFENET\Tools\<script>
    if workspace:
        tools = Path(workspace) / "Tools"
        candidate = tools / p
        return candidate
    return p

def run_subprocess(cmd: List[str], cwd: Optional[Path] = None, env: Optional[dict] = None) -> Tuple[int, str]:
    """Run a subprocess and capture stdout+stderr."""
    try:
        p = subprocess.run(
            cmd,
            cwd=str(cwd) if cwd else None,
            env=env,
            text=True,
            capture_output=True,
            encoding="utf-8",
            errors="replace",
        )
        out = (p.stdout or "") + ("\n" + p.stderr if p.stderr else "")
        return p.returncode, out.strip()
    except FileNotFoundError as e:
        return 127, f"File not found: {e}"
    except Exception as e:
        return 1, f"Exception: {e}"

def normalize_operation(value: Optional[str]) -> Optional[str]:
    if not value:
        return None
    v = value.strip().upper()
    return v if v in OP_DISPLAY else None

def infer_operation(step: Step) -> str:
    text = " ".join([step.name, step.description, step.script_path or ""]).lower()
    if any(k in text for k in ("init", "bootstrap", "schema")):
        return OP_INIT
    if any(k in text for k in ("insert", "load", "seed", "import")):
        return OP_INSERT
    if any(k in text for k in ("validate", "verify", "check", "normalize")):
        return OP_VALIDATE
    if any(k in text for k in ("dump", "extract", "capture", "export", "acquire")):
        return OP_DUMP
    if any(k in text for k in ("show", "report", "summary", "view")):
        return OP_SHOW
    return OP_UNKNOWN

def step_key(step: Step) -> str:
    return step.script_path or step.name

# ------------- UI -------------
class ForensicApp:
    def __init__(self, root: tk.Tk):
        self.root = root
        self.root.title("SAFENET Milestone UI (MySQL Runner)")
        self.root.geometry("1080x680")
        self.root.configure(bg=BG_BASE)

        self.config = ForensicConfig.load()
        self.state = ForensicState.load()
        self._current_milestone: Optional[Milestone] = None
        self._step_map: Dict[str, Tuple[Step, str]] = {}
        self._live_win: Optional[tk.Toplevel] = None
        self._live_after_id: Optional[str] = None
        self._live_vars: Dict[str, tk.Variable] = {}
        self._live_output: Optional[tk.Text] = None

        # background canvas
        self.bg = tk.Canvas(root, bg=BG_BASE, highlightthickness=0)
        self.bg.place(relx=0, rely=0, relwidth=1, relheight=1)
        self.root.bind("<Configure>", self._on_resize)

        # main layout
        self.container = tk.Frame(root, bg=BG_BASE)
        self.container.pack(fill="both", expand=True, padx=14, pady=14)

        header = tk.Frame(self.container, bg=BG_BASE)
        header.pack(fill="x")
        tk.Label(header, text="SAFENET Milestones", fg=TEXT_MAIN, bg=BG_BASE, font=FONT_TITLE).pack(side="left")

        body = tk.Frame(self.container, bg=BG_BASE)
        body.pack(fill="both", expand=True, pady=(10, 0))

        left = tk.Frame(body, bg=BG_BASE, width=360)
        left.pack(side="left", fill="y")
        left.pack_propagate(False)

        right = tk.Frame(body, bg=BG_BASE)
        right.pack(side="left", fill="both", expand=True, padx=(14, 0))

        # globals card
        gcard = tk.Frame(left, bg=CARD_BG, padx=14, pady=10, highlightthickness=1,
                         highlightbackground="#162447", highlightcolor="#162447")
        gcard.pack(fill="x")
        tk.Label(gcard, text="Globals", fg=TEXT_MAIN, bg=CARD_BG, font=FONT_SECTION).pack(anchor="w")
        self.global_text = tk.Label(gcard, text="", fg=TEXT_MAIN, bg=CARD_BG, justify="left", font=FONT_MONO)
        self.global_text.pack(anchor="w", pady=(4, 0))

        # milestone list
        mcard = tk.Frame(left, bg=CARD_BG, padx=14, pady=10, highlightthickness=1,
                         highlightbackground="#162447", highlightcolor="#162447")
        mcard.pack(fill="x", pady=(10, 0))
        tk.Label(mcard, text="Milestones", fg=TEXT_MAIN, bg=CARD_BG, font=FONT_SECTION).pack(anchor="w")
        self.milestone_list = tk.Listbox(mcard, bg=BG_DARK, fg=TEXT_MAIN, font=FONT_BODY, height=9,
                                         highlightthickness=0, selectbackground=ACCENT, selectforeground=BG_DARK)
        self.milestone_list.pack(fill="x", expand=False, pady=(6, 4))
        self.milestone_list.bind("<<ListboxSelect>>", self._on_select_milestone)
        self.milestone_list.bind("<Double-Button-1>", self._on_milestone_double_click)

        self.milestone_info = tk.Label(
            mcard,
            text="",
            fg=TEXT_MAIN,
            bg=CARD_BG,
            font=FONT_MONO,
            justify="left",
            wraplength=320,
        )
        self.milestone_info.pack(anchor="w", pady=(2, 0))

        # DB actions
        dbcard = tk.Frame(left, bg=CARD_BG, padx=14, pady=10, highlightthickness=1,
                          highlightbackground="#162447", highlightcolor="#162447")
        dbcard.pack(fill="x", pady=(10, 0))
        tk.Label(dbcard, text="DB Actions", fg=TEXT_MAIN, bg=CARD_BG, font=FONT_SECTION).pack(anchor="w")

        db_row = tk.Frame(dbcard, bg=CARD_BG)
        db_row.pack(fill="x", pady=(6, 4))
        tk.Button(db_row, text="Live DB", command=self._open_live_db_view, bg=BG_DARK, fg=TEXT_MAIN,
                  activebackground=ACCENT, activeforeground=BG_DARK, relief="flat",
                  padx=10, pady=4, font=FONT_BODY).pack(side="left", padx=(0, 6))
        tk.Button(db_row, text="Overview", command=self._open_db_overview, bg=BG_DARK, fg=TEXT_MAIN,
                  activebackground=ACCENT, activeforeground=BG_DARK, relief="flat",
                  padx=10, pady=4, font=FONT_BODY).pack(side="left", padx=(0, 6))
        tk.Button(db_row, text="Validate", command=self._validate_tables_for_milestone, bg=BG_DARK, fg=TEXT_MAIN,
                  activebackground=ACCENT, activeforeground=BG_DARK, relief="flat",
                  padx=10, pady=4, font=FONT_BODY).pack(side="left")

        db_row2 = tk.Frame(dbcard, bg=CARD_BG)
        db_row2.pack(fill="x")
        tk.Button(db_row2, text="Settings", command=self._open_settings, bg=BG_DARK, fg=TEXT_MAIN,
                  activebackground=ACCENT, activeforeground=BG_DARK, relief="flat",
                  padx=10, pady=4, font=FONT_BODY).pack(side="left", padx=(0, 6))
        tk.Button(db_row2, text="Refresh", command=self._refresh, bg=BG_DARK, fg=TEXT_MAIN,
                  activebackground=ACCENT, activeforeground=BG_DARK, relief="flat",
                  padx=10, pady=4, font=FONT_BODY).pack(side="left", padx=(0, 6))
        tk.Button(db_row2, text="Reset", command=self._open_db_reset, bg=BG_DARK, fg=TEXT_MAIN,
                  activebackground=ACCENT, activeforeground=BG_DARK, relief="flat",
                  padx=10, pady=4, font=FONT_BODY).pack(side="left")

        query_row = tk.Frame(dbcard, bg=CARD_BG)
        query_row.pack(fill="x", pady=(6, 0))
        tk.Label(query_row, text="Quick query (SELECT):", fg=TEXT_MAIN, bg=CARD_BG, font=FONT_BODY).pack(anchor="w")
        query_input = tk.Frame(query_row, bg=CARD_BG)
        query_input.pack(fill="x", pady=(4, 0))
        self.quick_query = tk.Entry(query_input, fg=TEXT_MAIN, bg=BG_DARK, insertbackground=TEXT_MAIN,
                                    relief="flat", font=FONT_MONO)
        self.quick_query.pack(side="left", fill="x", expand=True, padx=(0, 6))
        tk.Button(query_input, text="Run", command=self._run_quick_query, bg=TEXT_MAIN, fg=BG_DARK,
                  activebackground=ACCENT, activeforeground=BG_DARK, relief="flat",
                  padx=10, pady=4, font=FONT_BODY).pack(side="left")

        # left pane for operations + output
        left_pane = tk.PanedWindow(left, orient="vertical", bg=BG_BASE, sashwidth=6, sashrelief="flat")
        left_pane.pack(fill="both", expand=True, pady=(10, 0))

        opcard = tk.Frame(left_pane, bg=CARD_BG, padx=14, pady=10, highlightthickness=1,
                          highlightbackground="#162447", highlightcolor="#162447")
        left_pane.add(opcard, minsize=260)

        op_header = tk.Frame(opcard, bg=CARD_BG)
        op_header.pack(fill="x")
        tk.Label(op_header, text="Operations", fg=TEXT_MAIN, bg=CARD_BG, font=FONT_SECTION).pack(side="left")
        self.run_btn = tk.Button(op_header, text="Run Operation", command=self._run_selected_step,
                                 bg=TEXT_MAIN, fg=BG_DARK, activebackground=ACCENT, activeforeground=BG_DARK,
                                 relief="flat", padx=10, pady=6, font=FONT_SECTION, state="disabled")
        self.run_btn.pack(side="right")

        self.op_filter = tk.StringVar(value=OP_ALL)

        self.steps_tree = ttk.Treeview(
            opcard,
            columns=("operation", "step", "status", "last"),
            show="headings",
            selectmode="browse",
            height=10,
        )
        self.steps_tree.heading("operation", text="Op")
        self.steps_tree.heading("step", text="Operation")
        self.steps_tree.heading("status", text="Status")
        self.steps_tree.heading("last", text="Last Run")
        self.steps_tree.column("operation", width=70, anchor="w")
        self.steps_tree.column("step", width=170, anchor="w")
        self.steps_tree.column("status", width=70, anchor="w")
        self.steps_tree.column("last", width=110, anchor="w")
        self.steps_tree.pack(fill="x", expand=False, pady=(6, 6))
        self.steps_tree.bind("<<TreeviewSelect>>", self._on_step_selected)

        self.policy_label = tk.Label(
            opcard,
            text="",
            fg=TEXT_MAIN,
            bg=CARD_BG,
            font=FONT_BODY,
            justify="left",
            wraplength=320,
        )
        self.policy_label.pack(anchor="w", pady=(2, 2))

        self.step_hint = tk.Label(
            opcard,
            text="",
            fg=TEXT_MAIN,
            bg=CARD_BG,
            font=FONT_BODY,
            justify="left",
            wraplength=320,
        )
        self.step_hint.pack(anchor="w", pady=(2, 0))

        outcard = tk.Frame(left_pane, bg=CARD_BG, padx=14, pady=10, highlightthickness=1,
                           highlightbackground="#162447", highlightcolor="#162447")
        left_pane.add(outcard, minsize=160)

        out_header = tk.Frame(outcard, bg=CARD_BG)
        out_header.pack(fill="x")
        tk.Label(out_header, text="Output", fg=TEXT_MAIN, bg=CARD_BG, font=FONT_SECTION).pack(side="left")
        self.select_btn = tk.Button(out_header, text="Select All", command=self._select_output_text,
                                    bg=BG_DARK, fg=TEXT_MAIN, activebackground=ACCENT, activeforeground=BG_DARK,
                                    relief="flat", padx=8, pady=4, font=FONT_BODY)
        self.select_btn.pack(side="right", padx=(6, 0))
        self.clear_btn = tk.Button(out_header, text="Clear", command=self._clear_output,
                                   bg=BG_DARK, fg=TEXT_MAIN, activebackground=ACCENT, activeforeground=BG_DARK,
                                   relief="flat", padx=8, pady=4, font=FONT_BODY)
        self.clear_btn.pack(side="right")

        self.output = tk.Text(outcard, bg=BG_DARK, fg=TEXT_MAIN, insertbackground=TEXT_MAIN,
                              font=FONT_MONO, height=12, wrap="word")
        self.output.pack(fill="both", expand=True, pady=(6, 0))

        style = ttk.Style()
        style.theme_use("default")
        style.configure("Treeview", background=CARD_BG, foreground=TEXT_MAIN, fieldbackground=CARD_BG,
                        rowheight=26, bordercolor=CARD_BG, font=FONT_BODY)
        style.configure("Treeview.Heading", background=BG_DARK, foreground=TEXT_MAIN, font=FONT_SECTION)
        style.map("Treeview", background=[("selected", ACCENT)], foreground=[("selected", BG_DARK)])

        # live graph (right panel)
        graph_card = tk.Frame(right, bg=CARD_BG, padx=14, pady=10, highlightthickness=1,
                              highlightbackground="#162447", highlightcolor="#162447")
        graph_card.pack(fill="both", expand=True)
        self._build_live_graph(graph_card)

        self._populate_globals()
        self._populate_milestones()
        self._refresh_graph_view()
        self._toggle_graph_auto()

    def _on_resize(self, event) -> None:
        draw_radial_gradient(self.bg, event.width, event.height)

    def _place_graph_sash(self) -> None:
        pane = getattr(self, "_right_pane", None)
        if not pane or not pane.winfo_exists():
            return
        height = pane.winfo_height()
        if height <= 1:
            self.root.after(200, self._place_graph_sash)
            return
        pane.sash_place(0, 0, int(height * 0.58))

    def _populate_globals(self) -> None:
        g = self.config.globals
        workspace = g.workspace_folder or "<not set>"
        info = (
            f"Workspace: {workspace}\n"
            f"MySQL host: {g.mysql_host}:{g.mysql_port}\n"
            f"User/DB: {g.mysql_user} / {g.mysql_database}\n"
            f"MySQL CLI: {g.mysql_cli or 'mysql (from PATH)'}\n"
            f"Python: {g.python_exe or sys.executable}"
        )
        self.global_text.config(text=info)

    def _populate_milestones(self) -> None:
        self.milestone_list.delete(0, tk.END)
        for name in sorted(self.config.milestones):
            self.milestone_list.insert(tk.END, name)
        if self.config.milestones:
            self.milestone_list.selection_set(0)
            self._on_select_milestone()
        else:
            self._current_milestone = None
            self._rebuild_steps()

    def _on_select_milestone(self, event=None) -> None:
        selection = self.milestone_list.curselection()
        if not selection:
            self._current_milestone = None
            self._rebuild_steps()
            return
        name = self.milestone_list.get(selection[0])
        ms = self.config.milestones.get(name)
        if not ms:
            self._current_milestone = None
            self._rebuild_steps()
            return
        self._current_milestone = ms
        self._rebuild_steps()

    def _on_milestone_double_click(self, event=None) -> None:
        self._on_select_milestone()
        children = self.steps_tree.get_children()
        if children:
            self.steps_tree.selection_set(children[0])
            self.steps_tree.focus(children[0])
            self.steps_tree.see(children[0])
            self._update_run_state()

    def _on_filter_change(self) -> None:
        self._rebuild_steps()

    def _select_all_text(self, widget: tk.Text) -> None:
        widget.tag_add("sel", "1.0", "end")
        widget.mark_set("insert", "1.0")
        widget.see("1.0")

    def _select_output_text(self) -> None:
        self._select_all_text(self.output)

    def _build_live_graph(self, parent: tk.Frame) -> None:
        self._graph_vars = {
            "tail_count": tk.IntVar(value=3),
            "auto_refresh": tk.BooleanVar(value=True),
            "refresh_seconds": tk.IntVar(value=8),
            "hint": tk.StringVar(value="raw"),
        }
        self._graph_selected_table: Optional[str] = None
        self._graph_snapshot: Dict[str, object] = {}
        self._graph_after_id: Optional[str] = None
        self._graph_preview_cache: Dict[str, Tuple[float, List[str]]] = {}
        self._graph_hover_after: Optional[str] = None
        self._graph_hover_table: Optional[str] = None
        self._graph_tooltip: Optional[tk.Toplevel] = None
        self._graph_tooltip_label: Optional[tk.Label] = None

        header = tk.Frame(parent, bg=CARD_BG)
        header.pack(fill="x")
        tk.Label(header, text="Live DB Graph", fg=TEXT_MAIN, bg=CARD_BG, font=FONT_SECTION).pack(side="left")
        tk.Button(
            header,
            text="Refresh",
            command=self._refresh_graph_view,
            bg=TEXT_MAIN,
            fg=BG_DARK,
            activebackground=ACCENT,
            activeforeground=BG_DARK,
            relief="flat",
            padx=10,
            pady=4,
            font=FONT_BODY,
        ).pack(side="right")

        controls = tk.Frame(parent, bg=CARD_BG)
        controls.pack(fill="x", pady=(6, 6))
        tk.Label(controls, text="Find", fg=TEXT_MAIN, bg=CARD_BG, font=FONT_BODY).pack(side="left")
        hint_entry = tk.Entry(
            controls,
            textvariable=self._graph_vars["hint"],
            width=14,
            bg=BG_DARK,
            fg=TEXT_MAIN,
            insertbackground=TEXT_MAIN,
        )
        hint_entry.pack(side="left", padx=(6, 10))
        hint_entry.bind("<Return>", lambda _evt: self._apply_graph_hint())

        tk.Label(controls, text="Tail", fg=TEXT_MAIN, bg=CARD_BG, font=FONT_BODY).pack(side="left")
        tk.Spinbox(
            controls,
            from_=1,
            to=25,
            width=4,
            textvariable=self._graph_vars["tail_count"],
            bg=BG_DARK,
            fg=TEXT_MAIN,
            insertbackground=TEXT_MAIN,
        ).pack(side="left", padx=(6, 10))

        tk.Label(controls, text="Refresh (s)", fg=TEXT_MAIN, bg=CARD_BG, font=FONT_BODY).pack(side="left")
        tk.Spinbox(
            controls,
            from_=1,
            to=60,
            width=4,
            textvariable=self._graph_vars["refresh_seconds"],
            bg=BG_DARK,
            fg=TEXT_MAIN,
            insertbackground=TEXT_MAIN,
        ).pack(side="left", padx=(6, 10))

        tk.Checkbutton(
            controls,
            text="Auto",
            variable=self._graph_vars["auto_refresh"],
            command=self._toggle_graph_auto,
            bg=CARD_BG,
            fg=TEXT_MAIN,
            selectcolor=CARD_BG,
            activebackground=CARD_BG,
            font=FONT_BODY,
        ).pack(side="left", padx=(0, 10))

        quick = tk.Frame(parent, bg=CARD_BG)
        quick.pack(fill="x", pady=(0, 6))
        tk.Label(quick, text="Quick focus", fg=TEXT_MAIN, bg=CARD_BG, font=FONT_BODY).pack(side="left")
        tk.Button(
            quick,
            text="Raw",
            command=lambda: self._set_graph_focus("EVENTI_RAW", "raw"),
            bg=BG_DARK,
            fg=TEXT_MAIN,
            activebackground=ACCENT,
            activeforeground=BG_DARK,
            relief="flat",
            padx=8,
            pady=3,
            font=FONT_BODY,
        ).pack(side="left", padx=(6, 6))
        tk.Button(
            quick,
            text="Win Core",
            command=lambda: self._set_graph_focus("WIN_EVENT_CORE", "core"),
            bg=BG_DARK,
            fg=TEXT_MAIN,
            activebackground=ACCENT,
            activeforeground=BG_DARK,
            relief="flat",
            padx=8,
            pady=3,
            font=FONT_BODY,
        ).pack(side="left", padx=(0, 6))
        tk.Button(
            quick,
            text="Evidence",
            command=lambda: self._set_graph_focus("WIN_EVIDENCE_FILE", "evidence"),
            bg=BG_DARK,
            fg=TEXT_MAIN,
            activebackground=ACCENT,
            activeforeground=BG_DARK,
            relief="flat",
            padx=8,
            pady=3,
            font=FONT_BODY,
        ).pack(side="left")

        self._graph_status = tk.Label(parent, text="", fg=TEXT_MAIN, bg=CARD_BG, font=FONT_BODY)
        self._graph_status.pack(anchor="w", pady=(2, 2))
        self._graph_extra = tk.Label(parent, text="", fg=TEXT_MAIN, bg=CARD_BG, font=FONT_BODY, justify="left")
        self._graph_extra.pack(anchor="w", pady=(0, 6))

        self._graph_canvas = tk.Canvas(parent, bg=BG_DARK, highlightthickness=0)
        self._graph_canvas.pack(fill="both", expand=True)
        self._graph_canvas.bind("<Configure>", lambda _evt: self._draw_graph())

        self._graph_status_bar = tk.Label(parent, text="", fg=TEXT_MAIN, bg=CARD_BG, font=FONT_BODY)
        self._graph_status_bar.pack(anchor="w", pady=(6, 0))

    def _set_graph_focus(self, table: str, hint: str) -> None:
        if not self._graph_vars:
            return
        self._graph_vars["hint"].set(hint)
        self._graph_selected_table = table.upper()
        self._refresh_graph_view()

    def _apply_graph_hint(self) -> None:
        hint = self._graph_vars["hint"].get().strip()
        if not hint:
            return
        tables = self._graph_snapshot.get("tables", [])
        if not tables:
            return
        selected = None
        if live_view and hasattr(live_view, "select_table_from_hint"):
            selected = live_view.select_table_from_hint(tables, hint)
        if not selected:
            for name in tables:
                if hint.lower() == name.lower():
                    selected = name
                    break
        if not selected:
            for name in tables:
                if hint.lower() in name.lower():
                    selected = name
                    break
        if selected:
            self._graph_selected_table = selected
            self._refresh_graph_view()

    def _toggle_graph_auto(self) -> None:
        if not self._graph_vars.get("auto_refresh"):
            return
        if self._graph_vars["auto_refresh"].get():
            self._schedule_graph_refresh()
        else:
            self._cancel_graph_refresh()

    def _schedule_graph_refresh(self) -> None:
        self._cancel_graph_refresh()
        self._refresh_graph_view()
        seconds = max(1, int(self._graph_vars["refresh_seconds"].get()))
        self._graph_after_id = self.root.after(seconds * 1000, self._schedule_graph_refresh)

    def _cancel_graph_refresh(self) -> None:
        if self._graph_after_id:
            try:
                self.root.after_cancel(self._graph_after_id)
            except Exception:
                pass
        self._graph_after_id = None

    def _fetch_table_row_counts(self, conn, database: str, tables: List[str]) -> Dict[str, int]:
        if not tables:
            return {}
        placeholders = ", ".join(["%s"] * len(tables))
        sql = f"""
        SELECT table_name, table_rows
        FROM information_schema.tables
        WHERE table_schema = %s AND table_name IN ({placeholders})
        """
        params = [database] + tables
        counts: Dict[str, int] = {}
        with conn.cursor() as cur:
            cur.execute(sql, params)
            for name, rows in cur.fetchall():
                counts[str(name)] = int(rows or 0)
        return counts

    def _refresh_graph_view(self) -> None:
        if live_view is None:
            self._graph_status.config(text=f"Live view unavailable: {LIVE_VIEW_IMPORT_ERROR}")
            return
        g = self.config.globals
        cfg = live_view.MysqlConfig(
            host=g.mysql_host,
            port=g.mysql_port,
            user=g.mysql_user,
            password=g.mysql_password or "",
            database=g.mysql_database,
        )
        try:
            conn = live_view.connect_mysql(cfg)
        except Exception as exc:
            self._graph_status.config(text=f"DB error: {exc}")
            return

        try:
            tables = live_view.fetch_tables(conn, cfg.database)
            table_map = {name.upper(): name for name in tables}
            layout = self._graph_layout()
            layout_tables = list(layout.keys())
            present = [t for t in layout_tables if t in table_map]
            extra = [t for t in table_map if t not in layout]
            counts = self._fetch_table_row_counts(conn, cfg.database, [table_map[t] for t in present])
            fks = live_view.fetch_foreign_keys(conn, cfg.database)
            filtered_fks = []
            for table, column, ref_table, ref_column in fks:
                if table.upper() in layout_tables and ref_table.upper() in layout_tables:
                    filtered_fks.append((table.upper(), column, ref_table.upper(), ref_column))

            counts_upper: Dict[str, int] = {}
            for table in layout_tables:
                actual = table_map.get(table)
                counts_upper[table] = counts.get(actual, 0) if actual else 0

            self._graph_snapshot = {
                "tables": layout_tables,
                "present": set(present),
                "table_map": table_map,
                "counts": counts_upper,
                "fks": filtered_fks,
                "extra": extra,
            }
            self._graph_preview_cache = {}
            if not self._graph_selected_table or self._graph_selected_table not in layout_tables:
                hint = self._graph_vars["hint"].get().strip()
                candidate = None
                if hint and live_view and hasattr(live_view, "select_table_from_hint"):
                    candidate = live_view.select_table_from_hint(present, hint)
                    if not candidate:
                        candidate = live_view.select_table_from_hint(layout_tables, hint)
                if not candidate:
                    candidate = "EVENTI_RAW" if "EVENTI_RAW" in present else None
                if not candidate and present:
                    candidate = present[0]
                if not candidate and layout_tables:
                    candidate = layout_tables[0]
                self._graph_selected_table = candidate

            self._update_graph_info(conn)
            self._draw_graph()
            stamp = datetime.utcnow().strftime("%H:%M:%S")
            self._graph_status.config(text=f"Live @ {stamp} UTC | {len(table_map)} tables")
            extra_preview = ", ".join(sorted(extra)[:6])
            if extra_preview:
                suffix = "..." if len(extra) > 6 else ""
                self._graph_extra.config(text=f"Other tables: {extra_preview}{suffix}")
            else:
                self._graph_extra.config(text="")
        finally:
            conn.close()

    def _update_graph_info(self, conn) -> None:
        snapshot = self._graph_snapshot
        table = self._graph_selected_table
        if not table or "table_map" not in snapshot:
            self._graph_status_bar.config(text="Select a table")
            return
        table_map = snapshot["table_map"]
        actual = table_map.get(table)
        count = snapshot.get("counts", {}).get(table, 0)
        if not actual:
            self._graph_status_bar.config(text=f"Selected: {table} (missing)")
            return

        role = self._graph_table_role(table)
        self._graph_status_bar.config(text=f"Selected: {table} | Rows: {count} | Role: {role}")

    def _graph_layout(self) -> Dict[str, Tuple[float, float, float, float]]:
        # Relative positions (x, y, w, h) for the core M1 Windows schema.
        return {
            "DEVICE_MASTER": (0.05, 0.08, 0.22, 0.12),
            "ACCOUNT_MASTER": (0.30, 0.08, 0.22, 0.12),
            "SCHEMA_VERSION": (0.55, 0.08, 0.22, 0.12),
            "WIN_LOG_ACQUISITION": (0.18, 0.28, 0.30, 0.12),
            "WIN_EVIDENCE_FILE": (0.52, 0.28, 0.26, 0.12),
            "WIN_EVENT_CORE": (0.30, 0.48, 0.36, 0.14),
            "WIN_EVENT_TEXT": (0.30, 0.70, 0.36, 0.12),
            "WIN_LOG_CHANNEL": (0.05, 0.48, 0.20, 0.10),
            "WIN_EVENT_PROVIDER": (0.05, 0.60, 0.20, 0.10),
            "WIN_IP_ADDR": (0.05, 0.72, 0.20, 0.10),
            "EVENTI_RAW": (0.70, 0.62, 0.24, 0.12),
        }

    def _draw_graph(self) -> None:
        if not hasattr(self, "_graph_canvas"):
            return
        canvas = self._graph_canvas
        canvas.delete("all")
        snapshot = self._graph_snapshot or {}
        tables: List[str] = snapshot.get("tables", [])
        counts: Dict[str, int] = snapshot.get("counts", {})
        fks: List[Tuple[str, str, str, str]] = snapshot.get("fks", [])
        present_set = snapshot.get("present", set())
        layout = self._graph_layout()
        width = max(1, canvas.winfo_width())
        height = max(1, canvas.winfo_height())
        pad = 14
        avail_w = max(1, width - pad * 2)
        avail_h = max(1, height - pad * 2)

        positions: Dict[str, Tuple[int, int, int, int]] = {}
        for table in tables:
            if table not in layout:
                continue
            x, y, w, h = layout[table]
            x0 = int(pad + avail_w * x)
            y0 = int(pad + avail_h * y)
            x1 = int(pad + avail_w * (x + w))
            y1 = int(pad + avail_h * (y + h))
            positions[table] = (x0, y0, x1, y1)

        # Draw edges
        for table, _col, ref_table, _ref_col in fks:
            if table not in positions or ref_table not in positions:
                continue
            x0, y0, x1, y1 = positions[table]
            rx0, ry0, rx1, ry1 = positions[ref_table]
            sx, sy = (x0 + x1) // 2, (y0 + y1) // 2
            tx, ty = (rx0 + rx1) // 2, (ry0 + ry1) // 2
            canvas.create_line(sx, sy, tx, ty, fill="#2b3a46", width=2, arrow="last", smooth=True)

        # Draw nodes
        for table, (x0, y0, x1, y1) in positions.items():
            count = counts.get(table, 0)
            selected = table == self._graph_selected_table
            missing = table not in present_set
            fill = "#0f1a24" if missing else ("#162430" if count == 0 else "#1d2f3d")
            outline = ACCENT if selected else ("#3a4b5c" if missing else "#233445")
            rect_kwargs = {"dash": (4, 2)} if missing else {}
            shadow = "#0a1118"
            canvas.create_rectangle(
                x0 + 3,
                y0 + 3,
                x1 + 3,
                y1 + 3,
                fill=shadow,
                outline="",
            )
            canvas.create_rectangle(
                x0,
                y0,
                x1,
                y1,
                fill=fill,
                outline=outline,
                width=2,
                tags=(table,),
                **rect_kwargs,
            )
            label = f"{table}\nmissing" if missing else f"{table}\n{count} rows"
            canvas.create_text((x0 + x1) // 2, (y0 + y1) // 2, text=label, fill=TEXT_MAIN,
                               font=FONT_BODY, tags=(table,))
            canvas.tag_bind(table, "<Button-1>", lambda _evt, t=table: self._select_graph_table(t))
            canvas.tag_bind(table, "<Enter>", lambda evt, t=table: self._on_graph_hover(t, evt))
            canvas.tag_bind(table, "<Leave>", lambda _evt: self._on_graph_leave())
            canvas.tag_bind(table, "<Motion>", lambda evt, t=table: self._on_graph_motion(t, evt))

    def _select_graph_table(self, table: str) -> None:
        self._graph_selected_table = table
        if self._graph_vars:
            self._graph_vars["hint"].set(table)
        self._refresh_graph_view()

    def _graph_table_role(self, table: str) -> str:
        if live_view and hasattr(live_view, "TABLE_EXPLANATIONS"):
            return live_view.TABLE_EXPLANATIONS.get(table, "No description.")
        return "No description."

    def _on_graph_hover(self, table: str, event) -> None:
        self._graph_hover_table = table
        if self._graph_hover_after:
            try:
                self.root.after_cancel(self._graph_hover_after)
            except Exception:
                pass
        self._graph_hover_after = self.root.after(200, lambda: self._show_graph_tooltip(table, event))

    def _on_graph_leave(self) -> None:
        if self._graph_hover_after:
            try:
                self.root.after_cancel(self._graph_hover_after)
            except Exception:
                pass
            self._graph_hover_after = None
        self._hide_graph_tooltip()

    def _on_graph_motion(self, table: str, event) -> None:
        if self._graph_tooltip and self._graph_hover_table == table:
            self._position_graph_tooltip(event)

    def _position_graph_tooltip(self, event) -> None:
        if not self._graph_tooltip:
            return
        x = event.widget.winfo_rootx() + event.x + 12
        y = event.widget.winfo_rooty() + event.y + 12
        self._graph_tooltip.geometry(f"+{x}+{y}")

    def _show_graph_tooltip(self, table: str, event) -> None:
        text = self._build_graph_tooltip_text(table)
        if not text:
            return
        if not self._graph_tooltip or not self._graph_tooltip.winfo_exists():
            tip = tk.Toplevel(self.root)
            tip.wm_overrideredirect(True)
            tip.configure(bg=BG_DARK)
            label = tk.Label(
                tip,
                text=text,
                justify="left",
                fg=TEXT_MAIN,
                bg=BG_DARK,
                font=FONT_MONO,
                padx=8,
                pady=6,
            )
            label.pack()
            self._graph_tooltip = tip
            self._graph_tooltip_label = label
        else:
            self._graph_tooltip_label.config(text=text)
        self._position_graph_tooltip(event)
        self._graph_tooltip.deiconify()

    def _hide_graph_tooltip(self) -> None:
        if self._graph_tooltip and self._graph_tooltip.winfo_exists():
            self._graph_tooltip.withdraw()

    def _build_graph_tooltip_text(self, table: str) -> str:
        snapshot = self._graph_snapshot or {}
        counts = snapshot.get("counts", {})
        count = counts.get(table, 0)
        role = self._graph_table_role(table)
        lines = [f"{table}", f"Rows: {count}", f"Role: {role}"]
        preview = self._get_table_preview(table)
        if preview:
            lines.append("Last rows:")
            lines.extend(preview)
        else:
            lines.append("Last rows: n/a")
        return "\n".join(lines)

    def _get_table_preview(self, table: str) -> List[str]:
        now = time.time()
        cached = self._graph_preview_cache.get(table)
        if cached and now - cached[0] < 10:
            return cached[1]
        if live_view is None:
            return []
        snapshot = self._graph_snapshot or {}
        table_map = snapshot.get("table_map", {})
        actual = table_map.get(table)
        if not actual:
            return []

        g = self.config.globals
        cfg = live_view.MysqlConfig(
            host=g.mysql_host,
            port=g.mysql_port,
            user=g.mysql_user,
            password=g.mysql_password or "",
            database=g.mysql_database,
        )
        try:
            conn = live_view.connect_mysql(cfg)
        except Exception:
            return []

        try:
            columns = live_view.fetch_columns(conn, cfg.database, actual)
            col_names = [c[0] for c in columns]
            if not col_names:
                return []
            order_column = live_view.pick_order_column(col_names)
            tail_columns = live_view.pick_tail_columns(table, col_names, None)
            rows = live_view.fetch_tail_rows(
                conn,
                actual,
                tail_columns,
                order_column,
                int(self._graph_vars["tail_count"].get()),
            )
        except Exception:
            return []
        finally:
            conn.close()

        lines: List[str] = []
        for row in rows:
            parts = []
            for col in tail_columns:
                parts.append(f"{col}={live_view.format_value(row.get(col), 60)}")
            lines.append("- " + ", ".join(parts))
        self._graph_preview_cache[table] = (now, lines)
        return lines

    def _open_live_db_view(self) -> None:
        if live_view is None:
            messagebox.showerror(
                "Live DB View",
                f"Cannot load mysql_live_schema_view.py: {LIVE_VIEW_IMPORT_ERROR}",
            )
            return
        if self._live_win and self._live_win.winfo_exists():
            self._live_win.lift()
            return

        win = tk.Toplevel(self.root)
        win.title("Live DB View")
        win.geometry("980x720")
        win.configure(bg=BG_BASE)
        win.protocol("WM_DELETE_WINDOW", self._close_live_db_view)
        self._live_win = win

        self._live_vars = {
            "table_prefix": tk.StringVar(value=""),
            "table_contains": tk.StringVar(value=""),
            "hint": tk.StringVar(value=""),
            "tail_table": tk.StringVar(value="EVENTI_RAW"),
            "tail_columns": tk.StringVar(value=""),
            "tail_count": tk.IntVar(value=7),
            "preview_chars": tk.IntVar(value=200),
            "refresh_seconds": tk.IntVar(value=5),
            "auto_refresh": tk.BooleanVar(value=False),
            "smart_mode": tk.BooleanVar(value=True),
        }

        header = tk.Frame(win, bg=BG_BASE, pady=6)
        header.pack(fill="x")
        tk.Label(header, text="Live DB View", fg=TEXT_MAIN, bg=BG_BASE, font=FONT_SECTION).pack(side="left")

        form = tk.Frame(win, bg=BG_BASE, padx=12, pady=6)
        form.pack(fill="x")

        row1 = tk.Frame(form, bg=BG_BASE)
        row1.pack(fill="x", pady=2)
        tk.Label(row1, text="Table prefix", fg=TEXT_MAIN, bg=BG_BASE, font=FONT_BODY).pack(side="left")
        tk.Entry(row1, textvariable=self._live_vars["table_prefix"], width=12,
                 bg=CARD_BG, fg=TEXT_MAIN, insertbackground=TEXT_MAIN).pack(side="left", padx=(6, 10))
        tk.Label(row1, text="Contains", fg=TEXT_MAIN, bg=BG_BASE, font=FONT_BODY).pack(side="left")
        tk.Entry(row1, textvariable=self._live_vars["table_contains"], width=18,
                 bg=CARD_BG, fg=TEXT_MAIN, insertbackground=TEXT_MAIN).pack(side="left", padx=(6, 10))
        tk.Label(row1, text="Hint", fg=TEXT_MAIN, bg=BG_BASE, font=FONT_BODY).pack(side="left")
        tk.Entry(row1, textvariable=self._live_vars["hint"], width=12,
                 bg=CARD_BG, fg=TEXT_MAIN, insertbackground=TEXT_MAIN).pack(side="left", padx=(6, 10))
        tk.Label(row1, text="Tail table", fg=TEXT_MAIN, bg=BG_BASE, font=FONT_BODY).pack(side="left")
        tk.Entry(row1, textvariable=self._live_vars["tail_table"], width=18,
                 bg=CARD_BG, fg=TEXT_MAIN, insertbackground=TEXT_MAIN).pack(side="left", padx=(6, 0))

        row2 = tk.Frame(form, bg=BG_BASE)
        row2.pack(fill="x", pady=2)
        tk.Label(row2, text="Tail columns", fg=TEXT_MAIN, bg=BG_BASE, font=FONT_BODY).pack(side="left")
        tk.Entry(row2, textvariable=self._live_vars["tail_columns"], width=34,
                 bg=CARD_BG, fg=TEXT_MAIN, insertbackground=TEXT_MAIN).pack(side="left", padx=(6, 10))
        tk.Label(row2, text="Tail count", fg=TEXT_MAIN, bg=BG_BASE, font=FONT_BODY).pack(side="left")
        tk.Spinbox(row2, from_=1, to=50, textvariable=self._live_vars["tail_count"], width=5,
                   bg=CARD_BG, fg=TEXT_MAIN, insertbackground=TEXT_MAIN).pack(side="left", padx=(6, 10))
        tk.Label(row2, text="Preview chars", fg=TEXT_MAIN, bg=BG_BASE, font=FONT_BODY).pack(side="left")
        tk.Spinbox(row2, from_=40, to=2000, textvariable=self._live_vars["preview_chars"], width=6,
                   bg=CARD_BG, fg=TEXT_MAIN, insertbackground=TEXT_MAIN).pack(side="left", padx=(6, 0))

        row3 = tk.Frame(form, bg=BG_BASE)
        row3.pack(fill="x", pady=4)
        tk.Label(row3, text="Refresh (s)", fg=TEXT_MAIN, bg=BG_BASE, font=FONT_BODY).pack(side="left")
        tk.Spinbox(row3, from_=1, to=60, textvariable=self._live_vars["refresh_seconds"], width=5,
                   bg=CARD_BG, fg=TEXT_MAIN, insertbackground=TEXT_MAIN).pack(side="left", padx=(6, 10))
        tk.Checkbutton(row3, text="Smart mode", variable=self._live_vars["smart_mode"],
                       bg=BG_BASE, fg=TEXT_MAIN, selectcolor=BG_BASE,
                       activebackground=BG_BASE, font=FONT_BODY).pack(side="left", padx=(0, 10))
        tk.Checkbutton(row3, text="Auto refresh", variable=self._live_vars["auto_refresh"],
                       command=self._toggle_live_db_auto, bg=BG_BASE, fg=TEXT_MAIN,
                       selectcolor=BG_BASE, activebackground=BG_BASE,
                       font=FONT_BODY).pack(side="left", padx=(0, 10))
        tk.Button(row3, text="Refresh", command=self._refresh_live_db_view, bg=TEXT_MAIN, fg=BG_DARK,
                  activebackground=ACCENT, activeforeground=BG_DARK, relief="flat", padx=10, pady=4,
                  font=FONT_BODY).pack(side="left")
        tk.Button(row3, text="Select All", command=self._select_live_output, bg=BG_DARK, fg=TEXT_MAIN,
                  activebackground=ACCENT, activeforeground=BG_DARK, relief="flat", padx=10, pady=4,
                  font=FONT_BODY).pack(side="left", padx=(6, 0))

        row4 = tk.Frame(form, bg=BG_BASE)
        row4.pack(fill="x", pady=4)
        tk.Label(row4, text="Quick", fg=TEXT_MAIN, bg=BG_BASE, font=FONT_BODY).pack(side="left")
        tk.Button(row4, text="Raw (last 7)", command=lambda: self._apply_live_preset("raw"),
                  bg=BG_DARK, fg=TEXT_MAIN, activebackground=ACCENT, activeforeground=BG_DARK,
                  relief="flat", padx=8, pady=4, font=FONT_BODY).pack(side="left", padx=(6, 6))
        tk.Button(row4, text="Win Core", command=lambda: self._apply_live_preset("win_core"),
                  bg=BG_DARK, fg=TEXT_MAIN, activebackground=ACCENT, activeforeground=BG_DARK,
                  relief="flat", padx=8, pady=4, font=FONT_BODY).pack(side="left", padx=(0, 6))
        tk.Button(row4, text="Win Tables", command=lambda: self._apply_live_preset("win_tables"),
                  bg=BG_DARK, fg=TEXT_MAIN, activebackground=ACCENT, activeforeground=BG_DARK,
                  relief="flat", padx=8, pady=4, font=FONT_BODY).pack(side="left", padx=(0, 6))

        output_frame = tk.Frame(win, bg=BG_BASE, padx=12, pady=8)
        output_frame.pack(fill="both", expand=True)
        self._live_output = tk.Text(output_frame, bg=BG_DARK, fg=TEXT_MAIN,
                                    insertbackground=TEXT_MAIN, font=FONT_MONO,
                                    height=18, wrap="word")
        scroll = tk.Scrollbar(output_frame, command=self._live_output.yview)
        self._live_output.configure(yscrollcommand=scroll.set)
        self._live_output.pack(side="left", fill="both", expand=True)
        scroll.pack(side="right", fill="y")

        self._refresh_live_db_view()

    def _select_live_output(self) -> None:
        if self._live_output:
            self._select_all_text(self._live_output)

    def _toggle_live_db_auto(self) -> None:
        if not self._live_win or not self._live_win.winfo_exists():
            return
        auto = bool(self._live_vars.get("auto_refresh", tk.BooleanVar(value=False)).get())
        if auto:
            self._schedule_live_refresh()
        else:
            self._cancel_live_refresh()

    def _schedule_live_refresh(self) -> None:
        if not self._live_win or not self._live_win.winfo_exists():
            return
        self._cancel_live_refresh()
        self._refresh_live_db_view()
        seconds = int(self._live_vars.get("refresh_seconds", tk.IntVar(value=5)).get())
        seconds = max(1, seconds)
        self._live_after_id = self._live_win.after(seconds * 1000, self._schedule_live_refresh)

    def _cancel_live_refresh(self) -> None:
        if self._live_win and self._live_after_id:
            try:
                self._live_win.after_cancel(self._live_after_id)
            except Exception:
                pass
        self._live_after_id = None

    def _close_live_db_view(self) -> None:
        self._cancel_live_refresh()
        if self._live_win and self._live_win.winfo_exists():
            self._live_win.destroy()
        self._live_win = None

    def _apply_live_preset(self, preset: str) -> None:
        if not self._live_vars:
            return
        if preset == "raw":
            self._live_vars["table_prefix"].set("")
            self._live_vars["table_contains"].set("")
            self._live_vars["hint"].set("raw")
            self._live_vars["tail_table"].set("EVENTI_RAW")
            self._live_vars["tail_columns"].set("")
            self._live_vars["tail_count"].set(7)
            self._live_vars["smart_mode"].set(True)
        elif preset == "win_core":
            self._live_vars["table_prefix"].set("WIN_")
            self._live_vars["table_contains"].set("")
            self._live_vars["hint"].set("core")
            self._live_vars["tail_table"].set("WIN_EVENT_CORE")
            self._live_vars["tail_columns"].set("")
            self._live_vars["tail_count"].set(7)
            self._live_vars["smart_mode"].set(True)
        elif preset == "win_tables":
            self._live_vars["table_prefix"].set("WIN_")
            self._live_vars["table_contains"].set("")
            self._live_vars["hint"].set("")
            self._live_vars["tail_table"].set("")
            self._live_vars["tail_columns"].set("")
            self._live_vars["tail_count"].set(7)
            self._live_vars["smart_mode"].set(True)
        self._refresh_live_db_view()

    def _refresh_live_db_view(self) -> None:
        if not self._live_output:
            return
        g = self.config.globals
        cfg = live_view.MysqlConfig(
            host=g.mysql_host,
            port=g.mysql_port,
            user=g.mysql_user,
            password=g.mysql_password or "",
            database=g.mysql_database,
        )
        args = SimpleNamespace(
            table_prefix=self._live_vars["table_prefix"].get(),
            table_contains=self._live_vars["table_contains"].get(),
            hint=self._live_vars["hint"].get(),
            tail_table=self._live_vars["tail_table"].get(),
            tail_columns=self._live_vars["tail_columns"].get(),
            tail_count=self._live_vars["tail_count"].get(),
            raw_preview_chars=self._live_vars["preview_chars"].get(),
            smart_mode=self._live_vars["smart_mode"].get(),
        )
        try:
            text = live_view.build_view_text(cfg, args)
        except BaseException as exc:
            text = f"Error: {exc}"
        self._live_output.delete("1.0", tk.END)
        self._live_output.insert("1.0", text)

    def _rebuild_steps(self) -> None:
        for item in self.steps_tree.get_children():
            self.steps_tree.delete(item)
        self._step_map.clear()

        ms = self._current_milestone
        if not ms:
            self.policy_label.config(text="")
            self.milestone_info.config(text="")
            self.step_hint.config(text="")
            self.run_btn.config(state="disabled")
            return

        op_filter = self.op_filter.get() if self.op_filter else OP_ALL
        for step in ms.steps:
            op = self._get_step_operation(step)
            if op_filter != OP_ALL and op != op_filter:
                continue
            status = self._step_status(ms, step, op)
            last_run = self._format_last_run(self._get_last_run(ms, step))
            item = self.steps_tree.insert("", tk.END, values=(op, step.name, status, last_run))
            self._step_map[item] = (step, op)

        self._update_milestone_info(ms)
        self._update_policy_label(ms)

        children = self.steps_tree.get_children()
        if children:
            self.steps_tree.selection_set(children[0])
            self.steps_tree.focus(children[0])
            self.steps_tree.see(children[0])
        self._update_run_state()

    def _update_policy_label(self, ms: Milestone) -> None:
        expected = {OP_INSERT, OP_VALIDATE, OP_SHOW} if ms.external_collect else set(OP_DISPLAY)
        present = []
        unset_count = 0
        for step in ms.steps:
            op = self._get_step_operation(step)
            if op == OP_UNKNOWN:
                unset_count += 1
            elif op not in present:
                present.append(op)

        ordered_present = [op for op in OP_DISPLAY if op in present]
        missing = [op for op in OP_DISPLAY if op in expected and op not in present]
        extra = [op for op in present if op not in expected]
        policy = "External collect (INSERT + VALIDATE + SHOW only)" if ms.external_collect else "Standard (INIT + DUMP + INSERT + VALIDATE + SHOW)"
        text = f"Policy: {policy}. Present: {', '.join(ordered_present) or 'none'}."
        if missing:
            text += f" Missing: {', '.join(missing)}."
        if extra:
            text += f" Extra: {', '.join(extra)}."
        if unset_count:
            text += f" Unset: {unset_count}."
        text += " INIT runs once per milestone (tracked in forensic_state.json)."
        self.policy_label.config(text=text)

    def _update_milestone_info(self, ms: Milestone) -> None:
        dataset = ms.folder or "<not set>"
        source = ms.source_root or "<not set>"
        last_init = self.state.init_milestones.get(ms.name, "never")
        last_run = self._latest_run_for_milestone(ms) or "never"
        text = f"Dataset: {dataset}\nSource: {source}\nLast run: {last_run}\nInit: {last_init}"
        self.milestone_info.config(text=text)

    def _get_step_operation(self, step: Step) -> str:
        explicit = normalize_operation(step.operation)
        return explicit if explicit else infer_operation(step)

    def _step_status(self, ms: Milestone, step: Step, op: str) -> str:
        if op == OP_INIT and self._init_locked(ms, step):
            return "DONE"
        if ms.external_collect and op in (OP_INIT, OP_DUMP):
            return "BLOCKED"
        if op == OP_UNKNOWN:
            return "UNSET"
        if self._get_last_run(ms, step):
            return "DONE"
        return ""

    def _on_step_selected(self, event=None) -> None:
        self._update_run_state()

    def _update_run_state(self) -> None:
        ms = self._current_milestone
        if not ms:
            self.run_btn.config(state="disabled")
            self.step_hint.config(text="")
            return

        item = self.steps_tree.selection()
        if not item:
            self.run_btn.config(state="disabled")
            self.step_hint.config(text="")
            return

        step, op = self._step_map.get(item[0], (None, None))
        if not step or not op:
            self.run_btn.config(state="disabled")
            self.step_hint.config(text="")
            return

        allowed, hint = self._can_run_step(ms, step, op)
        self.run_btn.config(state="normal" if allowed else "disabled")
        last_run = self._get_last_run(ms, step) or "never"
        dependency = self._dependency_hint(ms, op)
        script = step.script_path or "<not set>"
        desc = step.description or "-"
        details = [
            f"Selected: {step.name} ({op})",
            f"Script: {script}",
            f"Description: {desc}",
            f"{dependency}",
            f"Last run: {last_run}",
        ]
        if hint:
            details.append(f"Note: {hint}")
        self.step_hint.config(text="\n".join(details))

    def _can_run_step(self, ms: Milestone, step: Step, op: str) -> Tuple[bool, str]:
        script = step.script_path or ""
        if not script or script == "<not set>" or script.lower() == "pending":
            return False, "No script set for this step."
        if ms.external_collect and op in (OP_INIT, OP_DUMP):
            return False, "External collect milestones allow only INSERT, VALIDATE, and SHOW."
        if op == OP_INIT and self._init_locked(ms, step):
            return False, "INIT already completed (locked)."
        if op == OP_UNKNOWN:
            return True, "Operation UNSET; consider setting operation in config."
        return True, ""

    def _refresh(self) -> None:
        try:
            self.config = ForensicConfig.load()
            self.state = ForensicState.load()
            self._populate_globals()
            self._populate_milestones()
            messagebox.showinfo("Refresh", "Configuration reloaded.")
        except Exception as exc:
            messagebox.showerror("Error", f"Could not reload config:\n{exc}")

    def _append_output(self, text: str) -> None:
        self.output.insert("end", text + "\n")
        self.output.see("end")
        self.output.update_idletasks()

    def _clear_output(self) -> None:
        self.output.delete("1.0", "end")

    def _init_locked(self, ms: Milestone, step: Step) -> bool:
        if ms.name in self.state.init_milestones:
            return True
        ms_runs = self.state.init_runs.get(ms.name, {})
        return bool(ms_runs)

    def _mark_init_done(self, ms: Milestone, step: Step) -> None:
        ts = datetime.utcnow().isoformat(timespec="seconds") + "Z"
        self.state.init_milestones[ms.name] = ts
        ms_runs = self.state.init_runs.setdefault(ms.name, {})
        ms_runs[step_key(step)] = ts
        self.state.save()

    def _mark_step_run(self, ms: Milestone, step: Step) -> None:
        ts = datetime.utcnow().isoformat(timespec="seconds") + "Z"
        ms_runs = self.state.last_runs.setdefault(ms.name, {})
        ms_runs[step_key(step)] = ts
        self.state.save()

    def _get_last_run(self, ms: Milestone, step: Step) -> Optional[str]:
        return self.state.last_runs.get(ms.name, {}).get(step_key(step))

    def _latest_run_for_milestone(self, ms: Milestone) -> Optional[str]:
        runs = self.state.last_runs.get(ms.name, {})
        if not runs:
            return None
        return max(runs.values())

    def _format_last_run(self, ts: Optional[str]) -> str:
        if not ts:
            return "-"
        return ts.replace("T", " ").replace("Z", "")

    def _dependency_hint(self, ms: Milestone, op: str) -> str:
        order = [OP_INIT, OP_DUMP, OP_INSERT, OP_VALIDATE, OP_SHOW]
        if op not in order:
            return "Depends on: <unset>"
        idx = order.index(op)
        required = order[:idx]
        if not required:
            return "Depends on: none"
        present_ops = {self._get_step_operation(step) for step in ms.steps}
        missing = [req for req in required if req not in present_ops]
        text = "Depends on: " + " -> ".join(required)
        if missing:
            text += f" (missing: {', '.join(missing)})"
        return text

    def _run_selected_step(self) -> None:
        ms_name = None
        sel = self.milestone_list.curselection()
        if sel:
            ms_name = self.milestone_list.get(sel[0])
        if not ms_name:
            messagebox.showwarning("No milestone", "Select a milestone first.")
            return

        ms = self.config.milestones.get(ms_name)
        if not ms:
            messagebox.showerror("Missing milestone", f"Milestone not found: {ms_name}")
            return

        item = self.steps_tree.selection()
        if not item:
            messagebox.showwarning("No step", "Select a step first.")
            return

        step_entry = self._step_map.get(item[0])
        if not step_entry:
            messagebox.showerror("Missing step", "Could not resolve selected step.")
            return
        step, op = step_entry
        step_name = step.name
        desc = step.description
        script = step.script_path or "<not set>"
        if not script or script == "<not set>" or script.lower() == "pending":
            messagebox.showwarning("No script", "This step has no script_path set.")
            return
        if ms.external_collect and op in (OP_INIT, OP_DUMP):
            messagebox.showwarning(
                "Blocked",
                "External collect milestones allow only INSERT, VALIDATE, and SHOW steps.",
            )
            return
        if op == OP_INIT and self._init_locked(ms, step):
            messagebox.showwarning("Blocked", "INIT already completed for this step.")
            return

        self._append_output(f"\n=== RUN: {ms_name} :: {step_name} ===")
        self._append_output(f"{desc}")
        self._append_output(f"Operation: {op}")
        self._append_output(f"Script: {script}")

        g = self.config.globals
        ws = g.workspace_folder
        resolved = resolve_script_path(ws, script)

        if not resolved.exists():
            self._append_output(f"ERROR: script not found at: {resolved}")
            messagebox.showerror("Missing script", f"Script not found:\n{resolved}")
            return

        ext = resolved.suffix.lower()
        if ext == ".sql":
            rc, out = self._run_sql(resolved)
        elif ext == ".py":
            extra_args = self._python_extra_args(ms, resolved)
            if extra_args is None:
                self._append_output("Canceled by user.")
                return
            rc, out = self._run_python(resolved, extra_args=extra_args)
        else:
            rc, out = 1, f"Unsupported script type: {ext}"

        self._append_output(out)
        self._append_output(f"=== EXIT CODE: {rc} ===")

        if rc == 0:
            self._mark_step_run(ms, step)
            if op == OP_INIT:
                self._mark_init_done(ms, step)
            self._rebuild_steps()

        if rc != 0:
            messagebox.showerror("Step failed", f"{ms_name} :: {step_name} failed.\nExit code: {rc}")
        else:
            messagebox.showinfo("Step complete", f"{ms_name} :: {step_name} completed OK.")

    def _mysql_base_cmd(self) -> List[str]:
        g = self.config.globals
        mysql = g.mysql_cli or "mysql"
        cmd = [
            mysql,
            "-h", g.mysql_host,
            "-P", str(g.mysql_port),
            "-u", g.mysql_user,
        ]
        if g.mysql_password:
            # safer than prompting for UI-run flows; user can blank it to get prompt
            cmd.append(f"-p{g.mysql_password}")
        else:
            cmd.append("-p")
        return cmd

    def _mysql_query(self, query: str) -> Tuple[int, str]:
        g = self.config.globals
        if not g.mysql_password:
            return 1, "MySQL password not set. Add it in Settings to run DB overview."
        cmd = self._mysql_base_cmd() + ["-N", "-B", g.mysql_database, "-e", query]
        return run_subprocess(cmd)

    def _mysql_exec(self, query: str) -> Tuple[int, str]:
        g = self.config.globals
        if not g.mysql_password:
            return 1, "MySQL password not set. Add it in Settings to run DB reset."
        cmd = self._mysql_base_cmd() + [g.mysql_database, "-e", query]
        return run_subprocess(cmd)

    def _run_quick_query(self) -> None:
        query = self.quick_query.get().strip() if hasattr(self, "quick_query") else ""
        if not query:
            messagebox.showinfo("Query", "Enter a SELECT query first.")
            return
        if not query.lower().lstrip().startswith("select"):
            messagebox.showwarning("Query", "Only SELECT queries are allowed.")
            return

        if live_view is None:
            rc, out = self._mysql_query(query)
            if rc != 0:
                messagebox.showerror("Query failed", out)
                return
            self._append_output(f"\n=== QUERY ===\n{query}\n{out}")
            return

        g = self.config.globals
        cfg = live_view.MysqlConfig(
            host=g.mysql_host,
            port=g.mysql_port,
            user=g.mysql_user,
            password=g.mysql_password or "",
            database=g.mysql_database,
        )
        try:
            conn = live_view.connect_mysql(cfg)
        except Exception as exc:
            messagebox.showerror("Query failed", f"DB error: {exc}")
            return

        try:
            with conn.cursor() as cur:
                cur.execute(query)
                rows = cur.fetchall()
                columns = [d[0] for d in (cur.description or [])]
        finally:
            conn.close()

        max_rows = 50
        lines = [f"=== QUERY ===", query]
        if columns:
            lines.append("\t".join(columns))
        for row in rows[:max_rows]:
            lines.append("\t".join(str(val) for val in row))
        if len(rows) > max_rows:
            lines.append(f"... ({len(rows) - max_rows} more rows)")
        self._append_output("\n".join(lines))

    def _extract_tables_from_sql(self, sql_path: Path) -> List[str]:
        if not sql_path.exists():
            return []
        payload = sql_path.read_text(encoding="utf-8", errors="replace")
        matches = re.findall(r"CREATE\\s+TABLE\\s+(?:IF\\s+NOT\\s+EXISTS\\s+)?`?([A-Za-z0-9_]+)`?", payload, re.IGNORECASE)
        seen = []
        for name in matches:
            if name not in seen:
                seen.append(name)
        return seen

    def _expected_tables_for_milestone(self, ms: Milestone) -> List[str]:
        if ms.db_tables:
            return ms.db_tables
        for step in ms.steps:
            op = self._get_step_operation(step)
            if op != OP_INIT:
                continue
            script = step.script_path or ""
            if script.lower().endswith(".sql"):
                sql_path = resolve_script_path(self.config.globals.workspace_folder, script)
                tables = self._extract_tables_from_sql(sql_path)
                if tables:
                    return tables
        return []

    def _validate_tables_for_milestone(self) -> None:
        ms = self._current_milestone
        if not ms:
            messagebox.showwarning("Validate tables", "Select a milestone first.")
            return
        expected = self._expected_tables_for_milestone(ms)
        if not expected:
            messagebox.showwarning("Validate tables", "No expected tables found for this milestone.")
            return
        if live_view is None:
            messagebox.showerror("Validate tables", f"Live view unavailable: {LIVE_VIEW_IMPORT_ERROR}")
            return

        g = self.config.globals
        cfg = live_view.MysqlConfig(
            host=g.mysql_host,
            port=g.mysql_port,
            user=g.mysql_user,
            password=g.mysql_password or "",
            database=g.mysql_database,
        )
        try:
            conn = live_view.connect_mysql(cfg)
        except Exception as exc:
            messagebox.showerror("Validate tables", f"DB error: {exc}")
            return

        try:
            tables = live_view.fetch_tables(conn, cfg.database)
        finally:
            conn.close()

        present = {t.upper() for t in tables}
        missing = [t for t in expected if t.upper() not in present]
        status = "OK" if not missing else "MISSING"
        summary = f"Milestone: {ms.name}\nExpected: {len(expected)}\nMissing: {len(missing)}"
        if missing:
            summary += f"\nMissing tables: {', '.join(missing)}"
        self._append_output(f"\n=== TABLE VALIDATION ({status}) ===\n{summary}")
        if missing:
            messagebox.showwarning("Validate tables", summary)
        else:
            messagebox.showinfo("Validate tables", summary)

    def _safe_table_name(self, name: str) -> bool:
        if not name:
            return False
        return all(ch.isalnum() or ch == "_" for ch in name)

    def _safe_code(self, code: str) -> bool:
        if not code:
            return False
        return all(ch.isalnum() or ch in ("_", "-") for ch in code)

    def _eventi_raw_available(self) -> Tuple[bool, str]:
        rc, out = self._mysql_query("SHOW TABLES LIKE 'EVENTI_RAW';")
        if rc != 0:
            return False, out
        return bool(out.strip()), ""

    def _reset_milestone_db(self, ms: Milestone) -> Tuple[int, str]:
        if not ms.db_tables:
            return 1, "No db_tables configured for this milestone."
        invalid = [t for t in ms.db_tables if not self._safe_table_name(t)]
        if invalid:
            return 1, f"Invalid table names: {', '.join(invalid)}"

        statements = ["SET SQL_SAFE_UPDATES=0", "START TRANSACTION"]
        for table in ms.db_tables:
            statements.append(f"DELETE FROM `{table}`")

        raw_notes = ""
        if ms.raw_milestone_code:
            if not self._safe_code(ms.raw_milestone_code):
                return 1, "Invalid raw milestone code."
            raw_ok, raw_err = self._eventi_raw_available()
            if not raw_ok and raw_err:
                return 1, raw_err
            if raw_ok:
                statements.append(
                    f"DELETE FROM `EVENTI_RAW` WHERE milestone_code = '{ms.raw_milestone_code}'"
                )
            else:
                raw_notes = "EVENTI_RAW not found; raw mirror not cleared."
        statements.append("COMMIT")

        query = "; ".join(statements) + ";"
        rc, out = self._mysql_exec(query)
        if raw_notes:
            out = (out + "\n" if out else "") + raw_notes
        return rc, out

    def _build_db_overview(self) -> Tuple[int, str]:
        g = self.config.globals
        rc_tables, out_tables = self._mysql_query("SHOW TABLES;")
        if rc_tables != 0:
            return rc_tables, out_tables

        tables = [line.strip() for line in out_tables.splitlines() if line.strip()]

        fk_query = (
            "SELECT TABLE_NAME, COLUMN_NAME, REFERENCED_TABLE_NAME, REFERENCED_COLUMN_NAME "
            "FROM information_schema.KEY_COLUMN_USAGE "
            "WHERE TABLE_SCHEMA = DATABASE() AND REFERENCED_TABLE_NAME IS NOT NULL "
            "ORDER BY TABLE_NAME, COLUMN_NAME;"
        )
        rc_fks, out_fks = self._mysql_query(fk_query)
        if rc_fks != 0:
            return rc_fks, out_fks

        relationships = []
        for line in out_fks.splitlines():
            parts = [p.strip() for p in line.split("\t")]
            if len(parts) != 4:
                continue
            table_name, column_name, ref_table, ref_col = parts
            relationships.append((ref_table, ref_col, table_name, column_name))

        lines = []
        lines.append(f"Database: {g.mysql_database}")
        lines.append(f"Host: {g.mysql_host}:{g.mysql_port}  User: {g.mysql_user}")
        lines.append(f"Generated: {datetime.utcnow().isoformat(timespec='seconds')}Z")
        lines.append("")
        lines.append(f"Tables ({len(tables)}):")
        for t in tables:
            lines.append(f"- {t}")
        lines.append("")
        if relationships:
            lines.append("Relationships:")
            for ref_table, ref_col, table_name, column_name in relationships:
                lines.append(f"{ref_table}.{ref_col} -> {table_name}.{column_name}")
        else:
            lines.append("Relationships: none found.")

        return 0, "\n".join(lines)

    def _run_sql(self, sql_path: Path) -> Tuple[int, str]:
        g = self.config.globals
        cmd = self._mysql_base_cmd() + [g.mysql_database]
        # redirect input file by reading and piping via stdin
        payload = sql_path.read_text(encoding="utf-8", errors="replace")
        try:
            p = subprocess.run(
                cmd,
                input=payload,
                text=True,
                capture_output=True,
                encoding="utf-8",
                errors="replace",
            )
            out = (p.stdout or "") + ("\n" + p.stderr if p.stderr else "")
            header = f"[mysql] {shlex.join(cmd)} < {sql_path}"
            return p.returncode, header + "\n" + out.strip()
        except Exception as e:
            return 1, f"Exception running mysql: {e}"

    def _run_python(self, py_path: Path, extra_args: Optional[List[str]] = None) -> Tuple[int, str]:
        g = self.config.globals
        py = g.python_exe or sys.executable

        # Pass workspace + config path as env so scripts can read config consistently
        env = os.environ.copy()
        if g.workspace_folder:
            env["SAFENET_WORKSPACE"] = g.workspace_folder
        env["SAFENET_CONFIG"] = str(CONFIG_FILE)

        cmd = [py, str(py_path)]
        if extra_args:
            cmd.extend(extra_args)
        rc, out = run_subprocess(cmd, cwd=py_path.parent, env=env)
        header = f"[python] {shlex.join(cmd)}"
        return rc, header + "\n" + out

    def _python_extra_args(self, ms: Milestone, py_path: Path) -> Optional[List[str]]:
        script_name = py_path.name
        if script_name == "m02_windows_logs_03_probe_load_to_EVENTI_PC.py":
            return self._prompt_m02_windows_loader_args(ms)
        if script_name == "m02_windows_logs_01_log_dump.py":
            return self._prompt_m02_windows_dump_args(ms)
        return []

    def _prompt_m02_windows_loader_args(self, ms: Milestone) -> Optional[List[str]]:
        g = self.config.globals
        dataset_root = ms.folder
        if not dataset_root and g.workspace_folder:
            dataset_root = str(Path(g.workspace_folder) / "DataSetGlobal" / "windows_logs")

        if not dataset_root or not Path(dataset_root).is_dir():
            dataset_root = simpledialog.askstring(
                "Dataset root",
                "Dataset root (DataSetGlobal/windows_logs):",
                initialvalue=dataset_root or "",
                parent=self.root,
            )
            if not dataset_root:
                return None

        source_log = simpledialog.askstring(
            "Source log",
            "Source log (Security/System/Application/PowerShell/AMSI):",
            initialvalue="Security",
            parent=self.root,
        )
        if not source_log:
            return None

        limit_str = simpledialog.askstring(
            "Limit per run",
            "Limit per run (default 100):",
            initialvalue="100",
            parent=self.root,
        )
        try:
            limit_val = int(limit_str) if limit_str else 100
        except ValueError:
            limit_val = 100

        dry_run = messagebox.askyesno(
            "Dry run",
            "Run in dry-run mode (no DB writes)?",
            parent=self.root,
        )

        args: List[str] = [
            "--dataset-root", dataset_root,
            "--mysql-host", g.mysql_host,
            "--mysql-port", str(g.mysql_port),
            "--mysql-user", g.mysql_user,
            "--mysql-database", g.mysql_database,
            "--source-log", source_log,
            "--limit-per-run", str(limit_val),
        ]
        if g.mysql_password:
            args.extend(["--mysql-password", g.mysql_password])
        if dry_run:
            args.append("--dry-run")
        return args

    def _prompt_m02_windows_dump_args(self, ms: Milestone) -> Optional[List[str]]:
        g = self.config.globals
        log_dir = ms.source_root or ""
        if not log_dir and g.workspace_folder:
            log_dir = str(Path(g.workspace_folder) / "DataSetGlobal" / "windows_logs")

        log_dir = simpledialog.askstring(
            "Log directory",
            "Log directory (EVTX/CSV root):",
            initialvalue=log_dir,
            parent=self.root,
        )
        if not log_dir:
            return None

        from_date = simpledialog.askstring(
            "From date",
            "From date (YYYY-MM-DD or ISO, optional):",
            initialvalue="",
            parent=self.root,
        )
        if from_date is None:
            return None

        to_date = simpledialog.askstring(
            "To date",
            "To date (YYYY-MM-DD or ISO, optional):",
            initialvalue="",
            parent=self.root,
        )
        if to_date is None:
            return None

        report_dir_default = ""
        if ms.folder:
            report_dir_default = str(Path(ms.folder) / "_reports")

        report_dir = simpledialog.askstring(
            "Report directory",
            "Report directory (optional):",
            initialvalue=report_dir_default,
            parent=self.root,
        )
        if report_dir is None:
            return None

        max_files = simpledialog.askstring(
            "Max files",
            "Max files (optional):",
            initialvalue="",
            parent=self.root,
        )
        if max_files is None:
            return None

        args = ["--log-dir", log_dir]
        if from_date:
            args.extend(["--from-date", from_date.strip()])
        if to_date:
            args.extend(["--to-date", to_date.strip()])
        if report_dir:
            args.extend(["--report-dir", report_dir.strip()])
        if max_files:
            args.extend(["--max-files", max_files.strip()])
        return args

    def _open_db_overview(self) -> None:
        win = tk.Toplevel(self.root)
        win.title("DB Overview")
        win.configure(bg=BG_BASE)
        win.geometry("760x520")
        win.grab_set()

        header = tk.Frame(win, bg=BG_BASE)
        header.pack(fill="x", padx=10, pady=(10, 6))
        tk.Label(header, text="Database Overview", fg=TEXT_MAIN, bg=BG_BASE, font=FONT_SECTION).pack(side="left")
        tk.Button(header, text="Refresh", command=lambda: refresh(), bg=BG_DARK, fg=TEXT_MAIN,
                  activebackground=ACCENT, activeforeground=BG_DARK, relief="flat",
                  padx=10, pady=4, font=FONT_BODY).pack(side="right")

        body = tk.Frame(win, bg=BG_BASE)
        body.pack(fill="both", expand=True, padx=10, pady=(0, 10))

        text = tk.Text(body, bg=BG_DARK, fg=TEXT_MAIN, insertbackground=TEXT_MAIN,
                       font=FONT_MONO, wrap="word")
        text.pack(side="left", fill="both", expand=True)

        scroll = tk.Scrollbar(body, command=text.yview)
        scroll.pack(side="right", fill="y")
        text.config(yscrollcommand=scroll.set)

        def refresh():
            text.delete("1.0", "end")
            rc, payload = self._build_db_overview()
            if rc != 0:
                payload = f"Error loading DB overview:\n{payload}"
            text.insert("end", payload)
            text.see("1.0")

        refresh()

    def _open_db_reset(self) -> None:
        g = self.config.globals
        if not g.allow_db_reset:
            messagebox.showwarning(
                "Reset disabled",
                "Enable DB reset (debug) in Settings to use this tool.",
            )
            return

        win = tk.Toplevel(self.root)
        win.title("Milestone Reset (Debug)")
        win.configure(bg=BG_BASE)
        win.geometry("640x420")
        win.grab_set()

        milestones = sorted(self.config.milestones.keys())
        if not milestones:
            messagebox.showinfo("No milestones", "No milestones configured.")
            win.destroy()
            return

        selection = tk.StringVar(value=milestones[0])

        header = tk.Frame(win, bg=BG_BASE)
        header.pack(fill="x", padx=10, pady=(10, 6))
        tk.Label(header, text="Milestone Reset (Debug)", fg=TEXT_MAIN, bg=BG_BASE,
                 font=FONT_SECTION).pack(side="left")

        body = tk.Frame(win, bg=BG_BASE)
        body.pack(fill="both", expand=True, padx=10, pady=(0, 10))

        row = tk.Frame(body, bg=BG_BASE)
        row.pack(fill="x", pady=(0, 6))
        tk.Label(row, text="Milestone", fg=TEXT_MAIN, bg=BG_BASE, font=FONT_BODY).pack(side="left")
        combo = ttk.Combobox(row, values=milestones, textvariable=selection, state="readonly", width=32)
        combo.pack(side="left", padx=(8, 0))

        info = tk.Label(body, text="", fg=TEXT_MAIN, bg=BG_BASE, font=FONT_MONO, justify="left")
        info.pack(anchor="w", pady=(4, 10))

        confirm_row = tk.Frame(body, bg=BG_BASE)
        confirm_row.pack(fill="x", pady=(0, 6))
        tk.Label(confirm_row, text="Type milestone name to confirm", fg=TEXT_MAIN, bg=BG_BASE,
                 font=FONT_BODY).pack(side="left")
        confirm_entry = tk.Entry(confirm_row, fg=TEXT_MAIN, bg=CARD_BG, insertbackground=TEXT_MAIN,
                                 relief="flat", width=28, font=FONT_BODY)
        confirm_entry.pack(side="left", padx=(8, 0))

        clear_var = tk.BooleanVar(value=True)
        tk.Checkbutton(
            body,
            text="Clear INIT lock for this milestone",
            variable=clear_var,
            bg=BG_BASE,
            fg=TEXT_MAIN,
            selectcolor=BG_BASE,
            activebackground=BG_BASE,
            activeforeground=TEXT_MAIN,
            font=FONT_BODY,
        ).pack(anchor="w", pady=(4, 10))

        output = tk.Text(body, bg=BG_DARK, fg=TEXT_MAIN, insertbackground=TEXT_MAIN,
                         font=FONT_MONO, height=6, wrap="word")
        output.pack(fill="both", expand=True, pady=(6, 0))

        def refresh_info(*_):
            name = selection.get()
            ms = self.config.milestones.get(name)
            if not ms:
                info.config(text="Milestone not found.")
                return
            tables = ", ".join(ms.db_tables) if ms.db_tables else "<not set>"
            raw_code = ms.raw_milestone_code or "<not set>"
            info.config(text=f"Tables: {tables}\nRaw code: {raw_code}")

        def do_reset():
            name = selection.get()
            ms = self.config.milestones.get(name)
            if not ms:
                messagebox.showerror("Missing milestone", "Milestone not found.")
                return
            if confirm_entry.get().strip() != name:
                messagebox.showwarning("Confirm", "Type the milestone name to confirm.")
                return
            output.delete("1.0", "end")
            rc, out = self._reset_milestone_db(ms)
            if clear_var.get():
                self.state.init_milestones.pop(name, None)
                self.state.init_runs.pop(name, None)
                self.state.save()
                self._rebuild_steps()
            if rc != 0:
                messagebox.showerror("Reset failed", out or "Reset failed.")
            else:
                messagebox.showinfo("Reset complete", f"{name} data deleted.")
            output.insert("end", out)
            output.see("end")

        btn_row = tk.Frame(body, bg=BG_BASE)
        btn_row.pack(fill="x", pady=(8, 0))
        tk.Button(btn_row, text="Reset Milestone Data", command=do_reset, bg=DANGER, fg=BG_DARK,
                  activebackground=ACCENT, activeforeground=BG_DARK, relief="flat",
                  padx=12, pady=6, font=FONT_SECTION).pack(side="right")
        tk.Button(btn_row, text="Close", command=win.destroy, bg=BG_DARK, fg=TEXT_MAIN,
                  activebackground=ACCENT, activeforeground=BG_DARK, relief="flat",
                  padx=12, pady=6, font=FONT_SECTION).pack(side="right", padx=(0, 6))

        refresh_info()
        selection.trace_add("write", refresh_info)

    def _open_settings(self) -> None:
        win = tk.Toplevel(self.root)
        win.title("Settings")
        win.configure(bg=BG_BASE)
        win.geometry("620x760")
        win.grab_set()

        section_title = lambda text: tk.Label(win, text=text, fg=TEXT_MAIN, bg=BG_BASE, font=FONT_SECTION)

        def add_field(parent, label, value, secret=False):
            row = tk.Frame(parent, bg=BG_BASE, pady=4)
            row.pack(fill="x")
            tk.Label(row, text=label, fg=TEXT_MAIN, bg=BG_BASE, width=20, anchor="w", font=FONT_BODY).pack(side="left")
            entry = tk.Entry(row, fg=TEXT_MAIN, bg=CARD_BG, insertbackground=TEXT_MAIN,
                             relief="flat", width=52, font=FONT_BODY)
            entry.insert(0, value or "")
            if secret:
                entry.config(show="*")
            entry.pack(side="left", fill="x", expand=True, padx=(6, 0))
            return entry

        def add_path_field(parent, label, value):
            row = tk.Frame(parent, bg=BG_BASE, pady=4)
            row.pack(fill="x")
            tk.Label(row, text=label, fg=TEXT_MAIN, bg=BG_BASE, width=20, anchor="w", font=FONT_BODY).pack(side="left")
            entry = tk.Entry(row, fg=TEXT_MAIN, bg=CARD_BG, insertbackground=TEXT_MAIN,
                             relief="flat", width=44, font=FONT_BODY)
            entry.insert(0, value or "")
            entry.pack(side="left", fill="x", expand=True, padx=(6, 6))

            def browse():
                d = filedialog.askdirectory()
                if d:
                    entry.delete(0, "end")
                    entry.insert(0, d)

            tk.Button(row, text="Browse", command=browse, bg=BG_DARK, fg=TEXT_MAIN,
                      activebackground=ACCENT, activeforeground=BG_DARK, relief="flat").pack(side="left")
            return entry

        def add_check(parent, label, value, check_text="External collect"):
            row = tk.Frame(parent, bg=BG_BASE, pady=4)
            row.pack(fill="x")
            tk.Label(row, text=label, fg=TEXT_MAIN, bg=BG_BASE, width=20, anchor="w", font=FONT_BODY).pack(side="left")
            var = tk.BooleanVar(value=value)
            tk.Checkbutton(
                row,
                text=check_text,
                variable=var,
                bg=BG_BASE,
                fg=TEXT_MAIN,
                selectcolor=BG_BASE,
                activebackground=BG_BASE,
                activeforeground=TEXT_MAIN,
                font=FONT_BODY,
            ).pack(side="left", padx=(6, 0))
            return var

        g = self.config.globals

        section_title("Workspace").pack(anchor="w", pady=(10, 2))
        wf = tk.Frame(win, bg=BG_BASE); wf.pack(fill="x", padx=8)
        ent_workspace = add_field(wf, "Workspace folder", g.workspace_folder or "")
        def browse_ws():
            d = filedialog.askdirectory()
            if d:
                ent_workspace.delete(0, "end")
                ent_workspace.insert(0, d)
        tk.Button(wf, text="Browse", command=browse_ws, bg=BG_DARK, fg=TEXT_MAIN,
                  activebackground=ACCENT, activeforeground=BG_DARK, relief="flat").pack(side="right", padx=6)

        section_title("MySQL").pack(anchor="w", pady=(14, 2))
        mf = tk.Frame(win, bg=BG_BASE); mf.pack(fill="x", padx=8)
        ent_host = add_field(mf, "Host", g.mysql_host)
        ent_port = add_field(mf, "Port", str(g.mysql_port))
        ent_user = add_field(mf, "User", g.mysql_user)
        ent_password = add_field(mf, "Password", g.mysql_password or "", secret=True)
        ent_db = add_field(mf, "Database", g.mysql_database)

        db_tools = tk.Frame(win, bg=BG_BASE); db_tools.pack(fill="x", padx=8, pady=(4, 0))
        tk.Button(db_tools, text="DB Overview", command=self._open_db_overview, bg=BG_DARK, fg=TEXT_MAIN,
                  activebackground=ACCENT, activeforeground=BG_DARK, relief="flat",
                  padx=10, pady=4, font=FONT_BODY).pack(side="left")
        tk.Button(db_tools, text="Milestone Reset", command=self._open_db_reset, bg=DANGER, fg=BG_DARK,
                  activebackground=ACCENT, activeforeground=BG_DARK, relief="flat",
                  padx=10, pady=4, font=FONT_BODY).pack(side="left", padx=(6, 0))
        tk.Label(db_tools, text="Uses current MySQL settings", fg=TEXT_MAIN, bg=BG_BASE, font=FONT_BODY).pack(side="left", padx=8)

        reset_row = tk.Frame(win, bg=BG_BASE); reset_row.pack(fill="x", padx=8, pady=(4, 0))
        reset_var = tk.BooleanVar(value=g.allow_db_reset)
        tk.Checkbutton(
            reset_row,
            text="Enable DB reset (debug)",
            variable=reset_var,
            bg=BG_BASE,
            fg=TEXT_MAIN,
            selectcolor=BG_BASE,
            activebackground=BG_BASE,
            activeforeground=TEXT_MAIN,
            font=FONT_BODY,
        ).pack(side="left")

        section_title("Executables (optional)").pack(anchor="w", pady=(14, 2))
        ef = tk.Frame(win, bg=BG_BASE); ef.pack(fill="x", padx=8)
        ent_mysql_cli = add_field(ef, "mysql.exe path", g.mysql_cli or "")
        ent_python = add_field(ef, "python.exe path", g.python_exe or "")

        # Milestone folders
        section_title("Dataset folders per milestone").pack(anchor="w", pady=(14, 2))
        ms_frame = tk.Frame(win, bg=BG_BASE); ms_frame.pack(fill="x", padx=8)
        milestone_entries: Dict[str, tk.Entry] = {}
        for name, ms in sorted(self.config.milestones.items()):
            milestone_entries[name] = add_path_field(ms_frame, name, ms.folder or "")

        section_title("Source folders per milestone").pack(anchor="w", pady=(14, 2))
        src_frame = tk.Frame(win, bg=BG_BASE); src_frame.pack(fill="x", padx=8)
        milestone_sources: Dict[str, tk.Entry] = {}
        for name, ms in sorted(self.config.milestones.items()):
            milestone_sources[name] = add_path_field(src_frame, name, ms.source_root or "")

        section_title("Milestone policy").pack(anchor="w", pady=(14, 2))
        tk.Label(
            win,
            text="External collect milestones allow only INSERT, VALIDATE, and SHOW.",
            fg=TEXT_MAIN,
            bg=BG_BASE,
            font=FONT_BODY,
        ).pack(anchor="w", padx=8)
        policy_frame = tk.Frame(win, bg=BG_BASE); policy_frame.pack(fill="x", padx=8)
        milestone_policy: Dict[str, tk.BooleanVar] = {}
        for name, ms in sorted(self.config.milestones.items()):
            milestone_policy[name] = add_check(policy_frame, name, ms.external_collect)

        section_title("Milestone DB mapping (reset)").pack(anchor="w", pady=(14, 2))
        tk.Label(
            win,
            text="Comma-separated table list + raw milestone code (used by reset).",
            fg=TEXT_MAIN,
            bg=BG_BASE,
            font=FONT_BODY,
        ).pack(anchor="w", padx=8)
        mapping_frame = tk.Frame(win, bg=BG_BASE); mapping_frame.pack(fill="x", padx=8)
        milestone_tables: Dict[str, tk.Entry] = {}
        milestone_raw_code: Dict[str, tk.Entry] = {}
        for name, ms in sorted(self.config.milestones.items()):
            row = tk.Frame(mapping_frame, bg=BG_BASE, pady=4)
            row.pack(fill="x")
            tk.Label(row, text=name, fg=TEXT_MAIN, bg=BG_BASE, width=20, anchor="w", font=FONT_BODY).pack(side="left")
            tables_entry = tk.Entry(row, fg=TEXT_MAIN, bg=CARD_BG, insertbackground=TEXT_MAIN,
                                    relief="flat", width=32, font=FONT_BODY)
            tables_entry.insert(0, ", ".join(ms.db_tables))
            tables_entry.pack(side="left", padx=(6, 6))
            raw_entry = tk.Entry(row, fg=TEXT_MAIN, bg=CARD_BG, insertbackground=TEXT_MAIN,
                                 relief="flat", width=10, font=FONT_BODY)
            raw_entry.insert(0, ms.raw_milestone_code or "")
            raw_entry.pack(side="left")
            milestone_tables[name] = tables_entry
            milestone_raw_code[name] = raw_entry

        btn_row = tk.Frame(win, bg=BG_BASE, pady=14); btn_row.pack(fill="x")

        def on_save():
            # globals
            g.workspace_folder = ent_workspace.get().strip() or None
            g.mysql_host = ent_host.get().strip() or g.mysql_host
            g.mysql_user = ent_user.get().strip() or g.mysql_user
            g.mysql_password = ent_password.get().strip() or None
            g.mysql_database = ent_db.get().strip() or g.mysql_database
            g.mysql_cli = ent_mysql_cli.get().strip() or None
            g.python_exe = ent_python.get().strip() or None
            try:
                g.mysql_port = int(ent_port.get().strip()) if ent_port.get().strip() else g.mysql_port
            except ValueError:
                messagebox.showerror("Invalid port", "MySQL port must be a number.")
                return

            # milestone folders
            for name, entry in milestone_entries.items():
                val = entry.get().strip()
                if name in self.config.milestones:
                    self.config.milestones[name].folder = val or None

            # milestone source folders
            for name, entry in milestone_sources.items():
                val = entry.get().strip()
                if name in self.config.milestones:
                    self.config.milestones[name].source_root = val or None

            # milestone policy
            for name, var in milestone_policy.items():
                if name in self.config.milestones:
                    self.config.milestones[name].external_collect = bool(var.get())

            # milestone DB mapping
            for name, entry in milestone_tables.items():
                if name in self.config.milestones:
                    raw = entry.get().strip()
                    tables = [t.strip() for t in raw.split(",") if t.strip()]
                    self.config.milestones[name].db_tables = tables
            for name, entry in milestone_raw_code.items():
                if name in self.config.milestones:
                    code = entry.get().strip()
                    self.config.milestones[name].raw_milestone_code = code or None

            # debug reset flag
            g.allow_db_reset = bool(reset_var.get())

            try:
                self.config.save()
                self._populate_globals()
                self._populate_milestones()
                messagebox.showinfo("Saved", "Settings updated and saved.")
                win.destroy()
            except Exception as exc:
                messagebox.showerror("Error", f"Could not save settings:\n{exc}")

        tk.Button(btn_row, text="Save", command=on_save, fg=BG_DARK, bg=TEXT_MAIN,
                  activebackground=ACCENT, activeforeground=BG_DARK, relief="flat",
                  padx=14, pady=6, font=FONT_SECTION).pack(side="right", padx=6)
        tk.Button(btn_row, text="Cancel", command=win.destroy, fg=TEXT_MAIN, bg=BG_DARK,
                  activebackground=ACCENT, activeforeground=BG_DARK, relief="flat",
                  padx=12, pady=6, font=FONT_SECTION).pack(side="right", padx=6)

def main() -> None:
    root = tk.Tk()
    app = ForensicApp(root)
    root.mainloop()

if __name__ == "__main__":
    main()

