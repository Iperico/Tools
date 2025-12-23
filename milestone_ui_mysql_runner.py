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
import shlex
import subprocess
import sys
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

FONT_TITLE = ("Bahnschrift", 20, "bold")
FONT_SECTION = ("Bahnschrift", 12, "bold")
FONT_BODY = ("Bahnschrift", 11)
FONT_MONO = ("Cascadia Code", 10)

OP_ALL = "ALL"
OP_INIT = "INIT"
OP_EXTRACT = "EXTRACT"
OP_VALIDATE = "VALIDATE"
OP_INSERT = "INSERT"
OP_UNKNOWN = "UNSET"
OP_DISPLAY = [OP_INIT, OP_EXTRACT, OP_VALIDATE, OP_INSERT]
OP_FILTERS = [OP_ALL] + OP_DISPLAY

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

    def to_json(self) -> str:
        return json.dumps(asdict(self), indent=4)

    @classmethod
    def load(cls, path: Path = STATE_FILE) -> "ForensicState":
        if not path.exists():
            return cls()
        data = json.loads(path.read_text(encoding="utf-8"))
        return cls(init_runs=data.get("init_runs", {}))

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
    if any(k in text for k in ("extract", "dump", "capture", "export", "acquire")):
        return OP_EXTRACT
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

        btns = tk.Frame(header, bg=BG_BASE)
        btns.pack(side="right")
        tk.Button(btns, text="Settings", command=self._open_settings, bg=TEXT_MAIN, fg=BG_DARK,
                  activebackground=ACCENT, activeforeground=BG_DARK, relief="flat", padx=12, pady=6,
                  font=FONT_SECTION).pack(side="left", padx=6)
        tk.Button(btns, text="Refresh", command=self._refresh, bg=BG_DARK, fg=TEXT_MAIN,
                  activebackground=ACCENT, activeforeground=BG_DARK, relief="flat", padx=12, pady=6,
                  font=FONT_SECTION).pack(side="left", padx=6)

        body = tk.Frame(self.container, bg=BG_BASE)
        body.pack(fill="both", expand=True, pady=(10, 0))

        left = tk.Frame(body, bg=BG_BASE)
        left.pack(side="left", fill="y")

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
        mcard.pack(fill="both", expand=True, pady=(12, 0))
        tk.Label(mcard, text="Milestones", fg=TEXT_MAIN, bg=CARD_BG, font=FONT_SECTION).pack(anchor="w")
        self.milestone_list = tk.Listbox(mcard, bg=BG_DARK, fg=TEXT_MAIN, font=FONT_BODY, height=16,
                                         highlightthickness=0, selectbackground=ACCENT, selectforeground=BG_DARK)
        self.milestone_list.pack(fill="both", expand=True, pady=(6, 0))
        self.milestone_list.bind("<<ListboxSelect>>", self._on_select_milestone)

        # steps + runner
        steps_card = tk.Frame(right, bg=CARD_BG, padx=14, pady=10, highlightthickness=1,
                              highlightbackground="#162447", highlightcolor="#162447")
        steps_card.pack(fill="both", expand=True)

        top_row = tk.Frame(steps_card, bg=CARD_BG)
        top_row.pack(fill="x")
        tk.Label(top_row, text="Steps", fg=TEXT_MAIN, bg=CARD_BG, font=FONT_SECTION).pack(side="left")

        self.run_btn = tk.Button(top_row, text="Run Selected Step", command=self._run_selected_step,
                                 bg=TEXT_MAIN, fg=BG_DARK, activebackground=ACCENT, activeforeground=BG_DARK,
                                 relief="flat", padx=10, pady=6, font=FONT_SECTION, state="disabled")
        self.run_btn.pack(side="right", padx=(6, 0))

        filter_row = tk.Frame(steps_card, bg=CARD_BG)
        filter_row.pack(fill="x", pady=(6, 0))
        tk.Label(filter_row, text="Operation", fg=TEXT_MAIN, bg=CARD_BG, font=FONT_BODY).pack(side="left")
        self.op_filter = tk.StringVar(value=OP_ALL)
        for op in OP_FILTERS:
            label = "All" if op == OP_ALL else op
            tk.Radiobutton(
                filter_row,
                text=label,
                variable=self.op_filter,
                value=op,
                command=self._on_filter_change,
                bg=CARD_BG,
                fg=TEXT_MAIN,
                selectcolor=CARD_BG,
                activebackground=CARD_BG,
                activeforeground=TEXT_MAIN,
                font=FONT_BODY,
            ).pack(side="left", padx=(8, 0))

        self.policy_label = tk.Label(
            steps_card,
            text="",
            fg=TEXT_MAIN,
            bg=CARD_BG,
            font=FONT_BODY,
            justify="left",
            wraplength=820,
        )
        self.policy_label.pack(anchor="w", pady=(4, 0))

        self.step_hint = tk.Label(steps_card, text="", fg=TEXT_MAIN, bg=CARD_BG, font=FONT_BODY)
        self.step_hint.pack(anchor="w", pady=(2, 6))

        self.steps_tree = ttk.Treeview(
            steps_card,
            columns=("operation", "step", "description", "script", "status"),
            show="headings",
            selectmode="browse",
            height=10,
        )
        self.steps_tree.heading("operation", text="Op")
        self.steps_tree.heading("step", text="Step")
        self.steps_tree.heading("description", text="Description")
        self.steps_tree.heading("script", text="Script")
        self.steps_tree.heading("status", text="Status")
        self.steps_tree.column("operation", width=90, anchor="w")
        self.steps_tree.column("step", width=150, anchor="w")
        self.steps_tree.column("description", width=300, anchor="w")
        self.steps_tree.column("script", width=300, anchor="w")
        self.steps_tree.column("status", width=90, anchor="w")
        self.steps_tree.pack(fill="x", expand=False, pady=(4, 8))
        self.steps_tree.bind("<<TreeviewSelect>>", self._on_step_selected)

        style = ttk.Style()
        style.theme_use("default")
        style.configure("Treeview", background=CARD_BG, foreground=TEXT_MAIN, fieldbackground=CARD_BG,
                        rowheight=26, bordercolor=CARD_BG, font=FONT_BODY)
        style.configure("Treeview.Heading", background=BG_DARK, foreground=TEXT_MAIN, font=FONT_SECTION)
        style.map("Treeview", background=[("selected", ACCENT)], foreground=[("selected", BG_DARK)])

        tk.Label(steps_card, text="Output", fg=TEXT_MAIN, bg=CARD_BG, font=FONT_SECTION).pack(anchor="w")
        self.output = tk.Text(steps_card, bg=BG_DARK, fg=TEXT_MAIN, insertbackground=TEXT_MAIN,
                              font=FONT_MONO, height=16, wrap="word")
        self.output.pack(fill="both", expand=True, pady=(6, 0))

        self._populate_globals()
        self._populate_milestones()

    def _on_resize(self, event) -> None:
        draw_radial_gradient(self.bg, event.width, event.height)

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

    def _on_filter_change(self) -> None:
        self._rebuild_steps()

    def _rebuild_steps(self) -> None:
        for item in self.steps_tree.get_children():
            self.steps_tree.delete(item)
        self._step_map.clear()

        ms = self._current_milestone
        if not ms:
            self.policy_label.config(text="")
            self.step_hint.config(text="")
            self.run_btn.config(state="disabled")
            return

        op_filter = self.op_filter.get()
        for step in ms.steps:
            op = self._get_step_operation(step)
            if op_filter != OP_ALL and op != op_filter:
                continue
            script = step.script_path or "<not set>"
            status = self._step_status(ms, step, op)
            item = self.steps_tree.insert("", tk.END, values=(op, step.name, step.description, script, status))
            self._step_map[item] = (step, op)

        self._update_policy_label(ms)

        children = self.steps_tree.get_children()
        if children:
            self.steps_tree.selection_set(children[0])
        self._update_run_state()

    def _update_policy_label(self, ms: Milestone) -> None:
        expected = {OP_INSERT, OP_VALIDATE} if ms.external_collect else set(OP_DISPLAY)
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
        policy = "External collect (INSERT + VALIDATE only)" if ms.external_collect else "Standard (INIT + EXTRACT + VALIDATE + INSERT)"
        text = f"Policy: {policy}. Present: {', '.join(ordered_present) or 'none'}."
        if missing:
            text += f" Missing: {', '.join(missing)}."
        if extra:
            text += f" Extra: {', '.join(extra)}."
        if unset_count:
            text += f" Unset: {unset_count}."
        text += " INIT runs once per step (tracked in forensic_state.json)."
        self.policy_label.config(text=text)

    def _get_step_operation(self, step: Step) -> str:
        explicit = normalize_operation(step.operation)
        return explicit if explicit else infer_operation(step)

    def _step_status(self, ms: Milestone, step: Step, op: str) -> str:
        if op == OP_INIT and self._init_locked(ms, step):
            return "DONE"
        if ms.external_collect and op in (OP_INIT, OP_EXTRACT):
            return "BLOCKED"
        if op == OP_UNKNOWN:
            return "UNSET"
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
        self.step_hint.config(text=hint or "")

    def _can_run_step(self, ms: Milestone, step: Step, op: str) -> Tuple[bool, str]:
        script = step.script_path or ""
        if not script or script == "<not set>" or script.lower() == "pending":
            return False, "No script set for this step."
        if ms.external_collect and op in (OP_INIT, OP_EXTRACT):
            return False, "External collect milestones allow only INSERT and VALIDATE."
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

    def _init_locked(self, ms: Milestone, step: Step) -> bool:
        ms_runs = self.state.init_runs.get(ms.name, {})
        return step_key(step) in ms_runs

    def _mark_init_done(self, ms: Milestone, step: Step) -> None:
        ms_runs = self.state.init_runs.setdefault(ms.name, {})
        ms_runs[step_key(step)] = datetime.utcnow().isoformat(timespec="seconds") + "Z"
        self.state.save()

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
        if ms.external_collect and op in (OP_INIT, OP_EXTRACT):
            messagebox.showwarning(
                "Blocked",
                "External collect milestones allow only INSERT and VALIDATE steps.",
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

        if rc == 0 and op == OP_INIT:
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

    def _open_settings(self) -> None:
        win = tk.Toplevel(self.root)
        win.title("Settings")
        win.configure(bg=BG_BASE)
        win.geometry("620x700")
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

        section_title("Executables (optional)").pack(anchor="w", pady=(14, 2))
        ef = tk.Frame(win, bg=BG_BASE); ef.pack(fill="x", padx=8)
        ent_mysql_cli = add_field(ef, "mysql.exe path", g.mysql_cli or "")
        ent_python = add_field(ef, "python.exe path", g.python_exe or "")

        # Milestone folders
        section_title("Dataset folders per milestone").pack(anchor="w", pady=(14, 2))
        ms_frame = tk.Frame(win, bg=BG_BASE); ms_frame.pack(fill="x", padx=8)
        milestone_entries: Dict[str, tk.Entry] = {}
        for name, ms in sorted(self.config.milestones.items()):
            milestone_entries[name] = add_field(ms_frame, name, ms.folder or "")

        section_title("Milestone policy").pack(anchor="w", pady=(14, 2))
        tk.Label(
            win,
            text="External collect milestones allow only INSERT and VALIDATE.",
            fg=TEXT_MAIN,
            bg=BG_BASE,
            font=FONT_BODY,
        ).pack(anchor="w", padx=8)
        policy_frame = tk.Frame(win, bg=BG_BASE); policy_frame.pack(fill="x", padx=8)
        milestone_policy: Dict[str, tk.BooleanVar] = {}
        for name, ms in sorted(self.config.milestones.items()):
            milestone_policy[name] = add_check(policy_frame, name, ms.external_collect)

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

            # milestone policy
            for name, var in milestone_policy.items():
                if name in self.config.milestones:
                    self.config.milestones[name].external_collect = bool(var.get())

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

