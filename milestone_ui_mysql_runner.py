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
from pathlib import Path
from typing import Dict, List, Optional, Tuple

import tkinter as tk
from tkinter import messagebox, ttk, filedialog

CONFIG_FILE = Path(__file__).with_name("forensic_config.json")

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

# ------------- Config models -------------
@dataclass
class Step:
    name: str
    description: str
    script_path: Optional[str] = None

@dataclass
class Milestone:
    name: str
    folder: Optional[str] = None
    steps: List[Step] = field(default_factory=list)

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

# ------------- UI -------------
class ForensicApp:
    def __init__(self, root: tk.Tk):
        self.root = root
        self.root.title("SAFENET Milestone UI (MySQL Runner)")
        self.root.geometry("1080x680")
        self.root.configure(bg=BG_BASE)

        self.config = ForensicConfig.load()

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
                                 relief="flat", padx=10, pady=6, font=FONT_SECTION)
        self.run_btn.pack(side="right", padx=(6, 0))

        self.steps_tree = ttk.Treeview(steps_card, columns=("step", "description", "script"), show="headings",
                                       selectmode="browse", height=10)
        self.steps_tree.heading("step", text="Step")
        self.steps_tree.heading("description", text="Description")
        self.steps_tree.heading("script", text="Script")
        self.steps_tree.column("step", width=130, anchor="w")
        self.steps_tree.column("description", width=360, anchor="w")
        self.steps_tree.column("script", width=420, anchor="w")
        self.steps_tree.pack(fill="x", expand=False, pady=(8, 8))

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

    def _on_select_milestone(self, event=None) -> None:
        for item in self.steps_tree.get_children():
            self.steps_tree.delete(item)
        selection = self.milestone_list.curselection()
        if not selection:
            return
        name = self.milestone_list.get(selection[0])
        ms = self.config.milestones.get(name)
        if not ms:
            return
        for step in ms.steps:
            script = step.script_path or "<not set>"
            self.steps_tree.insert("", tk.END, values=(step.name, step.description, script))
        # auto select first step
        children = self.steps_tree.get_children()
        if children:
            self.steps_tree.selection_set(children[0])

    def _refresh(self) -> None:
        try:
            self.config = ForensicConfig.load()
            self._populate_globals()
            self._populate_milestones()
            messagebox.showinfo("Refresh", "Configuration reloaded.")
        except Exception as exc:
            messagebox.showerror("Error", f"Could not reload config:\n{exc}")

    def _append_output(self, text: str) -> None:
        self.output.insert("end", text + "\n")
        self.output.see("end")
        self.output.update_idletasks()

    def _run_selected_step(self) -> None:
        ms_name = None
        sel = self.milestone_list.curselection()
        if sel:
            ms_name = self.milestone_list.get(sel[0])
        if not ms_name:
            messagebox.showwarning("No milestone", "Select a milestone first.")
            return

        item = self.steps_tree.selection()
        if not item:
            messagebox.showwarning("No step", "Select a step first.")
            return

        values = self.steps_tree.item(item[0], "values")
        step_name, desc, script = values
        if not script or script == "<not set>" or script.lower() == "pending":
            messagebox.showwarning("No script", "This step has no script_path set.")
            return

        self._append_output(f"\n=== RUN: {ms_name} :: {step_name} ===")
        self._append_output(f"{desc}")
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
            rc, out = self._run_python(resolved)
        else:
            rc, out = 1, f"Unsupported script type: {ext}"

        self._append_output(out)
        self._append_output(f"=== EXIT CODE: {rc} ===")

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

    def _run_python(self, py_path: Path) -> Tuple[int, str]:
        g = self.config.globals
        py = g.python_exe or sys.executable

        # Pass workspace + config path as env so scripts can read config consistently
        env = os.environ.copy()
        if g.workspace_folder:
            env["SAFENET_WORKSPACE"] = g.workspace_folder
        env["SAFENET_CONFIG"] = str(CONFIG_FILE)

        cmd = [py, str(py_path)]
        rc, out = run_subprocess(cmd, cwd=py_path.parent, env=env)
        header = f"[python] {shlex.join(cmd)}"
        return rc, header + "\n" + out

    def _open_settings(self) -> None:
        win = tk.Toplevel(self.root)
        win.title("Settings")
        win.configure(bg=BG_BASE)
        win.geometry("620x620")
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
