"""Interactive UI for configuring forensic milestones and steps.

This script provides a simple text-based interface to manage:
- Global folders and MySQL database settings.
- Milestones with standard steps (dump, table creation, data load, validation).

Configuration is stored in JSON next to the script by default.
"""
from __future__ import annotations

import json
import os
from dataclasses import dataclass, asdict, field
from typing import Dict, List, Optional

CONFIG_FILE = "forensic_config.json"


@dataclass
class Step:
    """A single step inside a milestone."""

    name: str
    description: str
    script_path: Optional[str] = None
<<<<<<< HEAD

    def display(self) -> str:
        script = self.script_path if self.script_path else "<not set>"
        return f"- {self.name}: {self.description} (script: {script})"
=======
    last_run_iteration: int = 0

    def display(self, current_iteration: int = 0) -> str:
        script = self.script_path if self.script_path else "<not set>"
        run_info = (
            f"last run in iteration {self.last_run_iteration}"
            if self.last_run_iteration
            else "never run"
        )
        marker = " ✅" if current_iteration and self.last_run_iteration == current_iteration else ""
        return f"- {self.name}: {self.description} (script: {script}; {run_info}){marker}"
>>>>>>> 4807cea7e81964f4ea3f58bad542d25a3bc5cd10


@dataclass
class Milestone:
    """Milestone grouping the four canonical forensic steps."""

    name: str
    folder: Optional[str] = None
<<<<<<< HEAD
    steps: List[Step] = field(default_factory=list)

    @classmethod
    def with_standard_steps(cls, name: str, folder: Optional[str] = None) -> "Milestone":
        return cls(
            name=name,
            folder=folder,
=======
    data_source: Optional[str] = None
    steps: List[Step] = field(default_factory=list)
    current_iteration: int = 0

    @classmethod
    def with_standard_steps(
        cls, name: str, folder: Optional[str] = None, data_source: Optional[str] = None
    ) -> "Milestone":
        return cls(
            name=name,
            folder=folder,
            data_source=data_source,
>>>>>>> 4807cea7e81964f4ea3f58bad542d25a3bc5cd10
            steps=[
                Step(
                    name="Dump",
                    description="Create forensic dump and normalize naming",
                ),
                Step(
                    name="Create Table",
                    description="Add table to contain data in database",
                ),
                Step(
                    name="Load Data",
                    description="Python script to fill the table",
                ),
                Step(
                    name="Validate",
                    description="Script to validate data insertion",
                ),
            ],
        )

<<<<<<< HEAD
    def display(self) -> str:
        folder = self.folder if self.folder else "<not set>"
        lines = [f"Milestone: {self.name} (folder: {folder})"]
        lines.extend(step.display() for step in self.steps)
=======
    def _iteration_started(self) -> bool:
        return self.current_iteration > 0 and any(
            step.last_run_iteration == self.current_iteration for step in self.steps
        )

    def iteration_completed(self) -> bool:
        return self.current_iteration > 0 and all(
            step.last_run_iteration == self.current_iteration for step in self.steps
        )

    def can_run_step(self, step_index: int) -> bool:
        if step_index == 0:
            return not self._iteration_started() or self.iteration_completed()
        previous_step = self.steps[step_index - 1]
        return previous_step.last_run_iteration == self.current_iteration

    def mark_step_run(self, step_index: int) -> None:
        if self.current_iteration == 0 or self.iteration_completed():
            self.current_iteration += 1
        self.steps[step_index].last_run_iteration = self.current_iteration

    def display(self) -> str:
        folder = self.folder if self.folder else "<not set>"
        data_source = self.data_source if self.data_source else "<not set>"
        iteration = self.current_iteration if self.current_iteration else "<never started>"
        lines = [
            f"Milestone: {self.name} (folder: {folder})",
            f"Data to parse: {data_source}",
            f"Current iteration: {iteration}",
        ]
        lines.extend(step.display(self.current_iteration) for step in self.steps)
>>>>>>> 4807cea7e81964f4ea3f58bad542d25a3bc5cd10
        return "\n".join(lines)


@dataclass
class GlobalSettings:
    """Shared settings applied to every milestone."""

    workspace_folder: Optional[str] = None
    mysql_host: str = "localhost"
    mysql_port: int = 3306
    mysql_user: str = "root"
    mysql_database: str = "forensic"

    def display(self) -> str:
        workspace = self.workspace_folder if self.workspace_folder else "<not set>"
        return (
            f"Workspace: {workspace}\n"
            f"MySQL host: {self.mysql_host}\n"
            f"MySQL port: {self.mysql_port}\n"
            f"MySQL user: {self.mysql_user}\n"
            f"MySQL database: {self.mysql_database}"
        )


@dataclass
class ForensicConfig:
    """Container for global settings and milestones."""

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
<<<<<<< HEAD
        milestones = {
            name: Milestone(
                name=milestone["name"],
                folder=milestone.get("folder"),
                steps=[Step(**step) for step in milestone.get("steps", [])],
            )
            for name, milestone in milestones_data.items()
        }
=======
        milestones = {}
        for name, milestone in milestones_data.items():
            milestones[name] = Milestone(
                name=milestone["name"],
                folder=milestone.get("folder"),
                data_source=milestone.get("data_source"),
                steps=[Step(**step) for step in milestone.get("steps", [])],
                current_iteration=milestone.get("current_iteration", 0),
            )
>>>>>>> 4807cea7e81964f4ea3f58bad542d25a3bc5cd10
        return cls(globals=globals_cfg, milestones=milestones)

    def save(self, path: str = CONFIG_FILE) -> None:
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(self.to_json())

    @classmethod
    def load(cls, path: str = CONFIG_FILE) -> "ForensicConfig":
        if not os.path.exists(path):
            return cls()
        with open(path, "r", encoding="utf-8") as fh:
            return cls.from_json(fh.read())


class ForensicUI:
    """Text-based UI to configure milestones and global settings."""

    def __init__(self, config_path: str = CONFIG_FILE) -> None:
        self.config_path = config_path
        self.config = ForensicConfig.load(config_path)

    def run(self) -> None:
        print("Forensic milestone configurator\n")
        while True:
            print("Main menu")
            print("1) Modifica impostazioni globali")
            print("2) Aggiungi milestone (passi standard)")
            print("3) Modifica milestone esistente")
<<<<<<< HEAD
            print("4) Mostra configurazione")
            print("5) Salva ed esci")
=======
            print("4) Esegui uno step")
            print("5) Mostra configurazione")
            print("6) Salva ed esci")
>>>>>>> 4807cea7e81964f4ea3f58bad542d25a3bc5cd10
            choice = input("Seleziona un'opzione: ").strip()
            if choice == "1":
                self._edit_globals()
            elif choice == "2":
                self._add_milestone()
            elif choice == "3":
                self._edit_milestone()
            elif choice == "4":
<<<<<<< HEAD
                self._show_config()
            elif choice == "5":
=======
                self._run_step()
            elif choice == "5":
                self._show_config()
            elif choice == "6":
>>>>>>> 4807cea7e81964f4ea3f58bad542d25a3bc5cd10
                self._save_and_exit()
            else:
                print("Scelta non valida. Riprova.\n")

    def _edit_globals(self) -> None:
        globals_cfg = self.config.globals
        print("\nImpostazioni globali attuali:")
        print(globals_cfg.display())
        workspace = input("Cartella workspace (vuoto per lasciare invariato): ").strip()
        if workspace:
            globals_cfg.workspace_folder = workspace
        host = input("MySQL host (default localhost): ").strip()
        if host:
            globals_cfg.mysql_host = host
        port_str = input("MySQL port (default 3306): ").strip()
        if port_str:
            try:
                globals_cfg.mysql_port = int(port_str)
            except ValueError:
                print("Porta non valida, valore ignorato.")
        user = input("MySQL user (default root): ").strip()
        if user:
            globals_cfg.mysql_user = user
        database = input("MySQL database (default forensic): ").strip()
        if database:
            globals_cfg.mysql_database = database
        print("Impostazioni globali aggiornate.\n")

    def _add_milestone(self) -> None:
        name = input("\nNome della milestone: ").strip()
        if not name:
            print("Nome obbligatorio per creare una milestone.\n")
            return
        folder = input("Cartella associata (opzionale): ").strip() or None
<<<<<<< HEAD
        milestone = Milestone.with_standard_steps(name=name, folder=folder)
=======
        data_source = input("Descrizione dati/DB da parsare (opzionale): ").strip() or None
        milestone = Milestone.with_standard_steps(
            name=name, folder=folder, data_source=data_source
        )
>>>>>>> 4807cea7e81964f4ea3f58bad542d25a3bc5cd10
        self.config.milestones[name] = milestone
        print(f"Milestone '{name}' creata con i quattro step standard.\n")

    def _select_milestone(self) -> Optional[Milestone]:
        if not self.config.milestones:
            print("\nNon ci sono milestone da modificare.\n")
            return None
        names = list(self.config.milestones)
        for idx, name in enumerate(names, start=1):
            print(f"{idx}) {name}")
        choice = input("Seleziona una milestone: ").strip()
        try:
            index = int(choice) - 1
            if index < 0:
                raise ValueError
            return self.config.milestones[names[index]]
        except (ValueError, IndexError):
            print("Scelta non valida.\n")
            return None

    def _edit_milestone(self) -> None:
        milestone = self._select_milestone()
        if not milestone:
            return
        while True:
            print("\nModifica milestone")
            print(milestone.display())
            print("1) Rinomina milestone")
            print("2) Imposta cartella")
<<<<<<< HEAD
            print("3) Aggiorna script per uno step")
            print("4) Torna al menu principale")
=======
            print("3) Imposta origine dati")
            print("4) Aggiorna script per uno step")
            print("5) Torna al menu principale")
>>>>>>> 4807cea7e81964f4ea3f58bad542d25a3bc5cd10
            choice = input("Seleziona un'opzione: ").strip()
            if choice == "1":
                self._rename_milestone(milestone)
            elif choice == "2":
                self._set_milestone_folder(milestone)
            elif choice == "3":
<<<<<<< HEAD
                self._update_step_script(milestone)
            elif choice == "4":
=======
                self._set_milestone_data_source(milestone)
            elif choice == "4":
                self._update_step_script(milestone)
            elif choice == "5":
>>>>>>> 4807cea7e81964f4ea3f58bad542d25a3bc5cd10
                print()
                return
            else:
                print("Scelta non valida.\n")

    def _rename_milestone(self, milestone: Milestone) -> None:
        new_name = input("Nuovo nome: ").strip()
        if not new_name:
            print("Nome non modificato.\n")
            return
        if new_name in self.config.milestones and new_name != milestone.name:
            print("Esiste già una milestone con questo nome.\n")
            return
        if new_name != milestone.name:
            self.config.milestones.pop(milestone.name)
            milestone.name = new_name
            self.config.milestones[new_name] = milestone
        print("Milestone rinominata.\n")

    def _set_milestone_folder(self, milestone: Milestone) -> None:
        folder = input("Nuova cartella (vuoto per rimuovere): ").strip()
        milestone.folder = folder or None
        print("Cartella aggiornata.\n")

<<<<<<< HEAD
=======
    def _set_milestone_data_source(self, milestone: Milestone) -> None:
        data_source = input(
            "Nuova origine dati/DB da parsare (vuoto per rimuovere): "
        ).strip()
        milestone.data_source = data_source or None
        print("Origine dati aggiornata.\n")

>>>>>>> 4807cea7e81964f4ea3f58bad542d25a3bc5cd10
    def _update_step_script(self, milestone: Milestone) -> None:
        for idx, step in enumerate(milestone.steps, start=1):
            print(f"{idx}) {step.name}")
        choice = input("Seleziona uno step: ").strip()
        try:
            index = int(choice) - 1
            if index < 0:
                raise ValueError
            step = milestone.steps[index]
        except (ValueError, IndexError):
            print("Scelta non valida.\n")
            return
        script = input("Percorso script (vuoto per rimuovere): ").strip()
        step.script_path = script or None
        print("Script aggiornato.\n")

<<<<<<< HEAD
=======
    def _run_step(self) -> None:
        milestone = self._select_milestone()
        if not milestone:
            return
        for idx, step in enumerate(milestone.steps, start=1):
            status = "completato" if step.last_run_iteration == milestone.current_iteration and milestone.current_iteration else "in sospeso"
            print(f"{idx}) {step.name} ({status})")
        choice = input("Seleziona lo step da eseguire: ").strip()
        try:
            index = int(choice) - 1
            if index < 0:
                raise ValueError
        except ValueError:
            print("Scelta non valida.\n")
            return
        if index >= len(milestone.steps):
            print("Scelta non valida.\n")
            return
        if not milestone.can_run_step(index):
            print(
                "Sequenza non valida: completa lo step precedente o chiudi l'iterazione prima di ripartire.\n"
            )
            return
        milestone.mark_step_run(index)
        step = milestone.steps[index]
        print(
            "Step registrato come eseguito."
            f" Iterazione attuale: {milestone.current_iteration}."
            f" Script: {step.script_path or 'n/d'}.\n"
        )

>>>>>>> 4807cea7e81964f4ea3f58bad542d25a3bc5cd10
    def _show_config(self) -> None:
        print("\nImpostazioni globali:")
        print(self.config.globals.display())
        if not self.config.milestones:
            print("\nNessuna milestone configurata.\n")
            return
        print("\nMilestone configurate:")
        for milestone in self.config.milestones.values():
            print(milestone.display())
            print()

    def _save_and_exit(self) -> None:
        self.config.save(self.config_path)
        print(f"Configurazione salvata in {self.config_path}.")
        raise SystemExit


def main() -> None:
    ui = ForensicUI()
    ui.run()


if __name__ == "__main__":
    main()
