import argparse
import subprocess
import sys
import shutil
import hashlib
import mimetypes
from datetime import datetime
from pathlib import Path


def sanitize_for_path(value: str) -> str:
    safe = "".join(ch if ch.isalnum() or ch in ("-", "_") else "_" for ch in value.strip())
    safe = safe.strip("_")
    return safe or "unknown"


def check_adb_available():
    if shutil.which("adb") is None:
        print(
            "[ERRORE] 'adb' non trovato nel PATH. "
            "Aggiungi la cartella platform-tools al PATH "
            "oppure esegui lo script da dentro quella cartella."
        )
        sys.exit(1)


def get_connected_device():
    try:
        result = subprocess.run(
            ["adb", "devices"],
            capture_output=True,
            text=True,
            check=False,
        )
    except FileNotFoundError:
        print("[ERRORE] adb non trovato. Controlla l'installazione.")
        sys.exit(1)

    lines = result.stdout.strip().splitlines()
    # Prima riga è di solito "List of devices attached"
    devices = []
    for line in lines[1:]:
        line = line.strip()
        if not line:
            continue
        parts = line.split()
        if len(parts) >= 2 and parts[1] == "device":
            devices.append(parts[0])

    if not devices:
        print("[ERRORE] Nessun dispositivo collegato (stato 'device').")
        print(" - Controlla cavo, driver, debug USB e autorizzazione sul telefono.")
        sys.exit(1)

    if len(devices) > 1:
        print("[INFO] Trovati più dispositivi, uso il primo:", devices[0])

    return devices[0]


def adb_shell_getprop(prop: str, device: str | None = None, timeout: int = 10) -> str:
    cmd = ["adb"]
    if device is not None:
        cmd += ["-s", device]
    cmd += ["shell", "getprop", prop]
    try:
        res = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        if res.returncode == 0 and res.stdout:
            return res.stdout.strip()
    except Exception:
        pass
    return ""


def collect_device_properties(device: str) -> dict[str, str]:
    props_map = {
        "ro.product.manufacturer": "manufacturer",
        "ro.product.brand": "brand",
        "ro.product.model": "model",
        "ro.product.device": "device_code",
        "ro.product.name": "product_name",
        "ro.build.version.release": "android_release",
        "ro.build.version.sdk": "android_sdk",
        "ro.build.id": "build_id",
        "ro.build.display.id": "build_display_id",
        "ro.build.version.security_patch": "security_patch",
        "ro.bootloader": "bootloader",
        "ro.build.fingerprint": "fingerprint",
        "ro.serialno": "ro_serialno",
    }

    info: dict[str, str] = {"adb_serial": device}
    for prop, key in props_map.items():
        info[key] = adb_shell_getprop(prop, device=device)

    # Orologio e kernel del dispositivo
    try:
        res_date = subprocess.run(
            ["adb", "-s", device, "shell", "date"],
            capture_output=True,
            text=True,
            timeout=10,
        )
        if res_date.stdout:
            info["device_datetime"] = res_date.stdout.strip()
    except Exception:
        info["device_datetime"] = ""

    try:
        res_uname = subprocess.run(
            ["adb", "-s", device, "shell", "uname", "-a"],
            capture_output=True,
            text=True,
            timeout=10,
        )
        if res_uname.stdout:
            info["kernel_uname"] = res_uname.stdout.strip()
    except Exception:
        info["kernel_uname"] = ""

    return info


def write_device_info_file(info: dict[str, str], outfile: Path):
    try:
        with outfile.open("w", encoding="utf-8", errors="replace") as f:
            f.write("Device information\n")
            f.write("==================\n")
            for key in sorted(info.keys()):
                f.write(f"{key}: {info.get(key, '')}\n")
    except Exception:
        pass


def run_adb_and_save(args, outfile: Path, device: str | None = None, text_mode=True):
    """
    Esegue adb con gli argomenti indicati, salva stdout in outfile
    e stderr in outfile + '.err'. Ritorna info su comando/percorsi.
    """
    cmd = ["adb"]
    if device is not None:
        cmd += ["-s", device]
    cmd += args

    print(f"[INFO] Eseguo: {' '.join(cmd)}")

    if text_mode:
        # Modalità testo: catturo bytes e decodifico esplicitamente in UTF-8
        proc = subprocess.run(cmd, capture_output=True)
        stdout_bytes = proc.stdout or b""
        stderr_bytes = proc.stderr or b""

        stdout_text = stdout_bytes.decode("utf-8", errors="replace")
        stderr_text = stderr_bytes.decode("utf-8", errors="replace")

        stderr_path = outfile.with_suffix(outfile.suffix + ".err")

        # Scrivo stdout come testo UTF-8
        try:
            with outfile.open("w", encoding="utf-8", errors="replace") as f:
                f.write(stdout_text)
        except Exception:
            pass

        # Scrivo stderr in file separato
        try:
            with stderr_path.open("w", encoding="utf-8", errors="replace") as f:
                if stderr_text:
                    f.write(stderr_text)
        except Exception:
            stderr_path = None

    else:
        # Modalità binaria (es. bugreport): scrivo stdout raw, stderr come testo
        proc = subprocess.run(cmd, capture_output=True)
        stderr_path = outfile.with_suffix(outfile.suffix + ".err")
        try:
            with outfile.open("wb") as f:
                if proc.stdout:
                    f.write(proc.stdout)
        except Exception:
            pass
        try:
            with stderr_path.open("w", encoding="utf-8", errors="replace") as f:
                if proc.stderr:
                    try:
                        f.write(proc.stderr.decode("utf-8", errors="replace"))
                    except Exception:
                        f.write(str(proc.stderr))
        except Exception:
            stderr_path = None

    if proc.returncode != 0:
        print(f"[ATTENZIONE] Comando fallito ({' '.join(cmd)}):")
        if proc.stderr:
            try:
                if isinstance(proc.stderr, bytes):
                    print(proc.stderr.decode("utf-8", errors="replace"))
                else:
                    print(proc.stderr)
            except Exception:
                pass

    return {
        "cmd": cmd,
        "returncode": proc.returncode,
        "stdout_path": outfile if outfile.exists() else None,
        "stderr_path": stderr_path if stderr_path and stderr_path.exists() else None,
    }


def is_binary_file(path: Path, blocksize: int = 512) -> bool:
    try:
        with path.open("rb") as f:
            chunk = f.read(blocksize)
            if b"\x00" in chunk:
                return True
            # Heuristica semplice per distinguere testo/binario
            text_chars = bytearray({7, 8, 9, 10, 12, 13, 27} | set(range(0x20, 0x100)))
            if not chunk:
                return False
            nontext = sum(1 for b in chunk if b not in text_chars)
            return nontext / max(1, len(chunk)) > 0.30
    except Exception:
        return False


def compute_sha256(path: Path, blocksize: int = 65536) -> str:
    h = hashlib.sha256()
    try:
        with path.open("rb") as f:
            while True:
                data = f.read(blocksize)
                if not data:
                    break
                h.update(data)
        return h.hexdigest()
    except Exception:
        return ""


def inspect_file(path: Path, skip_hash: bool = False, sample_lines: int = 0) -> dict:
    info = {
        "path": str(path),
        "size_bytes": None,
        "mtime": None,
        "sha256": None,
        "is_binary": None,
        "mimetype": None,
        "lines": None,
        "first_line": None,
        "last_line": None,
    }
    try:
        stat = path.stat()
        info["size_bytes"] = stat.st_size
        info["mtime"] = datetime.fromtimestamp(stat.st_mtime).isoformat(sep=" ")
        info["mimetype"] = mimetypes.guess_type(path.name)[0] or "unknown"
        info["is_binary"] = is_binary_file(path)
        info["sha256"] = "" if skip_hash else compute_sha256(path)

        if not info["is_binary"] and info["size_bytes"] > 0:
            # leggo prime / ultime righe in modo sicuro
            try:
                with path.open("r", encoding="utf-8", errors="replace") as f:
                    first = None
                    last = None
                    lines = 0
                    sample = []
                    for line in f:
                        if first is None:
                            first = line.rstrip("\n")
                        last = line.rstrip("\n")
                        if sample_lines and len(sample) < sample_lines:
                            sample.append(line.rstrip("\n"))
                        lines += 1
                    info["lines"] = lines
                    info["first_line"] = first
                    info["last_line"] = last
                    if sample_lines:
                        info["sample_lines"] = sample
            except Exception:
                pass
    except Exception:
        pass
    return info


def generate_summary_report(
    out_dir: Path,
    produced_files: list[Path],
    device: str | None,
    device_info: dict[str, str] | None,
    timestamp_readable: str,
    summary_format: str = "txt",
    failed_cmds: list[dict] | None = None,
    skip_hash: bool = False,
    sample_lines: int = 0,
) -> Path:
    if failed_cmds is None:
        failed_cmds = []

    safe_ts = timestamp_readable.replace(" ", "_").replace(":", "-")
    ext = "md" if summary_format == "md" else "txt"
    summary_path = out_dir / f"report_summary_{safe_ts}.{ext}"

    total_size = 0
    inspected = []
    for p in produced_files:
        if not p.exists():
            continue
        info = inspect_file(p, skip_hash=skip_hash, sample_lines=sample_lines)
        inspected.append(info)
        if info.get("size_bytes"):
            total_size += info["size_bytes"]

    if summary_format == "md":
        with summary_path.open("w", encoding="utf-8") as f:
            f.write("# Report summary\n\n")
            f.write(f"- Generated: **{timestamp_readable}**\n")
            f.write(f"- Device: **{device or 'unknown'}**\n")
            f.write(f"- Output dir: `{out_dir}`\n")
            f.write(f"- Files present: **{len(inspected)}**\n")
            f.write(f"- Total size: **{total_size} bytes**\n")

            if device_info:
                f.write("\n## Device info\n\n")
                for key in sorted(device_info.keys()):
                    value = device_info.get(key, "")
                    f.write(f"- **{key}**: `{value}`\n")

            if failed_cmds:
                f.write("\n## Failed commands\n\n")
                for c in failed_cmds:
                    f.write(f"- `{' '.join(c.get('cmd', []))}` (returncode: {c.get('returncode')})\n")

            f.write("\n## Files\n\n")
            for info in inspected:
                f.write(f"### `{info['path']}`\n\n")
                f.write(f"- Size: {info['size_bytes']} bytes\n")
                f.write(f"- Mtime: {info['mtime']}\n")
                f.write(f"- Mimetype: {info['mimetype']}\n")
                f.write(f"- Binary: {info['is_binary']}\n")
                if info.get("sha256"):
                    f.write(f"- SHA256: `{info['sha256']}`\n")
                if info.get("lines") is not None:
                    f.write(f"- Lines: {info['lines']}\n")
                if info.get("first_line") is not None:
                    f.write(f"- First line: `{info['first_line']}`\n")
                if info.get("last_line") is not None:
                    f.write(f"- Last line: `{info['last_line']}`\n")
                if info.get("sample_lines"):
                    f.write("\nSample:\n\n")
                    for s in info["sample_lines"]:
                        f.write(f"> {s}\n")
                f.write("\n")
    else:
        with summary_path.open("w", encoding="utf-8") as f:
            f.write("Report summary\n")
            f.write("================\n")
            f.write(f"Generated: {timestamp_readable}\n")
            f.write(f"Device: {device or 'unknown'}\n")
            f.write(f"Output dir: {out_dir}\n")
            f.write(f"Files present: {len(inspected)}\n")
            f.write(f"Total size: {total_size} bytes\n")

            if device_info:
                f.write("\nDevice info:\n")
                for key in sorted(device_info.keys()):
                    value = device_info.get(key, "")
                    f.write(f"- {key}: {value}\n")

            if failed_cmds:
                f.write("\nFailed commands:\n")
                for c in failed_cmds:
                    f.write(f"- cmd: {' '.join(c.get('cmd', []))}\n")
                    f.write(f"  returncode: {c.get('returncode')}\n")

            f.write("\nFiles:\n")
            for info in inspected:
                f.write(f"\n- Path: {info['path']}\n")
                f.write(f"  Size: {info['size_bytes']} bytes\n")
                f.write(f"  Mtime: {info['mtime']}\n")
                f.write(f"  Mimetype: {info['mimetype']}\n")
                f.write(f"  Binary: {info['is_binary']}\n")
                if info.get("sha256"):
                    f.write(f"  SHA256: {info['sha256']}\n")
                if info.get("lines") is not None:
                    f.write(f"  Lines: {info['lines']}\n")
                if info.get("first_line") is not None:
                    f.write(f"  First line: {info['first_line']}\n")
                if info.get("last_line") is not None:
                    f.write(f"  Last line: {info['last_line']}\n")
                if info.get("sample_lines"):
                    f.write("  Sample:\n")
                    for s in info["sample_lines"]:
                        f.write(f"    {s}\n")

    return summary_path


def main():
    parser = argparse.ArgumentParser(
        description="Estrazione log da dispositivo Android tramite adb."
    )
    parser.add_argument(
        "--out",
        "-o",
        type=str,
        default="android_logs",
        help="Cartella di output (default: ./android_logs)",
    )
    parser.add_argument(
        "--bugreport",
        action="store_true",
        help="Scarica anche un bugreport completo (può essere molto grande e lento).",
    )

    group = parser.add_mutually_exclusive_group()
    group.add_argument(
        "--summary",
        dest="summary",
        action="store_true",
        help="Genera un report riassuntivo (default)",
    )
    group.add_argument(
        "--no-summary",
        dest="summary",
        action="store_false",
        help="Non generare il report riassuntivo",
    )
    parser.set_defaults(summary=True)

    parser.add_argument(
        "--report-format",
        choices=["txt", "md"],
        default="txt",
        help="Formato del report riassuntivo (txt o md)",
    )
    parser.add_argument(
        "--su-dmesg",
        action="store_true",
        help="If dmesg fails, try running 'su -c dmesg' (requires rooted device).",
    )
    parser.add_argument(
        "--skip-hash",
        action="store_true",
        help="Skip SHA256 hashing of produced files (faster).",
    )
    parser.add_argument(
        "--sample-lines",
        type=int,
        default=0,
        help="Include first N lines of each text file in the summary (default 0).",
    )

    args = parser.parse_args()

    check_adb_available()
    device = get_connected_device()

    now = datetime.now()
    timestamp_files = now.strftime("%Y%m%d_%H%M%S")
    timestamp_readable = now.strftime("%Y-%m-%d_%H-%M-%S")

    device_info = collect_device_properties(device)
    safe_model = sanitize_for_path(device_info.get("model") or device_info.get("product_name") or "device")
    safe_brand = sanitize_for_path(device_info.get("manufacturer") or device_info.get("brand") or "brand")
    safe_serial = sanitize_for_path(device)

    base_out_dir = Path(args.out).expanduser().resolve()
    out_dir = base_out_dir / f"{safe_brand}_{safe_model}_{safe_serial}_{timestamp_files}"
    out_dir.mkdir(parents=True, exist_ok=True)
    print(f"[INFO] Cartella di output: {out_dir}")

    produced_files: list[Path] = []
    failed_cmds: list[dict] = []
    named_outputs: dict[str, Path] = {}

    device_info_path = out_dir / f"device_info_{timestamp_files}.txt"
    write_device_info_file(device_info, device_info_path)
    produced_files.append(device_info_path)
    named_outputs["device_info"] = device_info_path

    tasks = [
        {"name": "logcat_main", "args": ["logcat", "-d", "-v", "time"], "text_mode": True},
        {"name": "logcat_events", "args": ["logcat", "-d", "-b", "events", "-v", "time"], "text_mode": True},
        {"name": "logcat_radio", "args": ["logcat", "-d", "-b", "radio", "-v", "time"], "text_mode": True},
        {"name": "logcat_crash", "args": ["logcat", "-d", "-b", "crash", "-v", "time"], "text_mode": True},
        {"name": "getprop", "args": ["shell", "getprop"], "text_mode": True},
        {"name": "dmesg", "args": ["shell", "dmesg"], "text_mode": True},
        {"name": "dumpsys_battery", "args": ["shell", "dumpsys", "battery"], "text_mode": True},
        {"name": "dumpsys_power", "args": ["shell", "dumpsys", "power"], "text_mode": True},
        {"name": "dumpsys_connectivity", "args": ["shell", "dumpsys", "connectivity"], "text_mode": True},
        {"name": "dumpsys_wifi", "args": ["shell", "dumpsys", "wifi"], "text_mode": True},
        {"name": "dumpsys_activity", "args": ["shell", "dumpsys", "activity", "activities"], "text_mode": True},
        {"name": "dumpsys_package", "args": ["shell", "dumpsys", "package"], "text_mode": True},
        {"name": "packages_all", "args": ["shell", "pm", "list", "packages", "-f"], "text_mode": True},
        {"name": "packages_third_party", "args": ["shell", "pm", "list", "packages", "-3", "-f"], "text_mode": True},
        {"name": "ps_full", "args": ["shell", "ps", "-A", "-o", "user,pid,ppid,pcpu,pmem,args"], "text_mode": True},
        {"name": "netstat", "args": ["shell", "netstat", "-anp"], "text_mode": True},
        {"name": "ip_addr", "args": ["shell", "ip", "addr", "show"], "text_mode": True},
        {"name": "ip_route", "args": ["shell", "ip", "route", "show"], "text_mode": True},
        {"name": "df", "args": ["shell", "df", "-h"], "text_mode": True},
        {"name": "mounts", "args": ["shell", "cat", "/proc/mounts"], "text_mode": True},
        {"name": "settings_system", "args": ["shell", "settings", "list", "system"], "text_mode": True},
        {"name": "settings_global", "args": ["shell", "settings", "list", "global"], "text_mode": True},
        {"name": "settings_secure", "args": ["shell", "settings", "list", "secure"], "text_mode": True},
    ]

    for task in tasks:
        outfile = out_dir / f"{task['name']}_{timestamp_files}.txt"
        res = run_adb_and_save(
            task["args"],
            outfile,
            device=device,
            text_mode=task.get("text_mode", True),
        )
        produced_files.append(outfile)
        named_outputs[task["name"]] = outfile
        if res["returncode"] != 0:
            failed_cmds.append(res)

        if task["name"] == "dmesg" and res["returncode"] != 0 and args.su_dmesg:
            fallback_path = out_dir / f"dmesg_su_{timestamp_files}.txt"
            print("[INFO] dmesg failed; trying 'su -c dmesg' (requires root)...")
            res_dmesg_su = run_adb_and_save(
                ["shell", "su", "-c", "dmesg"],
                fallback_path,
                device=device,
                text_mode=True,
            )
            produced_files.append(fallback_path)
            named_outputs["dmesg_su"] = fallback_path
            if res_dmesg_su["returncode"] != 0:
                failed_cmds.append(res_dmesg_su)

    bug_file = None
    if args.bugreport:
        bug_file = out_dir / f"bugreport_{timestamp_files}.zip"
        print("[INFO] Genero bugreport completo (può richiedere un po' di tempo)...")
        res_bug = run_adb_and_save(
            ["bugreport", str(bug_file)],
            bug_file,
            device=device,
            text_mode=False,
        )
        produced_files.append(bug_file)
        named_outputs["bugreport"] = bug_file
        if res_bug["returncode"] != 0:
            failed_cmds.append(res_bug)

    summary_path = None
    if args.summary:
        summary_path = generate_summary_report(
            out_dir=out_dir,
            produced_files=produced_files,
            device=device,
            device_info=device_info,
            timestamp_readable=timestamp_readable,
            summary_format=args.report_format,
            failed_cmds=failed_cmds,
            skip_hash=args.skip_hash,
            sample_lines=args.sample_lines,
        )
        print(f"[INFO] Report riassuntivo generato: {summary_path}")

    print("\n[OK] Estrazione completata.")
    print(f" - Cartella:         {out_dir}")
    print(f" - Device info:      {device_info_path}")
    if "logcat_main" in named_outputs:
        print(f" - Logcat principale:{named_outputs['logcat_main']}")
    if "dmesg" in named_outputs:
        print(f" - dmesg:            {named_outputs['dmesg']}")
    if bug_file is not None:
        print(f" - Bugreport:        {bug_file}")
    if summary_path is not None:
        print(f" - Summary report:   {summary_path}")
    print("\nApri i file .txt con un editor (Notepad++, VS Code, ecc.) per l'analisi.")


if __name__ == "__main__":
    main()
