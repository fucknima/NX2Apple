"""Windows Defender exclusion helper for NX2Apple / NS Port Builder.

Real-time scanning (`WdFilter.sys` / `MsMpEng.exe`) intercepts every short-lived shader
compiler subprocess (`dmsh_xlate.exe`, `spirv-cross.exe`, `metal.exe`, `air-lld.exe`,
`metallib.exe`) and every multi-gigabyte SQLite / RomFS image write (`sh/cache/cas.db`,
`b-<chain>.img.part`) during the 99% shader packaging step, throttling disk I/O to a few
MB/s and stalling at 99% for minutes.

This module collects the exact build directories and compiler processes and submits them
in a single elevated PowerShell call (`Add-MpPreference`) after the user confirms the
native Windows UAC prompt.
"""
from __future__ import annotations

import base64
import json
import ntpath
import os
import subprocess
import sys
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable

from . import toolchain as tc

#: Compiler and build tool executables spawned thousands of times during a build.
#: Excluding these processes lets Defender skip scanning temporary `.spv`, `.air`,
#: `.metallib`, and `.o` files they create under `%TEMP%` without excluding `%TEMP%` itself.
COMPILER_PROCESS_NAMES: tuple[str, ...] = (
    'dmsh_xlate.exe',
    'spirv-cross.exe',
    'glslangValidator.exe',
    'metal.exe',
    'metal-nt.exe',
    'air-lld.exe',
    'metallib.exe',
    'clang.exe',
    'clang++.exe',
    'ld64.lld.exe',
    'ld.lld.exe',
    'llvm-ar.exe',
    'llvm-objcopy.exe',
    'zstd.exe',
)

#: Windows error code returned when the user clicks "No" / Cancel on the UAC prompt.
ERROR_CANCELLED = 1223


@dataclass
class DefenderResult:
    ok: bool
    cancelled: bool = False
    added_paths: list[str] = field(default_factory=list)
    added_processes: list[str] = field(default_factory=list)
    error: str = ''


def app_data_root() -> Path:
    """`%LOCALAPPDATA%\\NS Port Builder` — holds `tools/`, `git/`, `logs/`, and `shell/`."""
    return tc.tools_dir().parent


def state_file_path() -> Path:
    """Where confirmed Defender exclusions are recorded locally."""
    return app_data_root() / 'defender_exclusions.json'


def _is_win_abs(s: str) -> bool:
    """True when `s` is a Windows drive-letter path (`C:\\...`, `D:/...`) or UNC path (`\\\\server\\share`)."""
    if len(s) >= 2 and s[0].isalpha() and s[1] == ':':
        return True
    return s.startswith('\\\\')


def _norm_win_path(p: str | Path) -> str:
    """Normalize a path for stable comparison while preserving readable casing across OSes."""
    s = os.fspath(p).strip()
    if not s:
        return ''
    if _is_win_abs(s):
        if len(s) == 2 and s[1] == ':':
            s += '\\'
        return ntpath.normpath(s)
    return os.path.normpath(os.path.abspath(s))


def _norm_key(p: str | Path) -> str:
    """Case-insensitive normalized key for Windows path deduplication and prefix checks."""
    norm = _norm_win_path(p)
    return norm.replace('/', '\\').rstrip('\\').lower() if norm else ''


def is_safe_exclusion_dir(path: str | Path) -> bool:
    """Refuse drive roots, system directories, and broad user profile folders (`Downloads`, `Desktop`).

    Excluding `C:\\`, `C:\\Users\\Alice`, or `C:\\Users\\Alice\\Downloads` would weaken
    protection for unrelated files downloaded from a browser. Specific build folders
    such as `C:\\Users\\Alice\\Downloads\\01007ef00011e000_build` or a dedicated
    `D:\\SwitchGames` folder are allowed.
    """
    norm = _norm_win_path(path)
    if not norm:
        return False
    clean = norm.replace('/', '\\').rstrip('\\')
    if not clean:
        return False
    if _is_win_abs(norm):
        _drive, tail = ntpath.splitdrive(clean)
    else:
        _drive, tail = os.path.splitdrive(clean)
    if not tail or tail in ('\\', '/'):
        return False
    parts = [seg.lower() for seg in tail.strip('\\/').split('\\') if seg]
    if not parts:
        return False

    # Reject Windows system / program directories and generic Users profile folders on any drive
    if parts[0] in ('windows', 'program files', 'program files (x86)', 'programdata', '$recycle.bin', 'system volume information'):
        return False
    if parts == ['users'] or parts == ['users', 'public']:
        return False
    if len(parts) == 2 and parts[0] == 'users':
        return False
    if len(parts) == 3 and parts[0] == 'users' and parts[2] in ('desktop', 'downloads', 'documents', 'appdata'):
        return False
    if len(parts) == 4 and parts[0] == 'users' and parts[2] == 'appdata' and parts[3] in ('local', 'roaming', 'locallow'):
        return False
    if len(parts) == 5 and parts[0] == 'users' and parts[2] == 'appdata' and parts[3] == 'local' and parts[4] == 'temp':
        return False

    low_clean = clean.lower()
    home = _norm_win_path(Path.home()).replace('/', '\\').rstrip('\\').lower()
    unsafe_exact = {
        home,
        f'{home}\\desktop',
        f'{home}\\downloads',
        f'{home}\\documents',
        f'{home}\\appdata',
        f'{home}\\appdata\\local',
        f'{home}\\appdata\\roaming',
        f'{home}\\appdata\\locallow',
        f'{home}\\appdata\\local\\temp',
    }
    for env_key in ('SYSTEMROOT', 'WINDIR', 'USERPROFILE', 'PUBLIC', 'TEMP', 'TMP', 'APPDATA', 'LOCALAPPDATA'):
        val = os.environ.get(env_key, '').strip()
        if val:
            unsafe_exact.add(_norm_win_path(val).replace('/', '\\').rstrip('\\').lower())
    if low_clean in unsafe_exact:
        return False
    return True


def is_path_covered(target: str | Path, excluded_paths: Iterable[str | Path]) -> bool:
    """True when `target` itself or one of its parent directories is in `excluded_paths`.

    Microsoft Defender folder exclusions apply recursively to all subfolders, so an
    exclusion on `D:\\SwitchGames` already covers `D:\\SwitchGames\\01007ef00011e000_build`.
    """
    target_key = _norm_key(target)
    if not target_key:
        return True
    for raw in excluded_paths:
        ex_key = _norm_key(raw)
        if not ex_key:
            continue
        if target_key == ex_key or target_key.startswith(ex_key + '\\'):
            return True
    return False


_STATE_CACHE: tuple[tuple[str, int, float], tuple[list[str], list[str]]] | None = None


def load_recorded_state() -> tuple[list[str], list[str]]:
    """Return `(paths, processes)` previously confirmed and saved in `defender_exclusions.json`."""
    global _STATE_CACHE
    p = state_file_path()
    try:
        st = p.stat()
        sig = (str(p), st.st_size, st.st_mtime)
    except OSError:
        sig = (str(p), -1, -1.0)
        if _STATE_CACHE is not None and _STATE_CACHE[0] == sig:
            return list(_STATE_CACHE[1][0]), list(_STATE_CACHE[1][1])
        _STATE_CACHE = (sig, ([], []))
        return [], []

    if _STATE_CACHE is not None and _STATE_CACHE[0] == sig:
        return list(_STATE_CACHE[1][0]), list(_STATE_CACHE[1][1])

    try:
        data = json.loads(p.read_text(encoding='utf-8'))
    except (OSError, ValueError):
        return [], []
    if not isinstance(data, dict):
        return [], []
    paths = [str(x) for x in data.get('paths', ()) if isinstance(x, str) and x.strip()]
    procs = [str(x) for x in data.get('processes', ()) if isinstance(x, str) and x.strip()]
    _STATE_CACHE = (sig, (paths, procs))
    return list(paths), list(procs)


def save_recorded_state(paths: Iterable[str], processes: Iterable[str]) -> None:
    """Merge and persist confirmed exclusions to `defender_exclusions.json`."""
    global _STATE_CACHE
    old_paths, old_procs = load_recorded_state()
    merged_paths: list[str] = []
    seen_p: set[str] = set()
    for item in [*old_paths, *paths]:
        norm = _norm_win_path(item)
        k = _norm_key(norm)
        if norm and k and k not in seen_p:
            seen_p.add(k)
            merged_paths.append(norm)

    merged_procs: list[str] = []
    seen_proc: set[str] = set()
    for proc in [*old_procs, *processes]:
        s = str(proc).strip()
        k = s.replace('/', '\\').lower()
        if s and k not in seen_proc:
            seen_proc.add(k)
            merged_procs.append(s)

    st_file = state_file_path()
    try:
        st_file.parent.mkdir(parents=True, exist_ok=True)
        tmp = st_file.with_suffix(f'.tmp-{os.getpid()}')
        tmp.write_text(
            json.dumps({'paths': merged_paths, 'processes': merged_procs}, indent=2, ensure_ascii=False),
            encoding='utf-8',
        )
        os.replace(tmp, st_file)
        st = st_file.stat()
        _STATE_CACHE = ((str(st_file), st.st_size, st.st_mtime), (list(merged_paths), list(merged_procs)))
    except OSError:
        _STATE_CACHE = None


def collect_exclusions(
    *,
    games_folder: str = '',
    work_dir: str = '',
    out_dir: str = '',
    base_dir: str = '',
    shell_cache_dir: str = '',
    repo_dir: str = '',
    app_dir: str = '',
) -> tuple[list[str], list[str]]:
    """Build the deduplicated `(folder_paths, compiler_processes)` list to exclude.

    - Always includes `%LOCALAPPDATA%\\NS Port Builder` (holds the app-managed Python,
      LLVM-MinGW, .NET, iPhoneOS SDK, and shell cache).
    - Includes the app installation / checkout directory, custom shell cache, library
      games folder, output folder, and active `<tid>_build` work folder when safe.
    - When `base_dir` is a broad directory like `Downloads` or `Desktop`, `is_safe_exclusion_dir`
      skips `base_dir` while still allowing the specific `<tid>_build` `work_dir` inside it.
    """
    candidates: list[str] = [str(app_data_root())]

    if app_dir:
        candidates.append(app_dir)
    elif getattr(sys, 'frozen', False):
        candidates.append(str(Path(sys.executable).resolve().parent))

    if repo_dir:
        candidates.append(repo_dir)
    if shell_cache_dir:
        candidates.append(shell_cache_dir)
    if games_folder:
        candidates.append(games_folder)
    if out_dir:
        candidates.append(out_dir)
    if base_dir:
        candidates.append(base_dir)
    if work_dir:
        candidates.append(work_dir)

    folders: list[str] = []
    seen_keys: set[str] = set()
    for raw in candidates:
        if not raw or not str(raw).strip():
            continue
        norm = _norm_win_path(raw)
        if not is_safe_exclusion_dir(norm):
            continue
        k = _norm_key(norm)
        if not k or k in seen_keys:
            continue
        if is_path_covered(norm, folders):
            continue
        # Remove any narrower child folders already in `folders` if `norm` is their parent
        folders = [existing for existing in folders if not is_path_covered(existing, [norm])]
        seen_keys = {_norm_key(x) for x in folders}
        seen_keys.add(k)
        folders.append(norm)

    # Compiler processes + the app's own dedicated Python / .NET binaries under tools/
    t_dir = tc.tools_dir()
    own_py = _norm_win_path(t_dir / 'python' / 'python.exe')
    own_dotnet = _norm_win_path(t_dir / 'dotnet' / 'dotnet.exe')
    processes: list[str] = []
    seen_procs: set[str] = set()
    for proc in (own_py, own_dotnet, *COMPILER_PROCESS_NAMES):
        if not proc:
            continue
        k = proc.replace('/', '\\').lower()
        if k not in seen_procs:
            seen_procs.add(k)
            processes.append(proc)

    return folders, processes


def exclusions_status(
    *,
    games_folder: str = '',
    work_dir: str = '',
    out_dir: str = '',
    base_dir: str = '',
    shell_cache_dir: str = '',
    repo_dir: str = '',
    app_dir: str = '',
) -> tuple[str, list[str], list[str]]:
    """Return `(status, target_folders, target_processes)` where `status` is:

    - `'ready'`: every target folder and compiler process is already covered
    - `'partial'`: some exclusions were added before, but a newly chosen folder (e.g. a new
      games folder or build work_dir) is not covered yet
    - `'needed'`: no exclusions have been recorded yet
    """
    folders, procs = collect_exclusions(
        games_folder=games_folder,
        work_dir=work_dir,
        out_dir=out_dir,
        base_dir=base_dir,
        shell_cache_dir=shell_cache_dir,
        repo_dir=repo_dir,
        app_dir=app_dir,
    )
    rec_paths, rec_procs = load_recorded_state()
    if not rec_paths and not rec_procs:
        return 'needed', folders, procs

    rec_proc_keys = {p.replace('/', '\\').lower() for p in rec_procs}
    all_procs_ok = all(p.replace('/', '\\').lower() in rec_proc_keys for p in procs)
    all_paths_ok = all(is_path_covered(f, rec_paths) for f in folders)
    if all_paths_ok and all_procs_ok:
        return 'ready', folders, procs
    return 'partial', folders, procs


def encode_powershell_command(script: str) -> str:
    """Encode a PowerShell script as UTF-16LE Base64 for `-EncodedCommand`."""
    return base64.b64encode(script.encode('utf-16-le')).decode('ascii')


def build_inner_elevation_script(payload_json_path: str) -> str:
    """Build the elevated PowerShell script that reads `payload_json_path` and calls `Add-MpPreference`.

    All folder paths and process names are read from the UTF-8 JSON file on disk rather than
    interpolated into the command line, preventing any quoting, codepage, or injection issues.
    """
    escaped_payload = str(payload_json_path).replace("'", "''")
    return (
        "$ErrorActionPreference = 'Stop'\n"
        f"$payloadPath = '{escaped_payload}'\n"
        "$cfg = Get-Content -LiteralPath $payloadPath -Raw -Encoding UTF8 | ConvertFrom-Json\n"
        "try {\n"
        "    $paths = @($cfg.paths | Where-Object { $_ -ne $null -and $_ -ne '' })\n"
        "    $procs = @($cfg.processes | Where-Object { $_ -ne $null -and $_ -ne '' })\n"
        "    if ($paths.Count -gt 0) {\n"
        "        Add-MpPreference -ExclusionPath ([string[]]$paths) -ErrorAction Stop\n"
        "    }\n"
        "    if ($procs.Count -gt 0) {\n"
        "        Add-MpPreference -ExclusionProcess ([string[]]$procs) -ErrorAction Stop\n"
        "    }\n"
        "    @{ ok = $true; error = '' } | ConvertTo-Json -Compress | "
        "Set-Content -LiteralPath $cfg.result_path -Encoding UTF8\n"
        "    exit 0\n"
        "} catch {\n"
        "    $msg = if ($_.Exception) { $_.Exception.Message } else { $_.ToString() }\n"
        "    @{ ok = $false; error = $msg } | ConvertTo-Json -Compress | "
        "Set-Content -LiteralPath $cfg.result_path -Encoding UTF8\n"
        "    exit 1\n"
        "}\n"
    )


def build_outer_launcher_script(inner_encoded_command: str) -> str:
    """Build the non-elevated PowerShell wrapper that triggers the Windows UAC `RunAs` prompt."""
    safe_b64 = str(inner_encoded_command).replace("'", '')
    return (
        "$ErrorActionPreference = 'Stop'\n"
        "try {\n"
        "    $argList = @('-NoProfile', '-NonInteractive', '-WindowStyle', 'Hidden', "
        f"'-ExecutionPolicy', 'Bypass', '-EncodedCommand', '{safe_b64}')\n"
        "    $p = Start-Process -FilePath 'powershell.exe' -Verb RunAs -WindowStyle Hidden "
        "-Wait -PassThru -ArgumentList $argList\n"
        "    if ($null -eq $p) { exit 1 }\n"
        "    exit $p.ExitCode\n"
        "} catch {\n"
        "    $errText = $_.ToString()\n"
        "    if (($_.Exception -and $_.Exception.NativeErrorCode -eq 1223) -or "
        "($_.Exception.InnerException -and $_.Exception.InnerException.NativeErrorCode -eq 1223) -or "
        "($errText -match '1223|canceled|cancelled|取消|abgebrochen|annul|avbruten')) {\n"
        f"        exit {ERROR_CANCELLED}\n"
        "    }\n"
        "    [Console]::Error.WriteLine($errText)\n"
        "    exit 2\n"
        "}\n"
    )


def apply_exclusions(
    paths: Iterable[str],
    processes: Iterable[str],
    *,
    runner=subprocess.run,
) -> DefenderResult:
    """Prompt the user via Windows UAC and register `paths` and `processes` in Defender.

    Runs synchronously (call from a worker thread, never on the UI thread).
    """
    clean_paths = [_norm_win_path(p) for p in paths if p and is_safe_exclusion_dir(p)]
    clean_procs = [str(p).strip() for p in processes if p and str(p).strip()]
    if not clean_paths and not clean_procs:
        return DefenderResult(ok=True, added_paths=[], added_processes=[])

    base_dir = app_data_root()
    try:
        base_dir.mkdir(parents=True, exist_ok=True)
        work_td = tempfile.mkdtemp(prefix='defender-', dir=str(base_dir))
    except OSError:
        work_td = tempfile.mkdtemp(prefix='nspb-defender-')

    payload_file = Path(work_td) / 'payload.json'
    result_file = Path(work_td) / 'result.json'
    try:
        payload = {
            'paths': clean_paths,
            'processes': clean_procs,
            'result_path': str(result_file),
        }
        payload_file.write_text(json.dumps(payload, ensure_ascii=False), encoding='utf-8')
        inner_script = build_inner_elevation_script(str(payload_file))
        inner_b64 = encode_powershell_command(inner_script)
        outer_script = build_outer_launcher_script(inner_b64)
        outer_b64 = encode_powershell_command(outer_script)

        kwargs: dict = {}
        if os.name == 'nt':
            kwargs['creationflags'] = getattr(subprocess, 'CREATE_NO_WINDOW', 0x08000000)

        proc = runner(
            [
                'powershell.exe',
                '-NoProfile',
                '-NonInteractive',
                '-WindowStyle',
                'Hidden',
                '-ExecutionPolicy',
                'Bypass',
                '-EncodedCommand',
                outer_b64,
            ],
            capture_output=True,
            text=True,
            encoding='utf-8',
            errors='replace',
            **kwargs,
        )

        if proc.returncode == ERROR_CANCELLED:
            return DefenderResult(
                ok=False,
                cancelled=True,
                added_paths=clean_paths,
                added_processes=clean_procs,
            )

        if result_file.is_file():
            try:
                res_obj = json.loads(result_file.read_text(encoding='utf-8-sig'))
            except (OSError, ValueError):
                res_obj = {}
            if isinstance(res_obj, dict) and res_obj.get('ok') is True and proc.returncode == 0:
                save_recorded_state(clean_paths, clean_procs)
                return DefenderResult(
                    ok=True,
                    added_paths=clean_paths,
                    added_processes=clean_procs,
                )
            err_msg = str(res_obj.get('error') or '').strip() if isinstance(res_obj, dict) else ''
            stderr = (proc.stderr or proc.stdout or '').strip()
            return DefenderResult(
                ok=False,
                added_paths=clean_paths,
                added_processes=clean_procs,
                error=err_msg or stderr or f'exit code {proc.returncode}',
            )

        stderr = (proc.stderr or proc.stdout or '').strip()
        return DefenderResult(
            ok=False,
            added_paths=clean_paths,
            added_processes=clean_procs,
            error=stderr or f'elevated PowerShell exited with code {proc.returncode} without writing result.json',
        )
    except OSError as e:
        return DefenderResult(
            ok=False,
            added_paths=clean_paths,
            added_processes=clean_procs,
            error=str(e),
        )
    finally:
        for f in (payload_file, result_file):
            try:
                if f.exists():
                    f.unlink()
            except OSError:
                pass
        try:
            os.rmdir(work_td)
        except OSError:
            pass
