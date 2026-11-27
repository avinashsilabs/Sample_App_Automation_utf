"""Discover Silicon Labs toolchain binaries across platforms and build session env."""

from __future__ import annotations

import os
import platform
import shutil
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional

IS_WINDOWS = os.name == "nt"
IS_MACOS = platform.system() == "Darwin"


def _exe(name: str) -> str:
    """Executable file name for the current platform."""
    return f"{name}.exe" if IS_WINDOWS else name


def _script(name: str) -> str:
    """Launcher script name (SLC ships slc.bat on Windows, slc elsewhere)."""
    return f"{name}.bat" if IS_WINDOWS else name


def _silabs_roots() -> List[Path]:
    """SLT install roots, in priority order, for the current platform."""
    candidates: List[Path] = [Path.home() / ".silabs" / "slt" / "installs"]

    slt_root = os.environ.get("SILABS_SLT_ROOT", "").strip()
    if slt_root:
        candidates.insert(0, Path(slt_root).expanduser())

    if IS_WINDOWS:
        localappdata = os.environ.get("LOCALAPPDATA", "").strip()
        if localappdata:
            candidates.append(Path(localappdata) / "Silabs" / "slt" / "installs")
        candidates.append(Path("C:/Silabs/slt/installs"))
    elif IS_MACOS:
        candidates.append(
            Path.home() / "Library" / "Application Support" / "Silabs" / "slt" / "installs"
        )
        candidates.append(Path("/opt/silabs/slt/installs"))
    else:
        candidates.append(Path("/opt/silabs/slt/installs"))
        candidates.append(Path("/usr/local/silabs/slt/installs"))

    roots: List[Path] = []
    for candidate in candidates:
        try:
            if candidate.is_dir() and candidate not in roots:
                roots.append(candidate)
        except (OSError, ValueError):
            continue
    return roots


def _conan_dirs() -> List[Path]:
    return [r / "conan" / "p" for r in _silabs_roots() if (r / "conan" / "p").is_dir()]


def _archive_dirs() -> List[Path]:
    return [r / "archive" for r in _silabs_roots() if (r / "archive").is_dir()]


_slt_cache: Dict[str, Optional[Path]] = {}


def _slt_where(name: str) -> Optional[Path]:
    """Ask the SLT CLI where a package is installed."""
    if name in _slt_cache:
        return _slt_cache[name]

    slt = shutil.which("slt")
    if not slt:
        _slt_cache[name] = None
        return None
    try:
        result = subprocess.run(
            [slt, "where", name], capture_output=True, text=True, timeout=15
        )
        lines = (result.stdout or "").strip().splitlines()
        resolved = None
        if result.returncode == 0 and lines:
            path = Path(lines[0].strip())
            if path.exists():
                resolved = path.resolve()
        _slt_cache[name] = resolved
        return resolved
    except (OSError, subprocess.SubprocessError):
        _slt_cache[name] = None
        return None


def _conan_packages(prefix: str) -> List[Path]:
    """Conan package dirs matching prefix, newest name first."""
    packages: List[Path] = []
    for conan in _conan_dirs():
        packages.extend(
            sorted(conan.glob(f"{prefix}*"), key=lambda p: p.name, reverse=True)
        )
    return packages


def _find_in_conan(prefix: str, *rel_paths: str) -> Optional[Path]:
    """First existing file under any Conan package matching prefix."""
    for pkg in _conan_packages(prefix):
        for rel in rel_paths:
            candidate = pkg / rel
            if candidate.is_file():
                return candidate.resolve()
    return None


def slt_package_dirs(prefix: str = "") -> List[Path]:
    """Installed SLT package roots (Conan packages and archives) matching prefix."""
    dirs: List[Path] = []

    def add(path: Path) -> None:
        resolved = path.resolve()
        if resolved.is_dir() and resolved not in dirs:
            dirs.append(resolved)

    for pkg in _conan_packages(prefix):
        # Conan packages keep payload under <pkg>/p
        add(pkg / "p" if (pkg / "p").is_dir() else pkg)
    for archive in _archive_dirs():
        for entry in sorted(archive.glob(f"{prefix}*"), reverse=True):
            if entry.is_dir():
                add(entry)
    return dirs


def _find_tool_root_in_conan(prefix: str, marker: str) -> Optional[Path]:
    """Conan package root that contains marker (e.g. bin/clang)."""
    for pkg in _conan_packages(prefix):
        for rel in ("p", "."):
            root = (pkg / rel).resolve()
            if (root / marker).is_file():
                return root
    return None


def _first_file(base: Optional[Path], rel_paths) -> Optional[Path]:
    if not base:
        return None
    for rel in rel_paths:
        candidate = base / rel
        if candidate.is_file():
            return candidate.resolve()
    return None


def _which(name: str) -> Optional[Path]:
    found = shutil.which(name)
    return Path(found).resolve() if found else None


_JAVA_RELS = (
    f"bin/{_exe('java')}",
    f"jre/bin/{_exe('java')}",
    f"Contents/Home/bin/{_exe('java')}",
)


def find_java() -> Optional[Path]:
    java = _first_file(_slt_where("java"), _JAVA_RELS)
    if java:
        return java

    for archive in _archive_dirs():
        for entry in sorted(archive.glob("java*"), reverse=True):
            if not entry.is_dir():
                continue
            java = _first_file(entry, _JAVA_RELS)
            if java:
                return java
            # SLT nests a platform folder, e.g. java21-v21/win32.x86_64_21/jre/bin
            for sub in sorted(entry.iterdir(), reverse=True):
                if sub.is_dir():
                    java = _first_file(sub, _JAVA_RELS)
                    if java:
                        return java

    java_home = os.environ.get("JAVA_HOME", "").strip()
    if java_home:
        java = _first_file(Path(java_home), _JAVA_RELS)
        if java:
            return java
    return _which("java")


def find_slc() -> Optional[Path]:
    launcher = _script("slc")
    for archive in _archive_dirs():
        for pattern in ("slc-cli-v*", "slc_cli_base-v*", "slc-cli*"):
            for entry in sorted(archive.glob(pattern), reverse=True):
                found = _first_file(entry, (f"slc_cli/{launcher}", launcher))
                if found:
                    return found

    found = _find_in_conan("slc", f"p/slc_cli/{launcher}", f"slc_cli/{launcher}")
    if found:
        return found
    return _which("slc")


def find_cmake() -> Optional[Path]:
    cmake = _exe("cmake")
    found = _first_file(_slt_where("cmake"), (f"bin/{cmake}", cmake))
    if found:
        return found

    found = _find_in_conan("cmake", f"p/bin/{cmake}", f"bin/{cmake}")
    if found:
        return found

    for base in _system_tool_roots("CMake"):
        found = _first_file(base, (f"bin/{cmake}", cmake))
        if found:
            return found
    return _which("cmake")


def find_ninja() -> Optional[Path]:
    ninja = _exe("ninja")
    found = _first_file(_slt_where("ninja"), (ninja, f"bin/{ninja}", f"p/{ninja}"))
    if found:
        return found

    found = _find_in_conan("ninja", f"p/{ninja}", f"p/bin/{ninja}", ninja)
    if found:
        return found
    return _which("ninja")


def find_make() -> Optional[Path]:
    make = _exe("make")
    found = _first_file(_slt_where("make"), (make, f"bin/{make}", f"p/bin/{make}"))
    if found:
        return found

    found = _find_in_conan("make", f"p/bin/{make}", f"bin/{make}", make)
    if found:
        return found
    return _which("make") or _which("mingw32-make")


_COMMANDER_RELS = (
    _exe("commander"),
    f"bin/{_exe('commander')}",
    "Commander.app/Contents/MacOS/commander",
    "Contents/MacOS/commander",
)


def find_commander() -> Optional[Path]:
    for archive in _archive_dirs():
        for folder in ("Simplicity Commander", "commander"):
            found = _first_file(archive / folder, _COMMANDER_RELS)
            if found:
                return found

    found = _first_file(_slt_where("commander"), _COMMANDER_RELS)
    if found:
        return found

    found = _find_in_conan(
        "commander", f"p/{_exe('commander')}", _exe("commander")
    )
    if found:
        return found
    return _which("commander")


def _system_tool_roots(tool: str) -> List[Path]:
    """Non-SLT install locations to probe, per platform."""
    if IS_WINDOWS:
        return [
            Path(f"C:/Program Files/{tool}"),
            Path(f"C:/Program Files (x86)/{tool}"),
        ]
    if IS_MACOS:
        return [
            Path(f"/Applications/{tool}.app/Contents"),
            Path("/opt/homebrew"),
            Path("/usr/local"),
        ]
    return [Path("/usr"), Path("/usr/local"), Path("/opt")]


def find_gcc_root() -> Optional[Path]:
    marker = f"bin/{_exe('arm-none-eabi-gcc')}"

    slt_path = _slt_where("gcc-arm-none-eabi")
    if slt_path:
        for rel in (".", "p"):
            root = (slt_path / rel).resolve()
            if (root / marker).is_file():
                return root

    root = _find_tool_root_in_conan("gcc", marker)
    if root:
        return root

    for base in _system_tool_roots("GNU Arm Embedded Toolchain"):
        if not base.is_dir():
            continue
        if (base / marker).is_file():
            return base.resolve()
        try:
            for sub in sorted(base.iterdir(), reverse=True):
                if sub.is_dir() and (sub / marker).is_file():
                    return sub.resolve()
        except OSError:
            continue

    gcc = _which("arm-none-eabi-gcc")
    return gcc.parent.parent if gcc else None


def find_llvm_root() -> Optional[Path]:
    marker = f"bin/{_exe('clang')}"

    for name in ("arm-toolchain-for-embedded", "llvm-arm-toolchain-for-embedded"):
        slt_path = _slt_where(name)
        if not slt_path:
            continue
        for rel in (".", "p"):
            root = (slt_path / rel).resolve()
            if (root / marker).is_file():
                return root

    root = _find_tool_root_in_conan("llvm", marker)
    if root:
        return root

    clang = _which("clang")
    return clang.parent.parent if clang else None


@dataclass
class ToolPaths:
    slc: Optional[Path] = None
    cmake: Optional[Path] = None
    ninja: Optional[Path] = None
    make: Optional[Path] = None
    commander: Optional[Path] = None
    java: Optional[Path] = None
    gcc_root: Optional[Path] = None
    llvm_root: Optional[Path] = None
    path_dirs: List[str] = field(default_factory=list)
    env_vars: Dict[str, str] = field(default_factory=dict)

    def missing(self, toolchain: str = "gcc") -> List[str]:
        """Names of tools required for a build that were not found."""
        required = {
            "slc": self.slc,
            "cmake": self.cmake,
            "ninja": self.ninja,
            "commander": self.commander,
            "java": self.java,
        }
        if toolchain == "llvm_lto":
            required["llvm"] = self.llvm_root
        else:
            required["gcc"] = self.gcc_root
        return [name for name, value in required.items() if not value]

    def as_dict(self) -> dict:
        return {
            "slc": str(self.slc) if self.slc else None,
            "cmake": str(self.cmake) if self.cmake else None,
            "ninja": str(self.ninja) if self.ninja else None,
            "make": str(self.make) if self.make else None,
            "commander": str(self.commander) if self.commander else None,
            "java": str(self.java) if self.java else None,
            "gcc": str(self.gcc_root) if self.gcc_root else None,
            "llvm": str(self.llvm_root) if self.llvm_root else None,
            "path_dirs": self.path_dirs,
            "env_vars": self.env_vars,
            "platform": platform.system(),
            "missing": self.missing("gcc"),
            "ready": not self.missing("gcc"),
            "llvm_ready": not self.missing("llvm_lto"),
        }


_cached_tools: Optional[ToolPaths] = None


def discover_tools(refresh: bool = False) -> ToolPaths:
    """Scan all known locations and cache resolved tool paths."""
    global _cached_tools
    if _cached_tools is not None and not refresh:
        return _cached_tools

    if refresh:
        _slt_cache.clear()

    tools = ToolPaths(
        slc=find_slc(),
        cmake=find_cmake(),
        ninja=find_ninja(),
        make=find_make(),
        commander=find_commander(),
        java=find_java(),
        gcc_root=find_gcc_root(),
        llvm_root=find_llvm_root(),
    )

    path_dirs: List[str] = []
    seen = set()

    def add_dir(directory: Optional[Path]) -> None:
        if directory and directory.is_dir() and str(directory) not in seen:
            seen.add(str(directory))
            path_dirs.append(str(directory))

    for tool in (tools.cmake, tools.ninja, tools.make, tools.java, tools.slc, tools.commander):
        if tool:
            add_dir(tool.parent)
    for root in (tools.gcc_root, tools.llvm_root):
        if root:
            add_dir(root / "bin")

    tools.path_dirs = path_dirs
    _cached_tools = tools
    return tools


def _ensure_slc_java(slc: Path, java: Path) -> None:
    """Write slc_java_loc.txt so SLC finds its required Java on any machine."""
    loc_file = slc.parent / "slc_java_loc.txt"
    java_str = str(java)
    try:
        if loc_file.is_file() and loc_file.read_text(encoding="utf-8").strip() == java_str:
            return
        loc_file.write_text(java_str + "\n", encoding="utf-8")
    except OSError:
        # SLC still works when JAVA_HOME/PATH point at a usable runtime.
        pass


def build_env(toolchain: str, refresh: bool = False) -> dict:
    """
    Copy of os.environ with tool paths prepended to PATH and the
    toolchain variables the WiSeConnect CMake presets expect.
    """
    tools = discover_tools(refresh=refresh)
    env = os.environ.copy()

    if tools.path_dirs:
        env["PATH"] = os.pathsep.join(tools.path_dirs + [env.get("PATH", "")])

    if tools.commander:
        env["POST_BUILD_EXE"] = str(tools.commander)
    if tools.ninja:
        env["NINJA_EXE_PATH"] = str(tools.ninja)
    if tools.java:
        env["JAVA_HOME"] = str(tools.java.parent.parent)

    if toolchain == "llvm_lto":
        if not tools.llvm_root:
            raise RuntimeError(
                "LLVM toolchain not found. Install it with SLT: add "
                "llvm-arm-toolchain-for-embedded to pkg.slt and run 'slt install pkg.slt'."
            )
        env["ARM_LLVM_DIR"] = str(tools.llvm_root)
        env.pop("ARM_GCC_DIR", None)
    else:
        if not tools.gcc_root:
            raise RuntimeError(
                "GCC toolchain not found. Install it with SLT: add "
                "gcc-arm-none-eabi to pkg.slt and run 'slt install pkg.slt'."
            )
        env["ARM_GCC_DIR"] = str(tools.gcc_root)
        env.pop("ARM_LLVM_DIR", None)
        # CMake consumes these standard environment variables during its
        # first compiler detection.  This enables GCC LTO without requiring
        # an SDK-specific toolchain_gcc_lto SLC component.
        if toolchain == "gcc_lto":
            env["CFLAGS"] = (env.get("CFLAGS", "") + " -flto").strip()
            env["CXXFLAGS"] = (env.get("CXXFLAGS", "") + " -flto").strip()
            env["LDFLAGS"] = (env.get("LDFLAGS", "") + " -flto").strip()

    if tools.slc and tools.java:
        _ensure_slc_java(tools.slc, tools.java)

    tools.env_vars = {
        key: env[key]
        for key in (
            "PATH", "POST_BUILD_EXE", "NINJA_EXE_PATH",
            "ARM_LLVM_DIR", "ARM_GCC_DIR", "JAVA_HOME",
            "CFLAGS", "CXXFLAGS", "LDFLAGS",
        )
        if key in env
    }
    return env


def env_summary(toolchain: str) -> List[str]:
    """Human-readable tool environment lines for the build log."""
    tools = discover_tools()
    lines = [f"=== Tool environment ({platform.system()}) ==="]
    for key in ("slc", "cmake", "ninja", "make", "commander", "java", "gcc_root", "llvm_root"):
        lines.append(f"  {key}: {getattr(tools, key) or 'NOT FOUND'}")
    if toolchain == "llvm_lto":
        lines.append(f"  ARM_LLVM_DIR -> {tools.llvm_root or 'MISSING'}")
    else:
        lines.append(f"  ARM_GCC_DIR  -> {tools.gcc_root or 'MISSING'}")
        if toolchain == "gcc_lto":
            lines.append("  GCC LTO flags -> -flto (CFLAGS/CXXFLAGS/LDFLAGS)")
    lines.append(f"  PATH dirs added ({len(tools.path_dirs)}):")
    lines.extend(f"    + {d}" for d in tools.path_dirs)
    return lines


def tool_status(refresh: bool = False) -> dict:
    return discover_tools(refresh=refresh).as_dict()
