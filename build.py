import os
import shutil
import subprocess
import sys
import platform
from pathlib import Path
from PIL import Image  # type: ignore

PROJECT_ROOT = Path(__file__).parent.resolve()
MAIN_SCRIPT = PROJECT_ROOT / "main.py"
DIST_DIR = PROJECT_ROOT / "dist"
BUILD_DIR = PROJECT_ROOT / "build"
ICON_WIN = PROJECT_ROOT / "assets" / "icons" / "app_icon.png"
ICON_LINUX = PROJECT_ROOT / "assets" / "icons" / "app_icon.png"

# Resources to include in bundle (src;target) pairs
DATA_SPEC = [
    ("assets", "assets"),  # icons, qss, etc.
    ("src/resources", "resources"),
]

# Hidden imports that PyInstaller often misses
HIDDEN_IMPORTS = [
    "scapy.contrib.http",
    "matplotlib.backends.backend_qtagg",
]


def ensure_pyinstaller():
    """Install PyInstaller if not present."""
    try:
        import PyInstaller  # noqa: F401
    except ImportError:
        print("[+] Installing PyInstaller...")
        subprocess.check_call([sys.executable, "-m", "pip", "install", "pyinstaller"])


def build(exe_name: str = "Net4", onefile: bool = True):
    ensure_pyinstaller()

    cmd = [
        sys.executable,
        "-m",
        "PyInstaller",
        str(MAIN_SCRIPT),
        "--clean",
        "--noconfirm",
        "--windowed",
        "--name",
        exe_name,
    ]

    # icon & platform-specific tweaks
    if platform.system() == "Windows":
        # If .ico missing, attempt to generate from PNG (requires Pillow)
        if not ICON_WIN.exists() and ICON_LINUX.exists():
            try:
                from PIL import Image  # type: ignore
            except ImportError:
                print("[+] Installing Pillow for .ico conversion...")
                subprocess.check_call([sys.executable, "-m", "pip", "install", "pillow"])
                from PIL import Image  # type: ignore

            print("[+] Converting PNG to ICO ...")
            img = Image.open(ICON_LINUX)
            img.save(ICON_WIN, sizes=[(256, 256)])

        if ICON_WIN.exists():
            cmd += ["--icon", str(ICON_WIN)]
    else:
        # Linux / macOS uses PNG
        if ICON_LINUX.exists():
            cmd += ["--icon", str(ICON_LINUX)]

    # data files
    for src, dst in DATA_SPEC:
        cmd += ["--add-data", f"{src}{os.pathsep}{dst}"]

    # hidden imports
    for mod in HIDDEN_IMPORTS:
        cmd += ["--hidden-import", mod]

    if onefile:
        cmd.append("--onefile")

    # Ensure build/dist old folders removed
    if DIST_DIR.exists():
        shutil.rmtree(DIST_DIR)
    if BUILD_DIR.exists():
        shutil.rmtree(BUILD_DIR)

    print("[+] Running:", " ".join(cmd))
    subprocess.check_call(cmd)
    print(f"[+] Build complete. Output in {DIST_DIR}")


if __name__ == "__main__":
    exe = "Net4"
    if len(sys.argv) > 1:
        exe = sys.argv[1]
    try:
        build(exe_name=exe, onefile=True)
    except subprocess.CalledProcessError as e:
        print("[!] Build failed", e)
        sys.exit(1) 