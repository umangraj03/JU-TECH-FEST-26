#!/usr/bin/env python
import sys
import subprocess
import os
import shutil
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parent


def get_python_exe():
    venv_py = ROOT_DIR / ".venv" / ("Scripts" if os.name == "nt" else "bin") / ("python.exe" if os.name == "nt" else "python")
    if venv_py.exists():
        return str(venv_py)
    return sys.executable


def run_cmd(cmd, cwd=ROOT_DIR):
    print(f"\n[RUN] {cmd} (cwd={cwd})")
    res = subprocess.run(cmd, shell=True, cwd=cwd)
    if res.returncode != 0:
        print(f"[FAIL] Command exited with code {res.returncode}")
        sys.exit(res.returncode)


def setup():
    print("=== [1/3] Setting up Python dependencies ===")
    run_cmd(f'"{get_python_exe()}" -m pip install -r backend/requirements.txt')

    print("\n=== [2/3] Setting up .env configuration ===")
    env_file = ROOT_DIR / ".env"
    env_example = ROOT_DIR / ".env.example"
    if not env_file.exists() and env_example.exists():
        shutil.copy(env_example, env_file)
        print("Created .env from .env.example")

    print("\n=== [3/3] Setting up Frontend dependencies ===")
    npm_cmd = "npm.cmd" if os.name == "nt" else "npm"
    run_cmd(f"{npm_cmd} install", cwd=ROOT_DIR / "frontend")
    print("\n[SUCCESS] Setup complete!")


def seed():
    print("=== Seeding database with fictional entities and attacks ===")
    run_cmd(f'"{get_python_exe()}" -m backend.seed')
    print("[SUCCESS] Seed complete!")


def test():
    print("=== Running Pytest Security Test Suites ===")
    run_cmd(f'"{get_python_exe()}" -m pytest backend/tests -v')
    print("[SUCCESS] All tests passed!")


def dev():
    print("=== Launching Backend (FastAPI :8000) and Frontend (Vite :5173) ===")
    npm_cmd = "npm.cmd" if os.name == "nt" else "npm"

    # Start FastAPI backend
    backend_proc = subprocess.Popen(
        [get_python_exe(), "-m", "uvicorn", "backend.app.main:app", "--host", "127.0.0.1", "--port", "8000", "--reload"],
        cwd=ROOT_DIR
    )

    # Start Vite frontend
    frontend_proc = subprocess.Popen(
        [npm_cmd, "run", "dev"],
        cwd=ROOT_DIR / "frontend"
    )

    try:
        backend_proc.wait()
        frontend_proc.wait()
    except KeyboardInterrupt:
        print("\nStopping services...")
        backend_proc.terminate()
        frontend_proc.terminate()


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python run.py [setup|seed|test|dev]")
        sys.exit(1)

    action = sys.argv[1].lower()
    if action == "setup":
        setup()
    elif action == "seed":
        seed()
    elif action == "test":
        test()
    elif action == "dev":
        dev()
    else:
        print(f"Unknown command '{action}'. Supported: setup, seed, test, dev")
        sys.exit(1)
