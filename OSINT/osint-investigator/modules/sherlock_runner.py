import subprocess

def run_sherlock(username):
    try:
        cmd = ["sherlock", username, "--timeout", "5", "--print-found"]
        result = subprocess.run(cmd, capture_output=True, text=True)
        return result.stdout or result.stderr
    except FileNotFoundError:
        # fallback for python -m sherlock
        cmd = ["python", "-m", "sherlock", username, "--timeout", "5", "--print-found"]
        result = subprocess.run(cmd, capture_output=True, text=True)
        return result.stdout or result.stderr
