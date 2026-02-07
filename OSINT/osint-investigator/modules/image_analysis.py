import subprocess
import tempfile
import os

def analyze_image(uploaded):
    with tempfile.NamedTemporaryFile(delete=False, suffix=".jpg") as f:
        f.write(uploaded.read())
        path = f.name

    result = subprocess.run(
        ["exiftool", path],
        capture_output=True,
        text=True
    )

    os.remove(path)
    return result.stdout
