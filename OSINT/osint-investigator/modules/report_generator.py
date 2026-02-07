from datetime import datetime
import os

def generate_report(case):
    os.makedirs("reports", exist_ok=True)
    path = f"reports/{case}_report.txt"

    with open(path, "w") as f:
        f.write("OSINT CASE REPORT\n")
        f.write("=================\n\n")
        f.write(f"Case: {case}\n")
        f.write(f"Generated: {datetime.now()}\n\n")
        f.write("Findings:\n")
        f.write("- Username OSINT\n")
        f.write("- Image OSINT\n\n")
        f.write("Conclusion:\n")
        f.write("Pending analyst review.\n")

    return path
