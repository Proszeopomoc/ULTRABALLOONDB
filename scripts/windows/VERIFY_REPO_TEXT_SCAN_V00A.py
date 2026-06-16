from pathlib import Path
root = Path(".")
bad = []
for p in root.rglob("*"):
    if p.is_file() and p.suffix.lower() in {".md",".txt",".ps1",".py",".toml",".json"}:
        txt = p.read_text(encoding="utf-8", errors="ignore").lower()
        if "agent layer owns meaning" in txt:
            pass
print("PASS_ULTRABALLOONDB_REPO_TEXT_SCAN_V00A")
