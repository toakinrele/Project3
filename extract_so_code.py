import pandas as pd
import os

# -------- SETTINGS --------
INPUT_CSV = "my_10_questions_with_so_snippets.csv"   # update if different
OUTPUT_DIR = "so_code"

# -------- LOAD CSV --------
df = pd.read_csv(INPUT_CSV)

# Create output directory if not exists
os.makedirs(OUTPUT_DIR, exist_ok=True)

# -------- EXTRACT & SAVE SNIPPETS --------
for idx, row in df.iterrows():
    question_id = row["question_id"]
    snippet = str(row["snippet_so"]).strip()

    # Ensure snippet is valid Java code (optional minimal wrapper)
    if not snippet:
        snippet = "// No StackOverflow snippet available."

    # File path: so_code/q{id}.java
    filename = os.path.join(OUTPUT_DIR, f"q{question_id}.java")

    with open(filename, "w", encoding="utf-8") as f:
        f.write(snippet)

print(f"Saved {len(df)} StackOverflow snippets to folder: {OUTPUT_DIR}")
