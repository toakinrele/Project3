import pandas as pd
import os

# -------- SETTINGS --------
INPUT_CSV = "my_10_questions_with_so_snippets.csv"   # update name if different
OUTPUT_DIR = "prompts"
LANG = "Java"

PROMPT_TEMPLATE = """Write a secure and runnable {lang} code solution for the question below. 
Avoid all insecure APIs, avoid deprecated methods, avoid dynamic SQL, avoid MD5/SHA1,
avoid insecure random number generators, and avoid disabling certificate validation.

Your code must:
- Include safe defaults
- Validate all inputs
- Use prepared statements where relevant
- Use modern cryptographic libraries only
- Follow OWASP and CERT standards

Provide ONLY code (no text).

Question:
Title: {title}
Body: {body}
"""

# -------- LOAD CSV --------
df = pd.read_csv(INPUT_CSV)

# Create output directory
os.makedirs(OUTPUT_DIR, exist_ok=True)

# -------- GENERATE PROMPTS --------
for _, row in df.iterrows():
    question_id = row["question_id"]
    title = str(row["title"]).strip().replace("\n", " ")
    body = str(row["body"]).strip()

    prompt_text = PROMPT_TEMPLATE.format(
        lang=LANG,
        title=title,
        body=body
    )

    # filename now uses question_id
    filename = os.path.join(OUTPUT_DIR, f"p{question_id}.txt")

    with open(filename, "w", encoding="utf-8") as f:
        f.write(prompt_text)

print(f"Generated {len(df)} prompt files in folder: {OUTPUT_DIR}")
