import pandas as pd
import random

# Load the CSVs (adjust paths if needed)
questions = pd.read_csv("dataset_questions.csv")
snippets = pd.read_csv("dataset_snippets.csv")

# Keep only question_ids that appear in snippets
valid_qids = snippets["question_id"].unique()

# Filter questions to only those with snippets
questions_with_snippets = questions[questions["question_id"].isin(valid_qids)]

# Sample 10 distinct question_ids
sampled_questions = questions_with_snippets.sample(n=10, random_state=42)

# Join with one SO snippet per question (e.g., the first one for each)
sampled = sampled_questions.merge(
    snippets.groupby("question_id").first().reset_index(),
    on="question_id",
    how="left"
)

# Save for convenience
sampled.to_csv("my_10_questions_with_so_snippets.csv", index=False)

print(sampled[["question_id", "title"]])
