import pandas as pd
import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.metrics import precision_score, recall_score, f1_score, confusion_matrix
import matplotlib.pyplot as plt
import seaborn as sns

# Load CSV
file_path = r"C:\Users\chouh\Documents\MSc\Project - CYM500\Code\Insider_threats_alerts.csv"
df = pd.read_csv(file_path)

# -----------------------------
# Inject synthetic anomalies (~10% rows)
# -----------------------------
np.random.seed(42)
anomaly_indices = np.random.choice(df.index, size=int(0.1 * len(df)), replace=False)

df.loc[anomaly_indices, 'failed_access_attempts'] = np.random.randint(10, 50, size=len(anomaly_indices))
df.loc[anomaly_indices, 'email_attachments'] = np.random.randint(20, 100, size=len(anomaly_indices))
df.loc[anomaly_indices, 'command'] = "rare_cmd1"
df.loc[anomaly_indices, 'system'] = "prod_server"
df.loc[anomaly_indices, 'role'] = "admin"

# -----------------------------
# Generate R1–R8 features
# -----------------------------
df['R1'] = df.groupby('user')['system'].transform('nunique')
df['R2'] = df.groupby('user')['system'].transform('count')
df['R3'] = df.groupby('user')['ip'].transform('nunique')
df['R4'] = np.where(df['role'] == 'admin', 1, 0)
df['R5'] = df.groupby('user')['email_attachments'].transform('sum')
df['R6'] = np.where(df['command'].isin(['rare_cmd1', 'rare_cmd2']), 1, 0)
df['R7'] = df['failed_access_attempts']
df['R8'] = np.where(df['system'] == 'prod_server', 1, 0)

# Rule-based ground truth: flag if any risky behavior
df['rule_based_alert'] = ((df[['R1','R2','R3','R4','R5','R6','R7','R8']] > 2).any(axis=1)).astype(int)

# -----------------------------
# Isolation Forest
# -----------------------------
features = ['R1','R2','R3','R4','R5','R6','R7','R8']
X = df[features].astype(float)

iso = IsolationForest(contamination=0.15, random_state=42)
df['if_pred'] = iso.fit_predict(X)

# Map output: -1 = anomaly → 1, 1 = normal → 0
df['if_pred'] = df['if_pred'].map({-1: 1, 1: 0})

# -----------------------------
# Evaluation
# -----------------------------
y_true = df['rule_based_alert']
y_pred = df['if_pred']

precision = precision_score(y_true, y_pred, zero_division=0)
recall = recall_score(y_true, y_pred, zero_division=0)
f1 = f1_score(y_true, y_pred, zero_division=0)

print("Isolation Forest Evaluation vs Rule-based Detection")
print(f"Precision: {precision:.2f}")
print(f"Recall:    {recall:.2f}")
print(f"F1-Score:  {f1:.2f}")

# Confusion Matrix
cm = confusion_matrix(y_true, y_pred)
tn, fp, fn, tp = cm.ravel()

# Table for TP, FP, FN, TN
results_table = pd.DataFrame({
    "Metric": ["True Positives (TP)", "False Positives (FP)", "False Negatives (FN)", "True Negatives (TN)"],
    "Count": [tp, fp, fn, tn]
})

print("\nConfusion Matrix Results:")
print(results_table)

# -----------------------------
# Save outputs to Excel
# -----------------------------
output_file = r"C:\Users\chouh\Documents\MSc\Project - CYM500\Code\evaluation_results.xlsx"

with pd.ExcelWriter(output_file) as writer:
    pd.DataFrame({"Precision":[precision], "Recall":[recall], "F1-Score":[f1]}).to_excel(writer, sheet_name="Metrics", index=False)
    results_table.to_excel(writer, sheet_name="Confusion_Matrix", index=False)
    df.to_excel(writer, sheet_name="Predictions", index=False)

print(f"\nResults saved to {output_file}")

# -----------------------------
# Visualization
# -----------------------------
# Bar chart
metrics = {"Precision": precision, "Recall": recall, "F1-Score": f1}
plt.figure(figsize=(6,4))
plt.bar(metrics.keys(), metrics.values(), color=["skyblue","orange","green"])
plt.title("Isolation Forest vs Rule-based Detection")
plt.ylim(0,1)
plt.show()

# Confusion Matrix Heatmap
plt.figure(figsize=(5,4))
sns.heatmap(cm, annot=True, fmt="d", cmap="Blues",
            xticklabels=["Normal","Anomaly"],
            yticklabels=["Normal","Anomaly"])
plt.xlabel("Predicted")
plt.ylabel("Rule-based Truth")
plt.title("Confusion Matrix: Rule-based vs Isolation Forest")
plt.show()
