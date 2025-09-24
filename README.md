Insider Threat Detection Framework :

This repository contains the Python implementation for a policy- and rule-based insider threat detection framework, along with an optional hybrid extension that combines rule-based logic with the Isolation Forest (IF) anomaly detection algorithm.

The code was developed as part of a master’s research project on evaluating policy-driven approaches to insider threat detection in enterprise IT environments.

Repository Structure :
1. CodeforRuleImplementation.py :

* Implements a rule-based insider threat detection framework.

* Ingests a simulated enterprise dataset with fields:

  - UserID, Role, Action, Timestamp, ResourceAccessed, IPAddress.

* Applies eight predefined rules (R1–R8) to detect insider threat scenarios:

1. Lateral Movement – Access outside department scope.

2. Rapid Multi-System Access – >3 systems within 10 minutes.

3. IP Anomaly – New subnet at odd hours.

4. Role Change + Privileged Activity – Misuse after promotion.

5. Mass Email Attachments – >5 MB files to multiple external domains.

6. Rare Command Usage – Admin-level commands by non-admins.

7. Suspicious Command / Failed Attempts – Repeated failed access attempts.

8. Odd Hour Production Access – Unauthorized server access outside business hours.

* Each log entry is evaluated against these rules, and alerts are generated where violations occur.

* Outputs a flagged dataset showing normal vs. suspicious events.

2. IF+RuleImplementation.py :

* Extends the above rule-based framework with an Isolation Forest anomaly detection layer.

* Isolation Forest is used to detect unusual behavioural deviations that are not explicitly covered by rules.

* The script produces:

  - Rule-based alerts (policy violations).

  - IF-based anomaly scores (outliers).

  - Hybrid comparison to evaluate combined detection effectiveness.

Methodology Alignment :

* Rule-based framework → Demonstrates the interpretability and direct mapping of enterprise policies to detection rules.

* Hybrid (IF + Rules) → Provides comparative evaluation of rule-based detection vs. anomaly-based detection, highlighting strengths and limitations.

Output :

* Processed dataset with alerts flagged.

* Evaluation metrics (Precision, Recall, F1-score).

* Visualizations of detection performance (for hybrid model).

Contribution of the Project :

This repository provides a reproducible demonstration of how policy-driven rules can detect insider threats in enterprise IT, and explores whether augmenting them with anomaly detection improves effectiveness.
