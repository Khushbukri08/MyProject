Insider Threat Detection Framework (Policy & Rule-Based) -
This repository contains the implementation of a policy- and rule-based insider threat detection framework developed as part of a master’s research project. The framework demonstrates how insider threats in enterprise IT environments can be simulated, detected, and evaluated without reliance on large-scale SIEM tools or machine learning models.

Insider threats are among the most challenging risks to enterprise cybersecurity, as they originate from trusted users with legitimate access.
This project provides a lightweight, interpretable, and reproducible framework for detecting insider threats by:
1. Simulating enterprise activity logs with realistic attributes.
2. Applying rule-based detection logic derived from enterprise access policies.
3. Evaluating detection performance using precision, recall, and F1-score.

Repository Structure :

*simulate_logs.py

Generates a synthetic dataset of enterprise activity logs. Each record includes:
-User ID, Role, Action, Timestamp, Resource Accessed, IP Address
-Simulates both normal behaviour and malicious scenarios (e.g., off-hour access, data exfiltration).

*rules_engine.py

Contains the detection rules (R1–R8) that represent typical insider threat indicators:

R1: Lateral Movement
R2: Rapid Multi-System Access
R3: Location/IP Anomaly
R4: Role Change + Privileged Activity
R5: Mass Email Attachments
R6: Rare Command Usage
R7: Repeated Failed Access Attempts
R8: Off-Hour Production Access
