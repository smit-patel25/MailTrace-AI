# Scoring Calibration Analysis (Version 1.2)

## Scoring Version 1.2 Update

MailTrace AI now uses Scoring Version 1.2, which introduces the following changes:
- **Attachment Risk Component**: Evaluates email attachments based on metadata. Points awarded: 0 (Normal), 15 (Review required), or 50 (High risk/Executable/Deception).
- **Score Cap**: The total fraud score is strictly capped at 100 points.

## Overview
This document evaluates the MailTrace AI scoring engine against a variety of legitimate, spam, and severe phishing email fixtures.

## Test Results

### valid_plain.eml (Legitimate)
- Expected: Low, Actual: Low (Correct: True)
- Header Points: 0, Content Points: 0, Infra Points: 0, Domain Points: 0
- Final Score: 0

### Promotional/Spam
- Expected: Medium, Actual: Low (Correct: False)
- Header Points: 0
- Content Points: 5
- Infrastructure Points: 0
- URL/Domain Points: 0
- Final Score: 5

### Synthetic BEC
- Expected: High, Actual: Moderate (Correct: False)
- Header Points: 30
- Content Points: 18
- Infrastructure Points: 0
- URL/Domain Points: 0
- Final Score: 48

### strong_phishing_1.eml
- Expected: High, Actual: High (Correct: True)
- Header Points: 35
- Content Points: 21
- Infrastructure Points: 0
- URL/Domain Points: 0
- Final Score: 56

### strong_phishing_2.eml
- Expected: High, Actual: Moderate (Correct: False)
- Header Points: 15
- Content Points: 16
- Infrastructure Points: 0
- URL/Domain Points: 0
- Final Score: 31

### Legitimate business email
- Expected: Low, Actual: Low (Correct: True)
- Header Points: 0
- Content Points: 0
- Infrastructure Points: 0
- URL/Domain Points: 0
- Final Score: 0

### Legitimate password-reset email
- Expected: Low, Actual: Low (Correct: True)
- Header Points: 0
- Content Points: 6
- Infrastructure Points: 0
- URL/Domain Points: 0
- Final Score: 6

### Marketing email with tracking links
- Expected: Low, Actual: Low (Correct: True)
- Header Points: 0
- Content Points: 1
- Infrastructure Points: 0
- URL/Domain Points: 0
- Final Score: 1

### Credential phishing
- Expected: High, Actual: Moderate (Correct: False)
- Header Points: 15
- Content Points: 24
- Infrastructure Points: 0
- URL/Domain Points: 0
- Final Score: 39

### Executive wire-transfer BEC
- Expected: High, Actual: Low (Correct: False)
- Header Points: 0
- Content Points: 19
- Infrastructure Points: 0
- URL/Domain Points: 0
- Final Score: 19
