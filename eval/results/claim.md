# Claim

D2

- using 'full_test' (n=80) as the full-firewall recall/FPR result
- (a) all 11 sources pass end-to-end: see pytest (tests/unit/test_parsing.py, test_carriers.py)
- (b) overall recall 46/54 = 85% (95% CI 73%–92%): BELOW target; per-carrier ≥80% with n≥30: not measured
- (c) benign FPR 0/26 = 0% (95% CI 0%–13%): insufficient sample (n=26, need ≥300)
- (d) reliability (50/50 items × 3 runs): schema-valid 100%, agreement 50/50 = 100%, re-scan n/a (no sanitized releases): meets
