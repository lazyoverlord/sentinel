# Claim

D2

- using 'full_test' (n=80, split=test) as the test-split recall result
- (a) all 11 sources pass end-to-end: see pytest (tests/unit/test_parsing.py, test_carriers.py)
- (b) overall recall 46/54 = 85% (95% CI 73%–92%): BELOW target; per-carrier ≥80% with n≥30: not measured
- (c) pooled benign FPR 3/865 = 0% (95% CI 0%–1%) pooled (test_split=26, fpr_notinject_full=339, fpr_dolly_full=500): meets [hold rate 29/865 = 3% (95% CI 2%–5%), non-allow rate 34/865 = 4% (95% CI 3%–5%)]
- (d) reliability (50/50 items × 3 runs): schema-valid 100%, agreement 49/50 = 98%, re-scan 100% (5) (from frozen test run): meets
