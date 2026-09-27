# Login investigation report

**Status:**  completed — replace the prompts with your own findings.  
**Analyst:** [Mohamed Ibrahim]  
**Date performed:** [9/27/2026]  
**Evidence:** Synthetic `sample_logins.csv` from this lab.

## Summary

[I observed a total of sixteen login attempts, in which 11 resulted in failure. The account 'admiin' made 5 failed attempts, which is a perceived suspicious activity. ]

## Method

[I was able to identify eleven failures and five successes, I used the prompts py tools\analyze_logins.py labs\01-login-investigation\sample_logins.csv and py tools\analyze_logins.py labs\01-login-investigation\sample_logins.csv --threshold 6 to determine the thresholds, however no proof of breach or compromise.]

## Observations and timeline

| UTC timestamp or range | Source IP | Account(s) | Observed events | Interpretation / uncertainty |
| 2026-09-01T09:04:00Z| 203.0.113.50 | admin| Five failed login attempts followed by a successful attempt | Suspicious activity, must be reviewed. Breach uncomfired|


## Assessment

[My assessment is complete, the failed login attempts could be an error done by the account user, however it is a red flag. If more evidence showed that the login attempts are signs of compromise, then we should take defensive measures .]

## Recommended follow-up

[I would verify if the account owner tried to login during the time of the failed login attempts, check MFA records, and the activity that was made after the success login.]

## Tool limitations and lessons

[In threshold 6, the account 'admin' successfully logged in which can be an alert. The tool can miss evidence of breach.]

## Completion evidence

[Events: 16
Failures: 11
Successes: 5
Failure threshold: 5 (counts across the whole file)

Failure counts by source IP:
  198.51.100.25: 5 failures; users=amina,leila,omar [REVIEW]
  203.0.113.50: 5 failures; users=admin [REVIEW]
  192.0.2.20: 1 failures; users=omar

Success after repeated failures for the same IP and user:
  2026-09-01T09:04:00Z | 203.0.113.50 | admin | 5 prior failures

Review flags are leads, not proof of an attack or compromise.]
