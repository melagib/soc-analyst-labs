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
| 09:01:00–09:01:30| 203.0.113.50 | admin| Five failed login attempts followed by a successful attempt | Suspicious activity, must be reviewed. Breach uncomfired|
| ] | | | | |

## Assessment

[My assessment is complete, the organization employees should clarify the login attempts, and work together to eliminate threats. If more evidence showed that the login attempts are signs of compromise, then we should take defensive measures .]

## Recommended follow-up

[I would request the details of the activity that was done after the succesful login attempt.]

## Tool limitations and lessons

[In threshold 6, the account 'admin' successfully logged in which can be an alert. The tool can miss evidence of breach.]

## Completion evidence

[Paste a short excerpt of your actual output or link an optional screenshot. State clearly if you completed only the manual exercise.]
