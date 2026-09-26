# Lab 01: Investigate suspicious login activity

**Status:** practice exercise, not yet completed by the learner.  
**Time:** approximately 30–45 minutes.  
**Requirements:** a browser for manual review; Python 3 for the optional analyzer. No extra packages or virtual machines.

## Scenario and evidence

You are reviewing authentication activity for a fictional organization. Decide which events deserve follow-up and explain why. All names, events, and IP addresses are synthetic. The IPs are documentation addresses, not targets to scan or research for reputation.

Open [sample_logins.csv](sample_logins.csv). Each row contains a UTC timestamp, a username, a source IP, and either a successful or failed login. A success tells us that authentication succeeded; it does not establish who was behind it.

## 1. Investigate manually first

Write down your answers before running the script:

1. How many logins failed? Which source IPs have the most failures?
2. Which source targets one account repeatedly? Does it later authenticate successfully?
3. Which source tries several different accounts? What additional evidence would you need to establish password spraying?
4. Which failure followed by success could be an ordinary password typo?
5. What should an analyst check next before recommending account restrictions?

Separate observed facts from hypotheses. Multiple failed logins alone do not prove malicious activity.

## 2. Download the repository on Windows

1. On the repository's main page, click **Code → Download ZIP**.
2. In File Explorer, right-click the downloaded ZIP and select **Extract All**.
3. Open the extracted folder containing this repository's top-level README and `tools` folder.
4. Click the File Explorer address bar, type `cmd`, and press Enter.
5. Check whether Python is already available:

```bat
py --version
```

If that fails, try `python --version`. If neither reports Python 3, you can still finish the manual exercise. Ask for help installing Python from its official website; no paid software is required.

## 3. Run the analyzer

From the repository root:

```bat
py tools\analyze_logins.py labs\01-login-investigation\sample_logins.csv
```

If your working command was `python`, substitute `python` for `py` in every command.

The default review threshold is five failures per source IP across the entire file. Try changing it:

```bat
py tools\analyze_logins.py labs\01-login-investigation\sample_logins.csv --threshold 6
```

Explain why the flags change even though the underlying events are identical. A threshold is an analyst's rule, not a verdict.

Optional: check the analyzer's tests:

```bat
py -m unittest discover -s tests -v
```

## 4. Check your results

After your own review, compare your output with [expected-output.txt](expected-output.txt). It is a reference result generated from the supplied dataset, not proof that you ran the lab.

The default run should show 16 events: 11 failures and 5 successes. Two IPs meet the five-failure threshold. One successful login follows five earlier failures for the same source and username. These are investigation leads, not a confirmed breach.

## 5. Write your report

Use [report-template.md](report-template.md). You can edit it with GitHub's pencil button and save your own conclusions. Only mark the main README's progress checkboxes after doing the corresponding work. Add an optional screenshot of your actual output after checking it for personal information.

## How the tool works and where it falls short

- Reads and validates the exact CSV schema, then sorts events chronologically.
- Counts failed logins by source IP and lists the usernames involved.
- Flags IPs meeting the threshold, and successes after enough earlier failures for the same IP/user since that pair's last success.
- Does not use a sliding time window or automatically establish brute force/password spraying. Failures hours apart still count together.
- Does not detect distributed attacks, inspect MFA, analyze device data, or enrich IP reputation.
- A shared IP can represent many people. A legitimate user can mistype a password repeatedly.
- A later success is not proof of account compromise; correlate identity, device, MFA, and subsequent activity.

## Optional extension

Copy the CSV, add a few fictional events, and predict the result before running it. Keep the original evidence unchanged. Explain which threshold would produce fewer false positives and what suspicious activity it might miss.
