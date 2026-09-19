# iPhone SE 3 — Apple TSS Signing Monitor

Monitors official/public IPSW firmware for **iPhone SE (3rd generation)** (`iPhone14,6`) from **iOS 15.4 through iOS 26.6.1**, inclusive.

## Verification model

For every firmware Build ID in the configured range:

1. Query **IPSW.me** for the firmware and its `signed` field.
2. Query **Apple TSS** through [Modern TSS Checker](https://github.com/rhcp011235/Modern_TSS_Checker) using the exact Build ID.
3. Classify the result as `SIGNED_CONFIRMED`, `UNSIGNED_CONFIRMED`, `CONFLICT`, or `UNKNOWN`.

Only official IPSW entries are considered. Version strings containing beta/RC suffixes are excluded.

## Alerts

- `UNSIGNED_CONFIRMED` / `UNKNOWN` → `SIGNED_CONFIRMED`: email alert.
- Any transition into `CONFLICT`: email alert.
- On the first run, currently confirmed-signed builds are grouped into one baseline email.
- No email is sent when the state is unchanged.

## GitHub Secrets

Create these repository secrets:

- `SMTP_HOST`
- `SMTP_PORT`
- `SMTP_USERNAME`
- `SMTP_PASSWORD`
- `MAIL_FROM`
- `MAIL_TO`

Do not put SMTP credentials in the repository.

## Local test

```bash
python3 -m pip install -r requirements.txt
git clone --depth 1 https://github.com/rhcp011235/Modern_TSS_Checker.git Modern_TSS_Checker
python3 monitor.py
```

The workflow runs every 5 minutes. GitHub documents 5 minutes as the shortest supported `schedule` interval; scheduled runs can be delayed under high Actions load. Scheduled workflows run from the repository's default branch. citeturn120283search0turn120283search2
