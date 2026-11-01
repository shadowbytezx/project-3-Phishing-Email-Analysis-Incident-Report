# project-3-Phishing-Email-Analysis-Incident-Report

## Summary

Analysis of a suspicious email claiming to be from an "IT Security Team," warning of account suspension and urging the recipient to click a verification link. Manual header analysis and threat intelligence lookups confirm this is a **phishing email, high confidence**, despite one data source (VirusTotal) returning a clean result.

| Field | Value |
|---|---|
| Date analyzed | Oct 31, 2026 |
| Claimed sender | admin@it-support-desk.com |
| Actual sending IP | 185.220.101.47 |
| Verdict | Phishing — High Confidence |

## Indicators of Compromise (IOCs)

| Type | Value |
|---|---|
| Sending IP | 185.220.101.47 |
| Sending domain (actual) | secure-mailer-relay.net |
| Spoofed display domain | it-support-desk.com |
| Reply-To domain | mail-recoveryservice.ru |
| Phishing link domain | it-support-desk-verify.com |
| Full phishing URL | hxxp://secure-login[.]it-support-desk-verify[.]com/auth/session?id=28819&token=a93ke820 |

*(URL defanged with `hxxp` and brackets per standard IOC-sharing convention, to prevent accidental clicks when shared.)*

## Technical Analysis

### 1. Header Forgery

The `From:` field displayed `admin@it-support-desk.com`, but the `Return-Path` and `Received` headers show the email actually originated from `secure-mailer-relay.net` (185.220.101.47). The `From:` address is attacker-controlled and trivially spoofable; the `Received` chain reflects the true sending infrastructure.

### 2. Authentication Failures

dkim=fail header.i=@it-support-desk.com
spf=fail smtp.mailfrom=secure-mailer-relay.net
dmarc=fail (p=REJECT sp=REJECT dis=NONE) header.from=it-support-desk.com


All three authentication checks failed. Notably, the domain's DMARC policy is set to `p=REJECT`, meaning the legitimate domain owner has explicitly requested that failing mail be rejected outright. The email was still delivered (to spam), which illustrates that DMARC enforcement depends on the receiving mail server honoring the policy — it is a request, not a guarantee.

### 3. Reply-To Mismatch

From: admin@it-support-desk.com
Reply-To: itsupport.helpdesk@mail-recoveryservice.ru


Any reply would be routed to an entirely unrelated domain, a common technique to harvest responses without exposing the spoofed sending address.

### 4. Lookalike (Typosquatted) Domain

The embedded link points to `it-support-desk-verify.com`, not the claimed `it-support-desk.com`. Hyphens are not domain separators — only dots are — so `it-support-desk-verify.com` is a completely separate, independently registered domain designed to visually resemble the legitimate one. The `secure-login.` prefix is an attacker-controlled subdomain added for additional false legitimacy.

### 5. No Encryption

The link uses `http://`, not `https://` — unusual for a page impersonating a secure login portal, though not conclusive on its own since some phishing infrastructure does use valid TLS certificates.

## Threat Intelligence Lookups

| Source | Target | Result |
|---|---|---|
| AbuseIPDB | 185.220.101.47 | **100% abuse confidence.** Reported for web app attacks (126), hacking (85), brute-force (45), port scanning (30), bad bot activity (15) |
| VirusTotal | Phishing URL | **0/90 vendors flagged** |

**Analysis of the discrepancy:** AbuseIPDB reflects the IP's accumulated history across many prior incidents, while VirusTotal's URL scan checks a specific URL string against vendor blocklists at scan time. A newly registered phishing domain (as `it-support-desk-verify.com` almost certainly is) is frequently clean on first scan simply because no vendor has catalogued it yet — a known limitation sometimes called the "zero-day phishing gap." A clean VirusTotal result does not mean safe; it can mean *not yet reported*.

## Verdict

**Phishing — High Confidence.**

Despite the clean VirusTotal result, the totality of evidence — failed SPF/DKIM/DMARC, header/domain spoofing, a Reply-To redirect to an unrelated domain, a typosquatted link domain, and a sending IP with an extensive, unrelated abuse history — is conclusive. The clean VirusTotal result reflects the limitation of time-of-scan detection against newly registered infrastructure, not an absence of threat.

## Recommendations

- Do not click the link or reply to the email
- Report the email to the organization's security team / abuse mailbox
- Block the sending IP (185.220.101.47) and the phishing domain (it-support-desk-verify.com) at the mail gateway / firewall level
- If any recipient already clicked the link, treat it as a potential credential compromise: reset the affected account's password and review recent login activity

## Lessons Learned

- The `From:` field is not evidence of anything — it is attacker-controlled and must be cross-checked against `Return-Path` and `Received` headers.
- DMARC `p=REJECT` is a policy request, not an enforcement guarantee; delivery still depends on the receiving server's configuration.
- Domain lookalikes must be read strictly by dot-separated labels — hyphens inside a label are not separators and do not create a new domain boundary.
- No single threat intelligence source is authoritative. AbuseIPDB and VirusTotal measured different things (IP reputation history vs. point-in-time URL reputation) and a "clean" result from one tool does not override strong evidence from header analysis and another source.

