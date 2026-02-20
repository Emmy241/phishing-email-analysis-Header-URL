# Phishing Email Analysis — iCloud Impersonation (Header + URL Chain)

## Overview
A suspicious email was received in a personal mailbox, impersonating **Apple iCloud** and claiming the recipient’s cloud account was locked. The message used urgency (“photos and videos will be removed”) to drive clicks. Header analysis and URL tracing indicate this was **not** sent by Apple and is consistent with a **phishing / malicious redirection campaign**.

> **Recipient email intentionally redacted:** `a***@gmail.com`

---

## Case Metadata
- **Case ID:** PHISH-20260219-ICLOUD-001  
- **Date Observed:** 2026-02-19  
- **Analyst:** (Your Name / Handle)  
- **Category:** Phishing / Brand Impersonation / Malicious Redirect  
- **Impersonated Brand:** Apple iCloud  
- **Severity:** High (credential theft intent likely, brand impersonation confirmed)

---

## Tools Used
- Email Header Analyzer (online)
- MXToolbox (header / auth checks)
- urlscan.io (URL behavior + redirects)
- VirusTotal (URL reputation / detections)

---

## 1) Email Summary (Social Engineering)
### Lure Characteristics
- **Theme:** iCloud / cloud account lockout
- **Pressure tactic:** Threat of data removal (“photos and videos will be removed”)
- **Intent:** Drive urgent click-through to attacker-controlled infrastructure

### Suspicious Indicators
- Sender domain(s) do not match Apple/iCloud infrastructure
- Sender identity is inconsistent across header fields (From vs Return-Path)
- Link uses a trusted hosting domain as an initial hop (reputation shielding)

> Evidence screenshots are stored under `/evidence/` (redacted where needed).

---

## 2) Header & Sender Analysis

### Key Observed Header Values (Extract)
- **To:** `a***@gmail.com` *(redacted)*
- **From:** `Payment-Declined <nooreply.dchqirw@zbuqbahyqmbtrim.us>`
- **Return-Path / Envelope-From:** `<ddmxvizwoyfpd@pkaquaweiki.gfurlan.com.br>`
- **Sending IP observed by Google:** `89.252.161.234`
- **SPF Result:** `pass` for `pkaquaweiki.gfurlan.com.br` (authorized sender IP)

### Findings
#### 2.1 Not Apple: sender identity mismatch
The email claims to be related to iCloud, but both the visible sender and envelope sender are unrelated to Apple:
- Visible **From** domain: `zbuqbahyqmbtrim.us`
- Envelope **Return-Path** domain: `pkaquaweiki.gfurlan.com.br`

This mismatch is a common sign of impersonation.

#### 2.2 SPF “pass” does not prove legitimacy
SPF passing here only means the domain in `smtp.mailfrom` (Return-Path) authorized the sending IP. It **does not validate** that the email is from Apple or that the visible “From” display is trustworthy.

#### 2.3 Infrastructure chain is inconsistent with Apple mail flow
Header routing shows multiple unrelated services/domains in the chain. This is not consistent with typical Apple/iCloud notification delivery patterns and is consistent with abusive/compromised infrastructure or intentionally noisy header construction.

### Header Verdict
**Confirmed brand impersonation / phishing characteristics.**  
The message was **not** sent from Apple-controlled domains or infrastructure.

---

## 3) URL Analysis

### Extracted URL (Defanged)
**Stage 1 (Initial URL):**  
`hxxps[://]storage[.]googleapis[.]com/whilewait/comessuccess[.]html`

### Redirect / Final Landing
**Stage 2 (Final URL):**  
`hxxps[://]trackoriginal[.]com/`

### Key Finding: “Reputation Shielding” via trusted hosting
The initial URL uses **Google Cloud Storage** (`storage.googleapis.com`), which is a trusted and commonly allowed domain. Attackers frequently abuse major cloud platforms to:
- increase delivery/click success
- bypass basic domain reputation filters
- make blocking harder for defenders

### Final Landing Behavior (Observed)
The final destination **does not present an Apple login page**. It currently shows a generic **“Our Website is Coming Soon!”** page with an email subscription form.

This behavior is consistent with:
- **Cloaking / traffic routing** (showing benign content to scanners or some users)
- **Rotating destinations** (redirect target may change over time)
- **Cleanup / takedown reaction** (phishing page removed after campaign burst)
- **Decoy landing** while tracking/referral infrastructure remains active

> Screenshot captured and stored in `/evidence/final_landing_coming_soon.png`.

### URL Verdict
**Malicious redirection chain likely used for phishing delivery/tracking.**  
Even though the final page appears benign now, the overall context (brand impersonation + cloud-hosted redirect + suspicious sender infra) supports a phishing campaign assessment.

---

## 4) Indicators of Compromise (IOCs)

### Email Addresses
- `nooreply.dchqirw@zbuqbahyqmbtrim[.]us`
- `ddmxvizwoyfpd@pkaquaweiki[.]gfurlan[.]com[.]br`

### Domains
- `zbuqbahyqmbtrim[.]us`
- `pkaquaweiki[.]gfurlan[.]com[.]br`
- `storage[.]googleapis[.]com`
- `trackoriginal[.]com`

### URLs (Defanged)
- `hxxps[://]storage[.]googleapis[.]com/whilewait/comessuccess[.]html`
- `hxxps[://]trackoriginal[.]com/`

### IP Address (Mail Transport)
- `89[.]252[.]161[.]234`

---

## 5) Recommended Actions

### For the Recipient
- Do not click links or submit credentials.
- If any credentials were submitted:
  - change Apple ID password immediately
  - enable/confirm MFA
  - review Apple ID sign-in activity and trusted devices
- Check mailbox rules/forwarding for persistence (filters, auto-forward, delegated access).

### Defensive Recommendations (SOC-style)
- Block the identified sender domains (mail gateway / filtering rules).
- Add URL/domain indicators to DNS filtering / proxy blocklists where possible.
- Create detections for:
  - iCloud/Apple impersonation keywords + non-Apple sender domains
  - cloud-hosted redirect patterns (e.g., `storage.googleapis.com/*` used as a hop)

---

## 6) Evidence (Screenshots / Artifacts)



---

## 6) Notes / Limitations
- Final landing page appears benign **at time of analysis**; attacker infrastructure may change rapidly.
- This assessment is based on header inconsistencies, impersonation behavior, and redirect chain design.
- Additional confirmation can be achieved by comparing DKIM/DMARC alignment results (if available from tooling output).



