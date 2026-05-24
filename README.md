# ALU Regex Data Extraction & Secure Validation

> **Course:** Data Extraction & Secure Validation Assignment
> **Author:** INDOHA — Junior Frontend Developer
> **Language:** Python 3 (standard library only — no third-party dependencies)

---

## Overview

This program reads a noisy, production-style text dump (the kind a backend
might return from an external CRM / ticketing API) and uses **regular
expressions only** to extract structured data from it. The input is treated
as **hostile**: every extractor is paired with a validator, sensitive
fields are **masked**, and obvious injection markers are **quarantined**
instead of being passed through.

The deliverable matches the assignment spec exactly:

```text
alu-regex-data-extraction_INDOHA/
├── input/
│   └── raw-text.txt          # realistic, messy input (emails, cards, URLs, ...)
├── src/
│   └── main.py               # all regex + validation + masking logic
├── output/
│   └── sample-output.json    # structured, masked result
└── README.md                 # this file
```

---

## How to run

You need Python 3.8+ (any modern distro works — no `pip install` required).

```bash
cd alu-regex-data-extraction_INDOHA
python3 src/main.py
```

You'll see a console summary (counts only — safe to paste anywhere) and a
full, masked JSON written to `output/sample-output.json`.

You can also point it at a different file:

```bash
python3 src/main.py path/to/other-input.txt path/to/other-output.json
```

---

## What it extracts

The assignment requires at least four data types **with emails and credit
cards being mandatory**. This program implements all eight optional types
plus the ALU-specific email validations:

| # | Data type           | Pattern source (in `main.py`) | Notes |
|---|---------------------|-------------------------------|-------|
| 1 | Email addresses     | `EMAIL_EXTRACT` + `EMAIL_STRICT` | Strict `fullmatch` validator |
| 2 | ALU official        | `ALU_OFFICIAL` | Exact `@alueducation.com` |
| 3 | ALU alumni          | `ALU_ALUMNI`   | Exact `@alumni.alueducation.com` |
| 4 | ALU SI              | `ALU_SI`       | Exact `@si.alueducation.com` |
| 5 | Credit card numbers | `CREDIT_CARD_EXTRACT` + Luhn   | Visa / MC / AmEx / Discover / JCB — masked |
| 6 | URLs                | `URL_EXTRACT`  | http/https, port, path, query |
| 7 | Phone numbers       | `PHONE_EXTRACT` | +CC, parens area code, US format |
| 8 | HTML tags           | `HTML_TAG_EXTRACT` | Open / close / self-close |
| 9 | Hashtags            | `HASHTAG_EXTRACT` | Letter-led, alphanumerics + `_` |
| 10| Currency amounts    | `CURRENCY_EXTRACT` | `$ € £ ¥ USD EUR GBP JPY RWF` |
| 11| Times 12h / 24h     | `TIME_12H` / `TIME_24H` | Excludes timezone offsets |

Every pattern is **heavily commented inline**. The patterns are written in
verbose (`re.X`) mode so future maintainers can read them without a
decoder ring.

---

## How the regexes work (short tour)

### Emails
```
[A-Z0-9._%+\-]+@(?:[A-Z0-9](?:[A-Z0-9\-]{0,61}[A-Z0-9])?\.)+[A-Z]{2,24}
```
A liberal extractor pulls candidates; a **strict, anchored validator**
(`EMAIL_STRICT` with `re.fullmatch`) decides whether each candidate is a
well-formed address. The ALU variants use **exact** anchored patterns so
`user@alueducation.com.evil.com` is rejected as a spoof.

### Credit cards
```
(?<!\d)(?:\d[ \-]?){12,18}\d(?!\d)
```
This greedily collects 13–19 digit groups (with optional space / dash
separators) and then runs **the Luhn algorithm** on the digits. Cards
that fail Luhn (e.g. the planted `1234-5678-9012-3456`) are silently
dropped. Valid PANs are **masked to the last 4 digits** (PCI-DSS style)
before they ever enter the JSON or the console.

### Phone numbers
```
\+\d{1,3}[ \-.]? (?:\(\d{1,4}\)[ \-.]?)? \d{2,4}[ \-.]? \d{2,4}[ \-.]? \d{2,4}
| \(\d{2,4}\)[ \-.]? \d{3}[ \-.]? \d{4}
| \d{3}[ \-.]\d{3}[ \-.]\d{4}
```
Three alternatives cover international, US-parens, and plain US formats.
A trailing lookahead `(?![ \-.]?\d)` refuses to swallow the middle of a
longer digit run (so partial PANs like `5454 5454 5454` are rejected).
Post-filters then drop date-shaped strings and any digit run that is a
substring of an already-recognised card number.

### URLs
```
https?://(?:[A-Z0-9\-]+\.)+[A-Z]{2,24}(?::\d{2,5})?(?:/[^\s<>"']*)?
```
Stops at whitespace and at characters that commonly close a URL in prose
(`<`, `>`, `"`, `'`), which is the main defense against pulling URLs out
of attacker-controlled HTML.

### Currency
```
(?:[$€£¥]\s?<amount>) | ((?:USD|EUR|GBP|JPY|RWF)\s+<amount>)
where <amount> = \d{1,3}(?:,\d{3})+(?:\.\d{1,2})?  |  \d+(?:\.\d{1,2})?
```
The grouped alternative **requires at least one comma** so a plain
`45000` isn't truncated to `450`.

### Times
- `TIME_24H`: `00:00`–`23:59`, optional `:SS`, with `(?<![+\-\d])` so it
  ignores timezone offsets like `+02:00`.
- `TIME_12H`: `1:00 AM` … `12:59 PM`, optional `:SS`, case-insensitive
  `AM/PM`. A 24h match immediately followed by `AM/PM` is skipped (the
  12h regex picks it up correctly instead).

### Hashtags
```
(?<![A-Za-z0-9_])#[A-Za-z][A-Za-z0-9_]*
```
Must begin with a **letter**, so purely numeric noise like `#1` is
intentionally rejected.

---

## Security considerations

This is the most important part of the assignment. The full list also
lives at the bottom of `src/main.py`.

1. **Size cap.** Input larger than 1 MiB is refused outright
   (`MAX_INPUT_BYTES`). Prevents accidental DoS from huge or
   pathological dumps.
2. **Control-character stripping.** Before regex matching, all ASCII
   control bytes are removed. Attackers can't use NUL/BEL/etc. to smuggle
   separators past the extractors.
3. **No `eval` / `exec` / shell.** Extracted data is never executed —
   everything that leaves the program is `json.dump`'d, which escapes
   automatically.
4. **Threat-first sweep + redaction.** The program first scans the
   **original text** for injection markers (XSS, SQLi, `javascript:`,
   inline event handlers, etc.) and puts the offending snippets into
   `threats_detected`. Those spans are then **blanked out** before any
   other extractor runs, so URLs, cards, phones, or emails that lived
   inside a malicious payload **cannot leak** into the clean results.
5. **Strict email validation.** `EMAIL_STRICT` uses `re.fullmatch` so
   `user@@evil..com`, `not-an-email@.com`, `also@bad@domain.com` are
   rejected and tracked in `emails.rejected`.
6. **ALU domain spoof protection.** The three ALU validators are exact
   anchored patterns (`^...@alueducation\.com$` etc.), so
   `user@alueducation.com.evil.com` is **not** classified as ALU
   official — it lands in `emails.rejected`.
7. **Luhn checksum on credit cards.** Numbers that don't pass Luhn are
   dropped, so the planted `1234-5678-9012-3456` never appears.
8. **PAN masking.** Valid card numbers are masked to the last 4 digits
   before they are written anywhere (`************5454`).
9. **Email masking in output.** Emails are written as
   `j***a@alueducation.com`, so terminal history / JSON artifacts don't
   become accidental PII dumps.
10. **URL hygiene.** Even after redaction, URLs containing `<` or
    starting with `javascript:` are dropped as a belt-and-braces measure.

---

## Sample run

```
============================================================
  ALU REGEX DATA EXTRACTION — SUMMARY
============================================================
  Emails (valid)          : 8
    - ALU official        : 3
    - ALU alumni          : 1
    - ALU SI              : 2
  Emails (rejected)       : 1
  Credit cards (Luhn ok)  : 5
  URLs                    : 7
  Phone numbers           : 6
  HTML tags               : 10
  Hashtags                : 8
  Currency amounts        : 14
  Times (24h / 12h)       : 9 / 6
  Threats quarantined     : 6
============================================================
  Full JSON written to: output/sample-output.json
```

Open `output/sample-output.json` to see the structured, masked result.
Highlights:

- The MasterCard, Visa, AmEx, Discover, and JCB test PANs all pass Luhn
  and are masked to the last 4 digits.
- The spoofed `user@alueducation.com.evil.com` is **not** in
  `alu_official` — it's in `rejected`.
- The hostile `<img src=x onerror="...">`, `javascript:alert(...)`,
  `' OR 1=1`, `DROP TABLE shipments;`, and `<script>` payloads are
  quarantined in `threats_detected`, and their internal URL
  (`https://exfil.example/?c=...`) **does not** appear in `urls`.

---

## AI usage statement

Per the assignment rules:

- I did **not** use AI to write the source code, regex patterns, or
  validation logic. Every pattern in `src/main.py` is hand-written and
  commented in my own words.
- I used AI **only** to help brainstorm realistic, messy sample text for
  `input/raw-text.txt` (the kind of dump you'd see from a real CRM
  export). This is explicitly allowed by the assignment.
