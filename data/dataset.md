# Dataset — composition and provenance

**Total examples: 86** (up from 65 as of this update)
**Scam: 52 | Legitimate: 34**

This is a genuinely small dataset. Numbers below are reported plainly,
including where it's still weak, per the project's own stated
"honest metrics over inflated claims" standard.

## Category breakdown (after this update)

| Category | Count | Status |
|---|---:|---|
| safe | 34 | OK |
| otp_fraud | 6 | OK |
| upi_request | 5 | OK (borderline) |
| invest_scam | 5 | OK (borderline) |
| internship_fee | 4 | Still thin |
| delivery_scam | 4 | Still thin |
| telegram_job | 4 | Still thin |
| credential_harvesting | 4 | Still thin |
| lottery_prize | 3 | Still thin |
| bank_impersonation | 3 | Still thin |
| job_fee | 3 | Still thin |
| qr_scam | 3 | Still thin |
| tech_support | 3 | Still thin |
| scholarship_fee | 2 | Still thin |
| sextortion | 2 | Still thin — deliberately not padded, see note below |
| discord_scam | 1 | Still thin |

**Do not present this as "fixed."** Half the categories are still under
5 examples. This update closes the gap on 2 categories (upi_request,
invest_scam) and adds real hard negatives; it does not solve dataset
size as a whole. Continued growth of the thin categories should stay
on the roadmap.

## Provenance (the `source` column)

Before this update, every row's `source` field said `"dataset"` —
a placeholder with no actual information. This has been corrected to:

- **`unknown_provenance`** — applied to all 65 original rows. Their true
  origin (self-written vs. adapted from a real reported message) was
  never tracked and cannot be reconstructed after the fact. **If you
  personally know any of these came from an actual reported scam
  message (e.g. cybercrime.gov.in, a forwarded WhatsApp scam, a
  friend's experience), please correct that specific row's `source`
  field manually** — that distinction matters a lot for credibility
  if a judge asks "is this synthetic or real."
- **`self_written_representative`** — new scam-category examples added
  in this update. Written to represent common, well-documented scam
  patterns (fake Telegram jobs, UPI PIN-sharing requests, credential
  phishing), not copied or adapted from any specific real message.
  Labeled honestly as synthetic, not claimed as collected data.
- **`self_written_hard_negative`** — new legitimate-message examples
  added in this update, specifically written to be genuinely ambiguous
  (internship/scholarship/fee language with no built-in safety
  disclaimer), to actually test false-positive rate rather than pad
  the "safe" count with easy examples.

## Why sextortion wasn't padded to 5

Fabricating additional sextortion-scam example text for a training
dataset means generating plausible-sounding extortion/coercion message
templates. Even as clearly-synthetic training data, that felt like the
wrong tradeoff for a small, honest category-count bump — it's exactly
the kind of category where using real, properly-sourced reported
examples (e.g. from cybercrime.gov.in advisories, with permission/
attribution) is the right way to grow it, not template generation.
Recommend sourcing this category deliberately rather than synthetically.

## Known limitation: hard negatives are still synthetic, not real

The 10 new hard-negative examples are self-written to be representative
of real legitimate-message patterns, not pulled from actual sent
messages. If you have access to real, anonymized legitimate internship/
scholarship/placement notices (e.g. from your own inbox, with personal
details removed), swapping some of these synthetic examples for real
ones would meaningfully strengthen this section for judge scrutiny.