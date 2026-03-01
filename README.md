# PDF Anonymizer

This is an interactive command-line tool that does the following things:
1. Detects personally identifiable information (PII) in a PDF
2. Lets you approve or skip each redaction one by one
3. Writes the masked text back into the document in-place, preserving the original layout and font sizes. 

---

## Requirements

- Python **3.12** (3.14 is not supported - spacy is incompatible..)
- Make sure you get these packages:

```
pip install pymupdf pymupdf4llm spacy
python -m spacy download en_core_web_sm
```

---

## Usage

```
python pdf_anonymizer.py
```

You'll be prompted to enter a PDF path. The tool detects PII, then walks you through each finding for approval.

If no config file exists at the specified path, a default one is written there automatically on first run.

---

## How it works

1. The PDF is parsed into lines of text via `pymupdf4llm`
2. Adjacent lines are intelligently merged (e.g. `Account Number:` + `123456`, or multi-line addresses)
3. PII is detected using two methods one after another:
   - **Regex patterns** -> catches structured fields like emails, phone numbers, SSNs, credit cards, account numbers, addresses. You can add more of these in the config.
   - **spacy NER** — named entity recognition for people (`PERSON`), locations (`GPE`), and organisations (`ORG`)
4. Each detection is shown with its category, original value, and proposed masked value. And you approve or skip with `Y/N`
5. Approved redactions are applied: the original text is blocked out with a white rectangle and the masked string is drawn back at the same position and font size (roughly)
6. The anonymized PDF is saved in the same place as the original with a `_anonymized` suffix (you can configure this as well)

---

## Interactive review

```
This is what a sample review looks like . . .

────────────────────────────────────────────────────────────
  9 potential redaction(s) found. Review each one:
────────────────────────────────────────────────────────────

  [1/9]  Category : PERSON
         Original : 'Jon Smith'
         Masked   : 'J** ****h'
         Redact? [Y/n]:
```

Press **Enter** or **Y** to approve, **N** to skip. Only approved redactions are written to the output file.

---

## Configuration

The config file is a JSON file (`pdfanon_config.json` by default). A full default config is auto-generated on first run.

These are the fields you can edit:

### `output_suffix`
This is the suffix for the anonymized file.
```json
"output_suffix": "_anonymized"
```
`report.pdf` -> `report_anonymized.pdf`

---

### `spacy_model`
The spacy model to use for named entity recognition.
```json
"spacy_model": "en_core_web_sm"
```
For higher accuracy (slower), swap in `en_core_web_trf` after installing it.

---

### `spacy_entities`
Which NER entity types to flag. Remove any you don't want detected.
```json
"spacy_entities": ["PERSON", "GPE", "ORG"]
```

---

### `spacy_blocklist`
Terms that spaCy sometimes mis-flags as entities. 
You can any false positives you encounter here so the anonymizer gets better.
```json
"spacy_blocklist": ["Balance", "Date", "Statement", "Credit", ...]
```

---

### `mask_style`
Controls how each category is masked. Set a value to a fixed label to override the default star-masking, or leave it as `""` to use the built-in function.

For example you could have people be redacted as [NAME] instead of 'J*** ***h'

```json
"mask_style": {
  "PERSON":      "[NAME]",
  "EMAIL":       "[EMAIL]",
  "PHONE":       "",
  "INTL_PHONE":  "",
  "SSN":         "[REDACTED]",
  "CREDIT_CARD": "[REDACTED]",
  "ACCT_NUMBER": "",
  "ADDRESS":     "[ADDRESS]",
  "GPE":         "",
  "ORG":         ""
}
```

Leaving the style as an empty string ("") defaults to star-masking. 

| Category | Example input | Default masked output |
|---|---|---|
| `PERSON` | `Jon Smith` | `J** ****h` |
| `EMAIL` | `jon@hsbc.com` | `j***@h***.com` |
| `PHONE` | `07911123456` | `0***6` |
| `INTL_PHONE` | `+44 7911 123456` | `+4***6` |
| `SSN` | `123-45-6789` | `1***9` |
| `CREDIT_CARD` | `4111 1111 1111 1111` | `4*** **** **** ***1` |
| `ACCT_NUMBER` | `111-234-567-890` | `1**-***-***-**0` |
| `ADDRESS` | `12 Baker St London W1` | `1*** *** St ***n` |
| `GPE` / `ORG` | `London` | `L****n` |

---

### `patterns`
Regex patterns used for structured PII detection. You can modify existing ones or add new categories. 

The more regex patterns that suit your needs, the better the accuracy.
```json
"patterns": {
  "EMAIL": "\\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\\.[A-Za-z]{2,}\\b",
  "MY_CUSTOM_ID": "ID-\\d{6}"
}
```
IF YOU ARE ADDING A NEw CATEGORY HERE MAKE SURE YOU ALSO ADD IT TO `mask_style`.
If you forget to, it defaults to mask_default, star- masking.

---

## Notes

- The original PDF is NEVER modified. The output is always a new file.
- Longest strings are redacted first to make sure we don't double-write terms (e.g. `Barclays Bank London` is redacted before `London` or else we have London being written twice).
- The phone regex is tuned for UK numbers by default. Update the `PHONE` pattern in the config for other regions. `INTL_PHONE` covers international numbers somewhat.
- spacy NER sees the text as title-cased to improve detection of names in all-caps or all-lowercase documents, but this can occasionally lead to false positives... (use the `spacy_blocklist` to block any you find)
