"""
pdf_anonymizer_v0.3.py
-----------------
Detects and masks PII in multiple PDFs from an input folder, allowing the user 
approve each redaction before writing masked text back into the document. 

Once pre-requisites are met use the following command:
    python pdf_anonymizer_v0.3.py              # uses default config

Written by Htet Yan Linn
Python 3.12.12
"""

import json
import os
import re
import sys

import pymupdf
import pymupdf4llm
import spacy

# ---------------------------------------------------------------------------
# Default config (we make a default with on disk if there's nothing)
# Set any category to a fixed label like '[NAME]' or '[REDACTED]'. 
# Leave out to use the default star masking.
# ---------------------------------------------------------------------------

DEFAULT_CONFIG = {
    "output_suffix": "_anonymized",
    "spacy_model": "en_core_web_sm",
    "spacy_entities": ["PERSON", "GPE", "ORG"],
    "mask_style": {
        "PERSON":      "[PERSON XYZ]",
        "EMAIL":       "person@domain.com",
        "PHONE":       "[PHONE NUM]",
        "INTL_PHONE":  "[PHONE NUM]",
        "SSN":         "",
        "CREDIT_CARD": "",
        "ACCT_NUMBER": "",
        "ADDRESS":     "[ADDRESS LINE]",
        "GPE":         "[LOCATION]",
        "ORG":         "[COMPANY XYZ]"
    },
    "spacy_blocklist": [
        "mm", "dd", "yyyy", "Page", "Statement Date", "Period Covered",
        "Opening Balance", "Closing Balance", "Account Type", "Branch Name",
        "Current Account", "Statement", "Date", "Balance", "Debit", "Credit",
        "Page of", "Page    of"
    ],
    "patterns": {
        "EMAIL":       r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b",
        "PHONE":       r"(?:(?:\+44|0)[\s-]?(?:\d[\s-]?){9,10})\b",
        "INTL_PHONE":  r"\+\d{1,3}[\s-]?(?:\d[\s-]?){6,14}\b",
        "SSN":         r"\b\d{3}[-]?\d{2}[-]?\d{4}\b",
        "CREDIT_CARD": r"\b(?:\d{4}[-\s]?){3}\d{4}\b",
        "ADDRESS":     r"\d{2,5}\s[A-Z][a-zA-Z\s,]+(?:St|Ave|Blvd|Dr|Rd|Ln|Way|Ct|Court|STE|Suite|Hwy|Pkwy)[^\n]*?\d{5}",

        # These guys get default masking for now..
        # Account Number variants (captures digits and hyphens only) 
        "ACCT_NUMBER": r"Account Number:\s*([\d\-]+)",

        "ACCOUNT_NO_COLON": r"Account No:\s*([\d\-]+)",
        "ACCOUNT_NO_DOT_COLON": r"Account No\.\s*:\s*([\d\-]+)",
        "ACCOUNT_NUM_COLON": r"Account Num:\s*([\d\-]+)",
        "ACCOUNT_HASH": r"Account\s*#\s*([\d\-]+)",

        "ACCT_NUMBER_COLON": r"Acct Number:\s*([\d\-]+)",
        "ACCT_NO_COLON": r"Acct No:\s*([\d\-]+)",
        "ACCT_NO_DOT_COLON": r"Acct No\.\s*:\s*([\d\-]+)",
        "ACCT_HASH": r"Acct\s*#\s*([\d\-]+)",

        "A_C_NUMBER_COLON": r"A/C Number:\s*([\d\-]+)",
        "A_C_NO_COLON": r"A/C No:\s*([\d\-]+)",
        "A_C_HASH": r"A/C\s*#\s*([\d\-]+)",

        "ACC_NO_COLON": r"Acc No:\s*([\d\-]+)",
        "ACC_HASH": r"Acc\s*#\s*([\d\-]+)",

        # SWIFT/BIC (8 or 11 chars) 
        "SWIFT_COLON": r"SWIFT:\s*([A-Z]{4}[A-Z]{2}[A-Z0-9]{2}(?:[A-Z0-9]{3})?)\b",
        "SWIFT_CODE_COLON": r"SWIFT Code:\s*([A-Z]{4}[A-Z]{2}[A-Z0-9]{2}(?:[A-Z0-9]{3})?)\b",
        "BIC_COLON": r"BIC:\s*([A-Z]{4}[A-Z]{2}[A-Z0-9]{2}(?:[A-Z0-9]{3})?)\b",
        "BIC_CODE_COLON": r"BIC Code:\s*([A-Z]{4}[A-Z]{2}[A-Z0-9]{2}(?:[A-Z0-9]{3})?)\b",
        "SWIFT_BIC_COLON": r"SWIFT/BIC:\s*([A-Z]{4}[A-Z]{2}[A-Z0-9]{2}(?:[A-Z0-9]{3})?)\b",


        # ABA / US Routing Number (exactly 9 digits)
        "ABA_ROUTING_COLON": r"ABA Routing Number:\s*(\d{9})\b",
        "ROUTING_NUMBER_COLON": r"Routing Number:\s*(\d{9})\b",
        "ROUTING_TRANSIT_NUMBER_COLON": r"Routing Transit Number:\s*(\d{9})\b",
        "ACH_ROUTING_NUMBER_COLON": r"ACH Routing Number:\s*(\d{9})\b",
        "RTN_COLON": r"RTN:\s*(\d{9})\b",
        "ABA_COLON": r"ABA:\s*(\d{9})\b",


        # IBAN (allows spaces; total length 15–34 excluding spaces) 
        "IBAN_COLON": r"IBAN:\s*([A-Z]{2}\d{2}(?:\s?[A-Z0-9]){11,30})\b",
        "IBAN_NUMBER_COLON": r"IBAN Number:\s*([A-Z]{2}\d{2}(?:\s?[A-Z0-9]){11,30})\b",
        "IBAN_NO_COLON": r"IBAN No:\s*([A-Z]{2}\d{2}(?:\s?[A-Z0-9]){11,30})\b",
    }
}

DEFAULT_CONFIG_PATH = "pdfanon_config.json"

# ---------------------------------------------------------------------------
# Config helper functions
# ---------------------------------------------------------------------------

def load_config(path: str) -> dict:
    if os.path.exists(path):
        with open(path) as f:
            cfg = json.load(f)
        print(f"[config] Loaded: {path}")
        return cfg
    else:
        # Write default and return it
        with open(path, "w") as f:
            json.dump(DEFAULT_CONFIG, f, indent=2)
        print(f"[config] No config found. Wrote default config to: {path}")
        return DEFAULT_CONFIG


# ---------------------------------------------------------------------------
# Masking functions
# ---------------------------------------------------------------------------

def mask_name(name: str) -> str:
    parts = name.strip().split()
    if len(parts) == 1:
        return parts[0][0] + "*" * (len(parts[0]) - 2) + parts[0][-1]
    return parts[0][0] + "*" * (len(parts[0]) - 1) + " " + "*" * (len(parts[-1]) - 1) + parts[-1][-1]

def mask_email(email: str) -> str:
    name, domain = email.split("@")
    return name[0] + "***@" + domain[0] + "***.com"

def mask_account(acct: str) -> str:
    out = ""
    for i, char in enumerate(acct):
        if char == "-" or i < 1 or i > len(acct) - 2:
            out += char
        else:
            out += "*"
    return out

def mask_ssn(ssn: str) -> str:
    digits = re.sub(r"\D", "", ssn)
    return digits[0] + "***" + digits[-1]

def mask_phone(phone: str) -> str:
    if phone[0] == "+":
        return phone[:2] + "***" + phone[-1]
    return phone[0] + "***" + phone[-1]

def mask_credit_card(cc: str) -> str:
    digits = re.sub(r"\D", "", cc)
    return digits[0] + "*** **** **** ***" + digits[-1]

def mask_address(addr: str) -> str:
    street_types = ["St", "Ave", "Blvd", "Dr", "Rd", "Ln", "Way",
                    "Ct", "Court", "Suite", "Hwy", "Pkwy"]
    parts = addr.strip().split()
    masked = []
    for i, part in enumerate(parts):
        if i == 0:
            masked.append(part[0] + "***")
        elif i == len(parts) - 1:
            masked.append("***" + part[-1])
        elif part in street_types:
            masked.append(part)
        else:
            masked.append("***")
    return " ".join(masked)

# Default mask for categories that aren't in mask_fn
def mask_default(word: str) -> str:
    out = ""
    for i, char in enumerate(word):
        if i < 1 or i > len(word) - 2:
            out += char
        else:
            out += "*"
    return out

MASK_FN = {
    "PERSON":      mask_name,
    "EMAIL":       mask_email,
    "ACCT_NUMBER": mask_account,
    "SSN":         mask_ssn,
    "PHONE":       mask_phone,
    "INTL_PHONE":  mask_phone,
    "CREDIT_CARD": mask_credit_card,
    "ADDRESS":     mask_address,
    "GPE":         lambda x: x[0] + "*" * (len(x) - 2) + x[-1],
    "ORG":         lambda x: x[0] + "*" * (len(x) - 2) + x[-1],
}

def resolve_mask(original: str, cat: str, cfg: dict) -> str:
    """
    Returns the masked string for a given original + category.
    If the config has a non-empty label for that category (e.g. '[NAME]'),
    that label is used as-is. Otherwise falls back to the default star-masking function.

    In the case where a new pattern has been added but there is no masking func it
    defaults to mask_default.
    """
    label = cfg.get("mask_style", {}).get(cat, "")
    if label:
        return label
    #fn = MASK_FN.get(cat)
    #return fn(original) if fn else original
    fn = MASK_FN.get(cat, mask_default)
    return fn(original)


# ---------------------------------------------------------------------------
# Processing functions
# ---------------------------------------------------------------------------

# Merges lines
def merge_lines(lines: list, nlp) -> list:
    merged = []
    i = 0
    while i < len(lines):
        current = lines[i]

        # merge label: value pairs. cases where you have "Account number: 2394892348"
        if current.endswith(":") and i + 1 < len(lines):
            merged.append(current + " " + lines[i + 1])
            i += 2
            continue

        # Checks if current line is a location. If it is then we have a potential address
        # chain. Looks ahead up to 3 indices as address lines can be chunked up to 4 lines.
        # May have to reduce lookahead to prevent false flags.

        current_is_street = bool(re.search(r"^\d+[A-Za-z]?\s+[A-Z]", current))
        if current_is_street and i + 1 < len(lines):
            combined = current
            j = i + 1
            while j < len(lines) and j <= i + 3:
                next_line = lines[j]
                doc = nlp(next_line)
                next_is_gpe = any(ent.label_ == "GPE" for ent in doc.ents)

                # Location matches the following patterns
                # 1. Santa Monica, CA 90403 (Place, 2 letter state, 6 zipcode)
                # 2. Barclays Bank, London (Place, Another place)
                # 3. Springfield 62704 (Place+5digit zipcode)
                # 4. United Kingdom/England/Ireland/etc..

                next_is_location = bool(re.search(
                    r"([A-Z][a-zA-Z\s]+,\s*[A-Z]{2}\s*\d{4,6}"
                    r"|[A-Z][a-zA-Z\s]+,\s*[A-Z][a-zA-Z\s]+"
                    r"|[A-Z][a-zA-Z]+\s+[A-Z]{2}\s+\d{5}"  
                    r"|United\sKingdom|England|Scotland|Wales)",
                    next_line
                ))
                if next_is_gpe or next_is_location:
                    combined += " " + next_line
                    j += 1
                else:
                    break
            if j > i + 1:
                merged.append(combined)
                i = j
                continue
        merged.append(current)
        i += 1
    return merged

def process_doc(path: str, nlp) -> list:
    doc = pymupdf4llm.to_markdown(path)
    
    # Split text by '\n' and remove any whitespace lines 
    lines = [t for t in doc.split("\n") if t.strip()]

    # remove any weird asterick formatting
    lines = [re.sub(r'\*+', '', line).strip() for line in lines]
    return merge_lines(lines, nlp) # merge lines once we're donezo

def detect_pii(text_arr: list, cfg: dict, nlp) -> tuple[dict, dict]:
    """Returns dicts for pii_masked and pii_cat keyed by original info."""

    # We're loading the configs here
    patterns            = cfg["patterns"]               # Regex patterns
    blocklist           = set(cfg["spacy_blocklist"])   # Spacy blocklist for false flags
    spacy_ents          = cfg["spacy_entities"]         # Spacy entities we want to redact ("PERSON, GPE, ORG")
    non_colon_entities  = ['EMAIL', 'INTL_PHONE', 'PHONE', 'SSN','CREDIT_CARD','ADDRESS']

    pii_masked      = {} # dict for original:masked
    pii_cats        = {} # dict for original:category
    address_matches = [] # dict for seen addresses 

    for line in text_arr:
        # === REGEX SEARCH === #
        for cat, pattern in patterns.items():
            for match in re.finditer(pattern, line):
                original = match.group(0) if cat in non_colon_entities else match.group(1)
                if original not in pii_masked:
                    pii_masked[original] = resolve_mask(original, cat, cfg)
                    pii_cats[original]   = cat
                    if cat == "ADDRESS":
                        address_matches.append(original)

        # === NAMED-ENTITY-RECOGNITION (NER) WITH spaCy === #
        doc = nlp(line.title()) # titling to pick up flags like 'Jon smith'
        for ent in doc.ents:
            if ent.label_ not in spacy_ents:
                continue
            # save original_text since it'll have diff casing from what spacy sees
            original_text = line[ent.start_char:ent.end_char].strip()
            clean = ent.text.strip()

            # check if spacy accidentally caught any numbers like 'jon smith 23323' or something..
            if any(c.isdigit() for c in clean):
                clean = re.split(r"\d", clean)[0].strip()
                original_text = original_text[: len(clean)]
            
            # check if clean is in our blocklist
            if not clean or clean in blocklist:
                continue

            # check if clean is in any of the addresses 
            # COULD be problematic for situations like 'Monica' and 'Santa Monica'...
            if any(clean in addr for addr in address_matches):
                continue

            # apply masking after all checks are done
            if original_text not in pii_masked:
                pii_masked[original_text]   = resolve_mask(clean, ent.label_, cfg)
                pii_cats[original_text]     = ent.label_

    #print(pii_masked) # to debug
    return pii_masked, pii_cats


# ---------------------------------------------------------------------------
# Reviewing stuff
# ---------------------------------------------------------------------------

def review_redactions(pii_masked: dict, pii_cats: dict) -> dict:
    """Script that lets user walk through each redaction and approve with Y/N"""
    approved: dict = {}
    total = len(pii_masked)
    if total == 0:
        print("\nNo PII detected.")
        return approved

    print(f"\n{'─'*60}")
    print(f"  {total} potential redaction(s) found. Review each one:")
    print(f"{'─'*60}\n")

    for idx, (original, masked) in enumerate(pii_masked.items(), start=1):
        cat = pii_cats.get(original, "UNKNOWN")
        print(f"  [{idx}/{total}]  Category : {cat}")
        print(f"           Original : {original!r}")
        print(f"           Masked   : {masked!r}")
        while True:
            answer = input("           Redact? [Y/n]: ").strip().lower()
            if answer in ("", "y", "yes"):
                approved[original] = masked
                print("           [✓] Approved\n")
                break
            elif answer in ("n", "no"):
                print("           [X] Skipped\n")
                break
            else:
                print("           Please enter Y or N.")

    return approved


# ---------------------------------------------------------------------------
# Writing the redactions after approval 
# ---------------------------------------------------------------------------

def redact_pdf(input_path: str, output_path: str, findings: dict) -> None:
    doc = pymupdf.open(input_path)

    for page in doc:
        # Build a font-size map so it matches page sizes 
        size_map = {}
        for block in page.get_text("dict")["blocks"]:
            if "lines" in block:
                for line in block["lines"]:
                    for span in line["spans"]:
                        # maps stripped TEXT to the SIZE 
                        size_map[span["text"].strip()] = span["size"]

        # We quickly sort the findings by longest so 
        # we avoid partial-overlap problems
        # Ex. "London", then "Barclays London" would flag london twice if london was
        # written first.
        sorted_findings = dict(
            sorted(findings.items(), key=lambda x: len(x[0]), reverse=True)
        )

        redacted_rects = [] # Already redacted rectangles
        rects_to_draw  = {} # Rectangle coords we're meant to draw for each mask

        for original, masked in sorted_findings.items():
            hits = page.search_for(original)
            new_hits = []
            for rect in hits:
                if any(rect.intersects(r) for r in redacted_rects):
                    continue
                new_hits.append(rect)
                redacted_rects.append(rect)
            if new_hits:
                rects_to_draw[original] = new_hits
                for rect in new_hits:
                    page.add_redact_annot(rect, fill=(1, 1, 1))

        # actually apply rects, ignore images 
        page.apply_redactions(images=pymupdf.PDF_REDACT_IMAGE_NONE)

        # write stuff over the white masks...
        for original, rects in rects_to_draw.items():
            masked    = findings[original]
            # default fontsize 10 if we cant find the sizemap
            fontsize  = size_map.get(original.strip(), 10)
            for rect in rects:
                page.insert_text(
                    (rect.x0, rect.y1 - 2),
                    masked,
                    fontname="helv",
                    fontsize=fontsize,
                    color=(0, 0, 0),
                )

    doc.save(output_path, garbage=4, deflate=True)
    doc.close()
    print(f"\n[✓] Saved anonymized PDF: {output_path}")


# ---------------------------------------------------------------------------
# Main entry point
# ---------------------------------------------------------------------------

def main() -> None:
    cfg = load_config(DEFAULT_CONFIG_PATH)

    # Load spacy model
    model = cfg.get("spacy_model", "en_core_web_sm")
    try:
        nlp = spacy.load(model)
    except OSError:
        print(f"[error] spaCy model '{model}' not found.")
        print(f"        Run:  python -m spacy download {model}")
        sys.exit(1)

    # Check if input_files directory exists
    input_dir = "input_files"
    output_dir = "output_files"
    
    if not os.path.exists(input_dir):
        print(f"[error] Input directory '{input_dir}' not found.")
        print("Please create an 'input_files' folder and place your PDF files there.")
        sys.exit(1)
    
    # Create output directory if it doesn't exist
    if not os.path.exists(output_dir):
        os.makedirs(output_dir)
        print(f"[info] Created output directory: {output_dir}")

    # Get all PDF files from input directory
    pdf_files = [f for f in os.listdir(input_dir) if f.lower().endswith('.pdf')]
    
    if not pdf_files:
        print(f"[error] No PDF files found in '{input_dir}' directory.")
        sys.exit(1)
    
    print(f"\n" + "=" * 60)
    print("         PDF Anonymizer — Batch Processing Tool")
    print("=" * 60)
    print(f"\nFound {len(pdf_files)} PDF file(s) in '{input_dir}' directory:")
    for i, pdf_file in enumerate(pdf_files, 1):
        print(f"  {i}. {pdf_file}")
    
    # Process each PDF file
    for pdf_file in pdf_files:
        pdf_path = os.path.join(input_dir, pdf_file)
        print(f"\n{'─'*60}")
        print(f"Processing: {pdf_file}")
        print(f"{'─'*60}")
        
        # Process document
        print(f"\n[->] Reading and parsing: {pdf_file}")
        lines = process_doc(pdf_path, nlp)

        print("[->] Detecting PII …")
        pii_masked, pii_cats = detect_pii(lines, cfg, nlp)

        if not pii_masked:
            print("\nNo PII detected. Skipping redaction.")
            continue

        # Review
        approved = review_redactions(pii_masked, pii_cats)

        if not approved:
            print("No redactions approved. Skipping this file.")
            continue

        # Build output path in output_files directory
        base, ext = os.path.splitext(pdf_file)
        suffix    = cfg.get("output_suffix", "_anonymized")
        out_path  = os.path.join(output_dir, base + suffix + ext)

        # Redact + save
        print(f"\n[→] Applying {len(approved)} redaction(s) …")
        redact_pdf(pdf_path, out_path, approved)

    print(f"\n{'─'*60}")
    print("Batch processing completed!")
    print(f"Anonymized files saved to: {output_dir}")
    print(f"{'─'*60}")


if __name__ == "__main__":
    main()