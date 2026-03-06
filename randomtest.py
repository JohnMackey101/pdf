import spacy

nlp = spacy.load("en_core_web_sm")
text = "8 Standard Chartered Bank Lender USD 150,000,000 6.00% USD 45,000,000"
text_2 = "5 Société Générale Lender USD 250,000,000 10.00% USD 75,000,000 6 Mizuho Bank, Ltd. Lender USD 200,000,000 8.00% USD 60,000,000"
doc = nlp(text)

print(list(doc.ents))
for ent in doc.ents:
    print(ent.text, ent.label_)