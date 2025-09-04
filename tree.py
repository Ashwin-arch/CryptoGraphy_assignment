import streamlit as st
import nltk
import spacy
from nltk import CFG

# Load spaCy model
nlp = spacy.load("en_core_web_sm")

# -------------------------------
# Constituency Parser (Demo)
# -------------------------------
grammar = CFG.fromstring("""
  S -> NP VP
  NP -> Det N | Det N PP | 'I'
  VP -> V NP | V NP PP | Aux VBN PP | Aux VBN
  PP -> P NP
  Det -> 'a' | 'the' | 'The'
  N -> 'boy' | 'ball' | 'dog' | 'cat'
  V -> 'kicked' | 'saw' | 'chased' | 'played'
  Aux -> 'was' | 'is'
  VBN -> 'kicked' | 'seen' | 'chased' | 'played'
  P -> 'by' | 'with'
""")

parser = nltk.ChartParser(grammar)

def constituency_parse(sentence: str):
    tokens = sentence.split()
    trees = []
    try:
        for tree in parser.parse(tokens):
            trees.append(tree)
    except ValueError:
        pass
    return trees

# -------------------------------
# Dependency Parser (spaCy)
# -------------------------------
def dependency_parse(sentence: str):
    doc = nlp(sentence)
    rows = []
    for token in doc:
        rows.append({
            "Token": token.text,
            "Dep": token.dep_,
            "Head": token.head.text,
            "Children": [child.text for child in token.children]
        })
    return rows

# -------------------------------
# Convert Active ↔ Passive
# -------------------------------
def convert_sentence(sentence: str):
    doc = nlp(sentence)
    subj, obj, verb = "", "", ""

    for token in doc:
        if token.dep_ in ["nsubj", "nsubjpass"]:
            subj = token.text
        elif token.dep_ in ["dobj", "pobj"]:
            obj = token.text
        elif token.dep_ == "ROOT":
            verb = token.lemma_

    if any(t.dep_ == "nsubj" for t in doc):  # Active → Passive
        return "active", f"The {obj} was {verb}ed by the {subj}"
    elif any(t.dep_ == "nsubjpass" for t in doc):  # Passive → Active
        return "passive", f"The {subj} {verb}ed the {obj}"
    return "unknown", None

# -------------------------------
# Streamlit UI
# -------------------------------
st.title("Parse Tree Generator (Active ↔ Passive)")

sentence = st.text_input("Enter a sentence:")

if sentence:
    st.subheader("Original Sentence")
    st.write(sentence)

    # Constituency Parse
    st.subheader("Constituency Parse (NLTK)")
    trees = constituency_parse(sentence)
    if trees:
        for tree in trees:
            st.text(tree)
    else:
        st.warning(" No constituency parse (grammar too limited).")

    # Dependency Parse
    st.subheader("Dependency Parse (spaCy)")
    dep_rows = dependency_parse(sentence)
    st.table(dep_rows)

    # Conversion
    voice, converted = convert_sentence(sentence)
    if converted:
        st.subheader(f"Converted Sentence ({voice} → other)")
        st.write(converted)

        # Constituency Parse of Converted
        st.subheader("Constituency Parse (Converted)")
        trees = constituency_parse(converted)
        if trees:
            for tree in trees:
                st.text(tree)
        else:
            st.warning(" No constituency parse (grammar too limited).")

        # Dependency Parse of Converted
        st.subheader("Dependency Parse (Converted)")
        dep_rows = dependency_parse(converted)
        st.table(dep_rows)
