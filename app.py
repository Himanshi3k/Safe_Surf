import streamlit as st
import joblib
import numpy as np
import pandas as pd
import re
from urllib.parse import urlparse
from collections import Counter



#Loading model
model = joblib.load("phishing_model.pkl")
scaler = joblib.load("scaler.pkl")

#Extracting features
def haswww(url):
    return 1 if 'www.' in url else 0

def hashttp(url):
    return 1 if url.startswith('http') else 0

def hashttps(url):
    return 1 if url.startswith('https') else 0

def has_port(url):
    return 1 if ':' in urlparse(url).netloc else 0

def has_path(url):
    return 1 if bool(urlparse(url).path) else 0

def has_query(url):
    return 1 if bool(urlparse(url).query) else 0

def length_of_domain(url):
    return len(urlparse(url).netloc)

def number_of_dots_in_domain(url):
    return urlparse(url).netloc.count('.')

def number_of_hyphens_in_domain(url):
    return urlparse(url).netloc.count('-')

def special_characters_in_domain(url):
    return len(re.findall(r'[^a-zA-Z0-9.-]', urlparse(url).netloc))

def digits_in_domain(url):
    return sum(c.isdigit() for c in urlparse(url).netloc)

def number_of_subdomains(url):
    domain_parts = urlparse(url).netloc.split('.')
    return len(domain_parts) - 2 if len(domain_parts) > 2 else 0

def hyphen_in_subdomain(url):
    domain = urlparse(url).netloc
    subdomain = domain.split('.', 1)[0] if '.' in domain else ''
    return subdomain.count('-')

def average_subdomain_length(url):
    domain = urlparse(url).netloc
    subdomains = domain.split('.')[:-2] if len(domain.split('.')) > 2 else []
    return sum(len(s) for s in subdomains) / len(subdomains) if subdomains else 0

def average_number_of_hyphens_in_subdomain(url):
    domain = urlparse(url).netloc
    subdomains = domain.split('.')[:-2] if len(domain.split('.')) > 2 else []
    return sum(s.count('-') for s in subdomains) / len(subdomains) if subdomains else 0

def special_characters_in_subdomain(url):
    domain = urlparse(url).netloc
    subdomains = domain.split('.')[:-2] if len(domain.split('.')) > 2 else []
    return sum(len(re.findall(r'[^a-zA-Z0-9.-]', s)) for s in subdomains)

def digits_in_subdomain(url):
    domain = urlparse(url).netloc
    subdomains = domain.split('.')[:-2] if len(domain.split('.')) > 2 else []
    return sum(sum(c.isdigit() for c in s) for s in subdomains)

def repeated_digits_in_subdomain(url):
    domain = urlparse(url).netloc
    subdomains = domain.split('.')[:-2] if len(domain.split('.')) > 2 else []
    repeated_digits = sum(Counter(s).get(d, 0) > 1 for s in subdomains for d in set(s) if d.isdigit())
    return repeated_digits

def has_suspicious_words(url):
    suspicious_words = ["login", "signin", "secure", "account", "update"]
    return 0 if any(word in url.lower() for word in suspicious_words) else 1

def length_of_url(url):
    return len(url)

def number_of_dots(url):
    return url.count('.')

def number_of_hyphens(url):
    return url.count('-')

def number_of_subdirectories(url):
    return urlparse(url).path.count('/')

def number_of_query_parameters(url):
    return url.count('?')

def length_of_hostname(url):
    return len(urlparse(url).hostname or '')

def number_of_numeric_characters(url):
    return sum(c.isdigit() for c in url)

def number_of_special_characters(url):
    return len(re.findall(r'[!@#$%^&*()]', url))

def number_of_underscores(url):
    return url.count('_')

def number_of_equal_signs(url):
    return url.count('=')

def number_of_at_symbols(url):
    return url.count('@')

def number_of_dollar_signs(url):
    return url.count('$')

def number_of_exclamation_marks(url):
    return url.count('!')

def number_of_hashtag_symbols(url):
    return url.count('#')

def number_of_percent_symbols(url):
    return url.count('%')

def repeated_digits_in_url(url):
    digit_counts = Counter(c for c in url if c.isdigit())
    return sum(count > 1 for count in digit_counts.values())


def extract_features(url):
    feature_names = [
        "has_www", "has_http", "has_https", "has_port", "has_path", "has_query",
        "Length of Domain", "Number of Dots in Domain", "Number of Hyphens in Domain",
        "Special Characters in Domain", "Digits in Domain", "Number of Subdomains",
        "Hyphen in Subdomain", "Average Subdomain Length", "Average Number of Hyphens in Subdomain",
        "Special Characters in Subdomain", "Digits in Subdomain", "Repeated Digits in Subdomain",
        "Length of URL", "Number of Dots", "Number of Hyphens", "Number of Subdirectories",
        "Number of Query Parameters", "Length of Hostname", "Number of Numeric Characters",
        "Number of Special Characters", "Number of Underscores", "Number of Equal Signs",
        "Number of At Symbols", "Number of Dollar Signs", "Number of Exclamation Marks",
        "Number of Hashtag Symbols", "Number of Percent Symbols", "Repeated Digits in URL",
        "Presence of Suspicious Words"
    ]
    
    feature_values = np.array([
        haswww(url), hashttp(url), hashttps(url), has_port(url), has_path(url), has_query(url),
        length_of_domain(url), number_of_dots_in_domain(url), number_of_hyphens_in_domain(url),
        special_characters_in_domain(url), digits_in_domain(url), number_of_subdomains(url),
        hyphen_in_subdomain(url), average_subdomain_length(url), average_number_of_hyphens_in_subdomain(url),
        special_characters_in_subdomain(url), digits_in_subdomain(url), repeated_digits_in_subdomain(url),
        length_of_url(url), number_of_dots(url), number_of_hyphens(url), number_of_subdirectories(url),
        number_of_query_parameters(url), length_of_hostname(url), number_of_numeric_characters(url),
        number_of_special_characters(url), number_of_underscores(url), number_of_equal_signs(url),
        number_of_at_symbols(url), number_of_dollar_signs(url), number_of_exclamation_marks(url),
        number_of_hashtag_symbols(url), number_of_percent_symbols(url), repeated_digits_in_url(url),
        has_suspicious_words(url)
    ])

    return pd.DataFrame([feature_values], columns=feature_names)

st.title("SafeSurf")
with st.expander("ℹ️ How does this work?"):
    st.write("""
    - Our AI model analyzes the URL features.
    - It detects potential phishing attempts using ML techniques.
    - If a URL is suspicious, we recommend not clicking on it.
    """)

#Main page



url_input = st.text_input("Paste URL here:")

if st.button("Check URL"):
    if url_input:
       
        features_df = extract_features(url_input)

       
        scaled_features = scaler.transform(features_df)

        #prediction
        prediction = model.predict(scaled_features)[0]

        #result
        if prediction == 0:
            st.error("🚨 This is likely a phishing URL!")
        else:
            st.success("✅ This URL seems legitimate.")
    else:
        st.warning("⚠️ Please enter a valid URL.")




