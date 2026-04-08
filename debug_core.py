import whois
from datetime import datetime
import re

def get_domain_age_test(domain):
    try:
        print(f"Attempting WHOIS for: {domain}")
        w = whois.whois(domain)
        print(f"WHOIS Keys: {w.keys()}")
        print(f"Creation Date: {w.creation_date}")
        
        creation_date = w.creation_date
        if isinstance(creation_date, list):
            creation_date = creation_date[0]
            
        if isinstance(creation_date, datetime):
            return (datetime.now() - creation_date).days
        return 0
    except Exception as e:
        print(f"Error: {e}")
        return 0

scam_keywords = ['urgent', 'immediate hire', 'no experience', 'work from home', 'money', 'apply now', 'fee', 'guaranteed', 'too good']

def count_scam_keywords_test(text):
    text = text.lower()
    count = 0
    for kw in scam_keywords:
        if kw in text:
            print(f"Matched keyword: {kw}")
            count += 1
    return count

print("--- Testing WHOIS ---")
print(f"Age for tcs.com: {get_domain_age_test('tcs.com')}")

print("\n--- Testing Keywords ---")
sample_text = "Urgent: Immediate hire for work from home. No experience needed. Apply now, no fee."
print(f"Count: {count_scam_keywords_test(sample_text)}")
