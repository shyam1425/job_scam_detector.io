import re
from domain_age import get_domain_age_days


def extract_domain(url):
    domain = re.sub(r'^https?://', '', url.strip(), flags=re.IGNORECASE)
    domain = re.sub(r'^www\.', '', domain, flags=re.IGNORECASE)
    return re.split(r'[/:?#\s]', domain)[0].lower()


test_urls = [
    "https://www.tcs.com",
    "http://tcs.com/careers",
    "tcs.com",
    "https://careers.tcs.com",
]

print("Testing Extraction:")
for url in test_urls:
    print(f"URL: {url} -> Domain: {extract_domain(url)}")

age = get_domain_age_days("tcs.com")
print(f"\nDomain age for tcs.com: {age if age is not None else 'unknown'}")
