import re
from domain_age import get_domain_age

def extract_domain(url):
    domain = re.sub(r'^https?://', '', url)
    domain = re.sub(r'^www\.', '', domain)
    domain = domain.split('/')[0]
    return domain

test_urls = [
    "https://www.tcs.com",
    "http://tcs.com/careers",
    "tcs.com",
    "https://careers.tcs.com"
]

print("Testing Extraction:")
for url in test_urls:
    print(f"URL: {url} -> Domain: {extract_domain(url)}")

# Mock some values to see if score improves
pred_prob = 0.5 # Model uncertainty
scam_count = 0
domain_age = 5000 # Approximately 13 years for tcs.com
clean_website = "tcs.com"
trusted_domains = ['tcs.com', 'google.com']

penalty = (pred_prob * 50) + (scam_count * 10)
if domain_age > 365:
    penalty -= 20
elif domain_age == 0:
    penalty += 15
else:
    penalty += max(0, 15 - (domain_age / 30))

if any(trusted in clean_website for trusted in trusted_domains):
    penalty -= 30

trust_score = max(0, min(100, 100 - penalty))
print(f"\nMocked Result for TCS:")
print(f"Prob: {pred_prob}, Scam: {scam_count}, Age: {domain_age}")
print(f"Penalty: {penalty}")
print(f"Trust Score: {trust_score}")
