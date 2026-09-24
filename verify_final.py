from domain_age import get_domain_age_days

print("--- Testing Domain Age Fix ---")
age = get_domain_age_days("tcs.com")
print(f"Final Age for tcs.com: {age if age is not None else 'unknown'} days")
