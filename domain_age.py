import whois
from datetime import datetime

# ===== MODIFIED: Part 2 — DOMAIN AGE CALCULATION FIX =====
def get_domain_age_days(domain):
    """
    Performs WHOIS lookup on the domain.
    Returns domain age in days (INT) or None if lookup fails.
    Handles list of creation dates safely.
    """
    if not domain or '.' not in domain:
        return None
        
    try:
        w = whois.whois(domain)
        # Handle these cases safely
        creation_date = w.creation_date
        
        # If creation_date is list -> use first element
        if isinstance(creation_date, list):
            creation_date = creation_date[0]
            
        if not creation_date or not isinstance(creation_date, datetime):
            return None
            
        # Ensure naive comparison
        if creation_date.tzinfo is not None:
            creation_date = creation_date.replace(tzinfo=None)
            
        age_days = (datetime.now() - creation_date).days
        return max(0, age_days)
    except Exception:
        # If WHOIS fails: domain_age_days = NULL
        return None

# Helper for display logic used in Flask/Templates
def format_domain_age_display(age_days):
    """
    PART 3 — HUMAN READABLE DISPLAY
    Converts numeric days into formatted string for UI.
    """
    if age_days is None:
        return "Domain Age Unknown"
        
    if age_days < 90:
        return f"New Domain ({age_days} days old)"
    elif age_days < 365:
        return f"{age_days} days old"
    else:
        years = age_days // 365
        return f"{years} years old"
