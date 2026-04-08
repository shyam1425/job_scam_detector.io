from flask import Flask, request, render_template, jsonify
import pymysql
import pymysql.cursors
import joblib
import re
from ocr import extract_text
from domain_age import get_domain_age_days, format_domain_age_display
from sklearn.feature_extraction.text import TfidfVectorizer
import os
import uuid
import sys
from googlesearch import search

app = Flask(__name__)
model = joblib.load('job_classifier.pkl')
scam_keywords = [
    'urgent hiring', 'immediate joiner', 'no experience required', 
    'work from home opportunity', 'telegram contact', 'whatsapp only',
    'guaranteed income', 'quick money'
]

scam_override_keywords = [
    'registration fee required',
    'security deposit required',
    'training fee required',
    'pay to confirm job',
    'processing fee required',
    'slot booking fee',
    'pay before joining',
    'pay for interview',
    'visa processing fee',
    'send money to apply'
]

# MySQL config
db_config = {
    'host': 'localhost',
    'user': 'root',
    'password': 'Shyam@2005',
    'database': 'scam_detector'
}


# ===== NEW CODE =====
# ===== NEW CODE: Job Cloning Detection =====
def detect_job_cloning(title, description):
    """
    Detects if the job description is cloned from other websites.
    Uses googlesearch-python to find similar postings.
    """
    if not description or len(description.split()) < 8:
        return "Low"
    
    # Extract first 8-10 words as query
    query_words = description.split()[:10]
    search_query = f'"{ " ".join(query_words) }"'
    
    trusted_portals = ['linkedin.com', 'indeed.com', 'glassdoor.com', 'naukri.com', 'foundit.in', 'monster.com', 'simplyhired.com']
    
    try:
        # Perform search
        results = []
        # num_results=5 to keep it fast
        for j in search(search_query, num_results=5):
            results.append(j)
        
        if not results:
            return "Low"
            
        found_on_trusted = False
        suspicious_count = 0
        
        for url in results:
            domain = extract_domain(url)
            if any(portal in domain for portal in trusted_portals):
                found_on_trusted = True
            else:
                suspicious_count += 1
                
        if found_on_trusted and suspicious_count == 0:
            return "Low"
        elif suspicious_count >= 3:
            return "High"
        elif suspicious_count > 0:
            return "Medium"
            
        return "Low"
    except Exception:
        return "Low"

def generate_ai_explanation(classification, trust_score, scam_keywords, domain_age_days, email_domain, platform, clone_risk="Low", impersonation_flag="No"):
    """
    Generates a human-friendly explanation and identifies specific risk factors.
    Includes Job Cloning Analysis and Brand Impersonation detection.
    """
    try:
        explanation = ""
        risk_indicators = []
        
        # PIPELINE CONSISTENCY FIX
        if classification == "Safe":
            explanation = "No major risk factors detected."
        elif classification == "Suspicious":
            explanation = "This job shows some risk indicators. Verify company details."
        elif classification == "Dangerous":
            explanation = "High fraud risk detected. This job posting contains strong scam indicators."
        else:
            explanation = "Insufficient data to generate explanation."
        # END PIPELINE CONSISTENCY FIX
            
        # Job Clone Risk Explanation (Updated for Brand Impersonation)
        if clone_risk == "High":
            if impersonation_flag == "Yes":
                explanation += " This job appears to impersonate a known company using an unofficial email domain. This is a common scam pattern."
            else:
                explanation += " The job description appears copied from other online sources, which is a common tactic used in job scams."
            risk_indicators.append("High Cloning Risk")
        elif clone_risk == "Medium":
            explanation += " The job description appears similar to postings found on other websites. This may indicate copied job listings."
            risk_indicators.append("Cloned Description")
            
        if email_domain == "Not Provided":
            explanation += " HR email was not provided in the job posting."
        
        # Risk factor detection logic
        if domain_age_days < 180:
            risk_indicators.append("New Domain")
            
        free_emails = ['gmail.com', 'yahoo.com', 'hotmail.com', 'outlook.com', 'mail.com', 'protonmail.com', 'yandex.com', 'icloud.com']
        if email_domain and email_domain != "Not Provided" and email_domain.lower() in free_emails:
            risk_indicators.append("Free Email Provider")
            
        if scam_keywords > 0:
            risk_indicators.append("Suspicious Keywords")
            
        platform_str = str(platform).lower() if platform else ""
        if 'telegram' in platform_str or 'whatsapp' in platform_str:
            risk_indicators.append("Telegram/WhatsApp Contact")
            
        payment_triggers = ['registration fee', 'security deposit', 'processing fee', 'pay for interview', 'visa fee']
        if any(trigger in platform_str for trigger in payment_triggers):
            risk_indicators.append("Payment Request")

        return {
            'explanation': explanation,
            'risk_indicators': risk_indicators
        }
    except Exception:
        return {
            'explanation': "Insufficient data to generate explanation.",
            'risk_indicators': []
        }
# ===== END NEW CODE =====

def extract_domain(url):
    if not url: return ""
    # Remove whitespace
    url = url.strip().lower()
    # Remove https://, http://, and www.
    domain = re.sub(r'^https?://', '', url)
    domain = re.sub(r'^www\.', '', domain)
    domain = re.split(r'[/: ]', domain)[0]
    return domain

# ===== NEW CODE =====
official_domains = {
    "amazon": "amazon.com",
    "google": "google.com",
    "microsoft": "microsoft.com",
    "meta": "meta.com",
    "apple": "apple.com",
    "netflix": "netflix.com",
    "tesla": "tesla.com",
    "infosys": "infosys.com",
    "tcs": "tcs.com",
    "wipro": "wipro.com",
    "accenture": "accenture.com",
    "ibm": "ibm.com"
}
# ===== END NEW CODE =====

trusted_domains = {
    'tcs.com': 10000, 
    'google.com': 10000, 
    'microsoft.com': 11000, 
    'amazon.com': 10000, 
    'ibm.com': 12000, 
    'infosys.com': 9000, 
    'wipro.com': 9000, 
    'apple.com': 10000, 
    'meta.com': 7000,
    'linkedin.com': 8000,
    'github.com': 6000
}

# ===== MODIFIED CODE =====
def analyze_posting(title, desc, email, website, extracted_text, company_name="", job_url="", correlation_stats=None):
# ===== END MODIFIED CODE =====
    full_text = f"{title} {desc or ''} {extracted_text}".lower()
    clean_website = extract_domain(website) if website else ""
    
    # 1. Run ML prediction
    # Simple ML prediction
    input_text = full_text
    pred_probs = model.predict_proba([input_text])[0]
    pred_prob = float(pred_probs[1]) if len(pred_probs) > 1 else 0.5

    # 2. Count scam keywords
    detected_scam_keywords = [kw for kw in scam_keywords if kw in full_text]
    scam_count = len(detected_scam_keywords)
    
    # 3. Detect override phrases
    detected_overrides = [op for op in scam_override_keywords if op in full_text]
    override_phrase = detected_overrides[0] if detected_overrides else "None"

    # 4. Evaluate risk signals
    risk_signals = 0
    
    # Signal: Free Email Provider
    free_emails = ['gmail.com', 'yahoo.com', 'hotmail.com', 'outlook.com', 'mail.com', 'protonmail.com', 'yandex.com', 'icloud.com']
    email_domain_str = "Not Provided"
    is_free_email = False
    if email and '@' in email:
        email_domain_str = email.split('@')[-1]
        if email_domain_str.lower() in free_emails:
            risk_signals += 1
            is_free_email = True
            
    # Signal: Domain Age < 60 days
    domain_age_days = -1
    is_trusted = False
    for trusted, age in trusted_domains.items():
        if clean_website == trusted or clean_website.endswith('.' + trusted):
            domain_age_days = age
            is_trusted = True
            break
            
    if not is_trusted and clean_website:
        domain_age_days = get_domain_age_days(clean_website)
        if domain_age_days == -1:
            parts = clean_website.split('.')
            if len(parts) > 2:
                domain_age_days = get_domain_age_days(base_domain)

    # ===== BUG FIX =====
    # Validate and handle None values before numeric comparison
    if domain_age_days is None:
        print(f"Domain Age Value: None")
        print(f"Converted Domain Age: 0")
        print(f"Risk Evaluation Continuing...")
        domain_age_days = 0
        
    if scam_count is None: scam_count = 0
    if pred_prob is None: pred_prob = 0.0
    # ===== END BUG FIX =====

    if domain_age_days != -1 and domain_age_days < 60:
        risk_signals += 1
        
    # Signal: Scam keywords >= 2
    if scam_count >= 2:
        risk_signals += 1
        
    # Signal: ML Fraud Probability >= 0.5
    if pred_prob >= 0.5:
        risk_signals += 1
        
    # Signal: Domain mismatch
    domain_mismatch = False
    if clean_website and is_trusted:
        if email_domain_str != "Not Provided" and not is_free_email:
            if email_domain_str.lower() != clean_website.lower():
                risk_signals += 1
                domain_mismatch = True

    # ===== NEW CODE: Brand Impersonation Detection (STEPS 1, 2 & 3) =====
    impersonation_flag = "No"
    impersonated_brand = None
    if company_name and company_name != "Unknown Company":
        company_lower = company_name.lower()
        for brand, official_domain in official_domains.items():
            if brand in company_lower:
                # Rule 1: Brand name + Public email provider (Step 1)
                if is_free_email:
                    impersonation_flag = "Yes"
                    impersonated_brand = brand
                    break
                # Rule 2: Brand name + Mismatched non-free email domain (Step 2 & 3)
                if email_domain_str != "Not Provided" and email_domain_str != official_domain and not email_domain_str.endswith('.' + official_domain):
                    impersonation_flag = "Yes"
                    impersonated_brand = brand
                    break
                # Rule 3: Brand name + Mismatched website domain (Existing logic)
                if clean_website and clean_website != official_domain and not clean_website.endswith('.' + official_domain):
                    impersonation_flag = "Yes"
                    impersonated_brand = brand
                    break
                    
    # Update risk signals for impersonation logic
    impersonation_risk_met = True if impersonation_flag == "Yes" else False
    # ===== END NEW CODE =====

    # 5. Calculate trust score
    penalty = (pred_prob * 40.0)
    
    # ===== MODIFIED CODE =====
    # PART 2 — RISK PENALTIES FOR MISSING DATA (and PART 1)
    incomplete_company_info = False

    if not company_name or company_name == "Unknown Company":
        penalty += 10.0
        incomplete_company_info = True

    if not email or email.strip().lower() == "not provided":
        penalty += 10.0
        incomplete_company_info = True

    if not website or not website.strip():
        penalty += 15.0
        incomplete_company_info = True

    if not job_url or not job_url.strip():
        penalty += 10.0
        incomplete_company_info = True
    # ===== END MODIFIED CODE =====

    if scam_count > 0: penalty += 15.0
    if is_free_email: penalty += 20.0
    if domain_age_days != -1 and domain_age_days < 90: penalty += 5.0
    if domain_mismatch: penalty += 20.0
    if is_trusted: penalty -= 10.0
    if clean_website and email_domain_str.lower() == clean_website.lower(): penalty -= 10.0
    
    # ===== NEW CODE: Risk Scoring =====
    if impersonation_flag == "Yes":
        penalty += 40.0
    # ===== END NEW CODE =====
    
    # VARIABLE INITIALIZATION FIX
    clone_risk = "Low"
    try:
        clone_risk = detect_job_cloning(title, desc)
    except Exception:
        clone_risk = "Low"
    
    # Brand Impersonation logic forces High Clone Risk (Step 1, 2, 3)
    if impersonation_flag == "Yes":
        clone_risk = "High"
        
    # Apply penalties for clone risk (Step 5 alignment)
    if clone_risk == "High": 
        penalty += 60.0 # Force Dangerous
    elif clone_risk == "Medium": 
        penalty += 30.0 # Force Suspicious
    # END VARIABLE INITIALIZATION FIX
    
    # ===== CORRELATION DETECTION ADDITION =====
    campaign_risk = "Low"
    campaign_reason = "No correlation detected."
    correlation_penalty = 0.0
    
    if correlation_stats:
        e_count = correlation_stats.get('email_domain_count', 0)
        w_count = correlation_stats.get('website_domain_count', 0)
        k_count = correlation_stats.get('keyword_match_count', 0)
        i_pattern = correlation_stats.get('impersonation_pattern', False)
        
        reasons = []
        if e_count > 3:
            reasons.append("Email domain used in multiple suspicious job postings")
            correlation_penalty += 20.0
        if w_count > 3:
            reasons.append("Job website domain linked to repeated scam reports")
            correlation_penalty += 20.0
        if k_count > 2:
            reasons.append("Similar scam keyword campaign detected across multiple scans")
            correlation_penalty += 15.0
        if i_pattern:
            reasons.append("Multiple companies using identical unofficial email domains")
            correlation_penalty += 20.0
            
        if correlation_penalty >= 40: campaign_risk = "High"
        elif correlation_penalty > 0: campaign_risk = "Moderate"
        
        if reasons:
            campaign_reason = "; ".join(reasons)
            
    penalty += correlation_penalty
    # ===== END CORRELATION DETECTION ADDITION =====

    trust_score = float(max(0, min(100, 100 - penalty)))

    # 6. Apply final classification
    classification = ""
    override_active = False
    
    # ===== MODIFIED CODE =====
    # PART 3 & PART 6 — CLASSIFICATION RULES
    can_be_safe = True
    if incomplete_company_info or domain_age_days < 180 or scam_count > 0 or pred_prob >= 0.3:
        can_be_safe = False

    if override_phrase != "None" and risk_signals >= 1:
        override_active = True
    elif impersonation_flag == "Yes" and impersonation_risk_met:
        override_active = True

    # PIPELINE CONSISTENCY FIX
    # Step 3: Create final_classification ONLY from trust_score
    if trust_score is None:
        trust_score = 0.0
        
    if trust_score >= 80:
        final_classification = "Safe"
    elif trust_score >= 50:
        final_classification = "Suspicious"
    else:
        final_classification = "Dangerous"
    
    # STEP 5: Ensure alignment between clone risk and classification
    if clone_risk == "High":
        final_classification = "Dangerous"
    elif clone_risk == "Medium" and final_classification == "Safe":
        final_classification = "Suspicious"
    
    # Override logic: ML conflicts must not control the UI if they differ from trust_score
    classification = final_classification
    # END PIPELINE CONSISTENCY FIX
    # ===== END MODIFIED CODE =====

    # PART 6 — DEBUG LOGGING
    print(f"--- Debug Analysis ---")
    print(f"Company: {company_name}")
    print(f"Detected Scam Keywords: {scam_count} ({', '.join(detected_scam_keywords) if detected_scam_keywords else 'None'})")
    print(f"Override Phrase: {override_phrase}")
    print(f"Risk Signals: {risk_signals}")
    print(f"ML Fraud Probability: {pred_prob:.2f}")
    if impersonation_flag == "Yes":
        print(f"Company Name Detected: {company_name}")
        print(f"Website Domain: {clean_website}")
        print(f"Official Domain: {official_domains[impersonated_brand]}")
        print(f"Impersonation Detected: True")
    print(f"Final Classification: {classification}")
    print(f"----------------------")

    ai_analysis = generate_ai_explanation(
        classification=classification,
        trust_score=trust_score,
        scam_keywords=int(scam_count),
        domain_age_days=domain_age_days if domain_age_days != -1 else 0,
        email_domain=email_domain_str,
        platform=full_text,
        clone_risk=clone_risk,
        impersonation_flag=impersonation_flag
    )
    
    if classification == "Low Risk – New Startup Domain":
        ai_analysis['explanation'] = "This job is posted from a newly registered domain. However, no scam indicators were found, suggesting it may be a legitimate new startup."
    # PIPELINE CONSISTENCY FIX: AI explanation already handled above based on final_classification

    return {
        'scam_keywords': int(scam_count),
        'domain_age_days': domain_age_days if domain_age_days != -1 else None,
        'domain_age_display': format_domain_age_display(domain_age_days if domain_age_days != -1 else None),
        'ml_prediction': float(pred_prob),
        'trust_score': float(round(trust_score, 2)),
        'classification': classification,
        'ai_explanation': ai_analysis['explanation'],
        'risk_indicators': ai_analysis['risk_indicators'],
        'clone_risk': clone_risk,
        'impersonation_flag': impersonation_flag,
        'hr_email': email if email else "Not Provided",
        'company_name': company_name,
        'incomplete_company_info': incomplete_company_info, # ===== MODIFIED CODE =====
        'campaign_risk': campaign_risk, # CORRELATION DETECTION ADDITION
        'campaign_reason': campaign_reason # CORRELATION DETECTION ADDITION
    }
    # ===== END MODIFIED =====

@app.route('/', methods=['GET', 'POST'])
def index():
    if request.method == 'POST':
        # ===== BUG FIX =====
        company_name = request.form.get('company_name')
        if not company_name or str(company_name).strip() == "" or str(company_name).strip().lower() == "none":
            company_name = "Unknown Company"
        else:
            company_name = company_name.strip()
            
        print(f"Captured Company Name: {company_name}")
        # ===== END BUG FIX =====
            
        title = request.form['title']
        desc = request.form['description']
        email = request.form.get('email', '').strip() # ===== MODIFIED =====
        website = request.form['website']
        job_url = request.form.get('job_url', '') # ===== NEW CODE =====
        
        db_email = email if email else "Not Provided" # ===== NEW CODE =====
        
        extracted_text = ''
        file_path = None
        if 'file' in request.files:
            file = request.files['file']
            if file.filename:
                filename = f"uploads/{uuid.uuid4()}_{file.filename}"
                os.makedirs('uploads', exist_ok=True)
                file.save(filename)
                file_path = filename
                with open(filename, 'rb') as f:
                    content = f.read()
                is_pdf = filename.endswith('.pdf')
                extracted_text = extract_text(content, is_pdf)
        
        try:
            # ===== CORRELATION DETECTION ADDITION =====
            correlation_stats = {
                'email_domain_count': 0,
                'website_domain_count': 0,
                'keyword_match_count': 0,
                'impersonation_pattern': False
            }
            
            try:
                conn_corr = pymysql.connect(**db_config)
                cursor_corr = conn_corr.cursor(pymysql.cursors.DictCursor)
                
                # 1. Email Domain Correlation
                if email and '@' in email:
                    e_domain = email.split('@')[-1]
                    cursor_corr.execute("SELECT COUNT(*) as count FROM scans WHERE email LIKE %s AND (classification='Dangerous' OR classification='Suspicious')", (f"%@{e_domain}",))
                    correlation_stats['email_domain_count'] = cursor_corr.fetchone()['count']
                
                # 3. Keyword Campaign Detection
                check_text = f"{title} {desc} {extracted_text}".lower()
                matched_kws = [kw for kw in scam_keywords if kw in check_text]
                for kw in matched_kws:
                    cursor_corr.execute("SELECT COUNT(*) as count FROM scans WHERE description LIKE %s AND classification = 'Dangerous'", (f"%{kw}%",))
                    if cursor_corr.fetchone()['count'] > 3:
                        correlation_stats['keyword_match_count'] += 1

                # 4. Company Impersonation Pattern
                if email and '@' in email:
                    e_domain = email.split('@')[-1]
                    free_emails = ['gmail.com', 'yahoo.com', 'hotmail.com', 'outlook.com']
                    if e_domain.lower() in free_emails:
                        cursor_corr.execute("SELECT COUNT(DISTINCT company_name) as c_count FROM scans WHERE email LIKE %s", (f"%@{e_domain}",))
                        if cursor_corr.fetchone()['c_count'] > 2:
                            correlation_stats['impersonation_pattern'] = True
                
                cursor_corr.close()
                conn_corr.close()
            except Exception as e:
                print(f"Correlation Error: {e}")
            # ===== END CORRELATION DETECTION ADDITION =====

            # ===== MODIFIED CODE =====
            results = analyze_posting(title, desc, email, website, extracted_text, company_name, job_url, correlation_stats)
            # ===== END MODIFIED CODE =====
            
            # Save to DB
            conn = pymysql.connect(**db_config)
            cursor = conn.cursor()
            # ===== BUG FIX =====
            cursor.execute("""
                INSERT INTO scans (company_name, title, description, email, website, job_url, file_path, extracted_text, 
                                  domain_age_days, scam_keywords, ml_prediction, trust_score, classification, clone_risk_level)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
            """, (company_name, title, desc, db_email, website, job_url, file_path, extracted_text,
                  results['domain_age_days'], results['scam_keywords'], results['ml_prediction'],
                  results['trust_score'], results['classification'], results['clone_risk']))
            # ===== END BUG FIX =====
            conn.commit()
            cursor.close()
            conn.close()
            
            return render_template('result.html', results=results, extracted_text=extracted_text)
        except Exception as e:
            # Log error to file
            with open("app_error.log", "a") as f:
                f.write(f"Error processing request: {e}\n")
            print(f"Error processing request: {e}", file=sys.stderr)
            return f"An error occurred: {e}", 500
    
    return render_template('index.html')

@app.route('/dashboard')
def dashboard():
    # ===== NEW CODE: Impersonation Check for Dashboard =====
    def check_impersonation(c_name, web, email=""):
        if not c_name: return "No"
        c_lower = c_name.lower()
        clean_w = extract_domain(web) if web else ""
        e_domain = email.split('@')[-1].lower() if email and '@' in email else ""
        
        free_emails = ['gmail.com', 'yahoo.com', 'hotmail.com', 'outlook.com', 'mail.com', 'protonmail.com', 'yandex.com', 'icloud.com']
        
        for brand, off_domain in official_domains.items():
            if brand in c_lower:
                # Rule 1: Email check
                if e_domain:
                    if e_domain in free_emails: return "Yes"
                    if e_domain != off_domain and not e_domain.endswith('.' + off_domain): return "Yes"
                # Rule 2: Website check
                if clean_w and clean_w != off_domain and not clean_w.endswith('.' + off_domain):
                    return "Yes"
        return "No"
    # ===== END NEW CODE =====

    # ===== NEW CODE: Fetch Analytics Data =====
    conn = pymysql.connect(**db_config)
    cursor = conn.cursor(pymysql.cursors.DictCursor)
    
    # 1. Total Scans
    cursor.execute("SELECT COUNT(*) as total FROM scans")
    total_result = cursor.fetchone()
    total_scans = total_result['total'] if total_result else 0
    
    # 2. Classification Counts (Pie Chart)
    cursor.execute("SELECT classification, COUNT(*) as count FROM scans GROUP BY classification")
    class_stats = cursor.fetchall()
    
    # 3. Top Flagged Domains (Bar Chart)
    cursor.execute("SELECT website, COUNT(*) as count FROM scans GROUP BY website ORDER BY count DESC LIMIT 5")
    top_domains = cursor.fetchall()
    
    # 4. Indicator Panel Insights
    # Average Trust Score
    cursor.execute("SELECT AVG(trust_score) as avg_score FROM scans")
    avg_result = cursor.fetchone()
    avg_score = round(avg_result['avg_score'], 2) if avg_result['avg_score'] else 0
    
    # Most suspicious domain (highest volume of dangerous/suspicious scans)
    cursor.execute("""
        SELECT website, COUNT(*) as d_count FROM scans 
        WHERE classification IN ('Dangerous', 'Suspicious') 
        GROUP BY website ORDER BY d_count DESC LIMIT 1
    """)
    suspicious_result = cursor.fetchone()
    most_suspicious = suspicious_result['website'] if suspicious_result else "N/A"
    
    # Most common HR email provider
    cursor.execute("""
        SELECT SUBSTRING_INDEX(email, '@', -1) as provider, COUNT(*) as count 
        FROM scans GROUP BY provider ORDER BY count DESC LIMIT 1
    """)
    provider_result = cursor.fetchone()
    common_provider = provider_result['provider'] if provider_result else "N/A"

    # 6. Cloned Job Alerts
    cursor.execute("SELECT COUNT(*) as count FROM scans WHERE clone_risk_level IN ('Medium', 'High')")
    cloned_result = cursor.fetchone()
    cloned_alerts = cloned_result['count'] if cloned_result else 0

    # ===== DEBUG FIX =====
    # PART 4: Upgrade Summary Stats (Fraud Investigation Center)
    cursor.execute("""
        SELECT 
            COALESCE(SUM(CASE WHEN classification = 'Safe' OR classification LIKE 'Low Risk%' THEN 1 ELSE 0 END), 0) as safe_count,
            COALESCE(SUM(CASE WHEN classification = 'Suspicious' THEN 1 ELSE 0 END), 0) as suspicious_count,
            COALESCE(SUM(CASE WHEN classification = 'Dangerous' THEN 1 ELSE 0 END), 0) as dangerous_count
        FROM scans
    """)
    fraud_stats = cursor.fetchone()
    if not fraud_stats:
        fraud_stats = {'safe_count': 0, 'suspicious_count': 0, 'dangerous_count': 0}
        
    safe_count = int(fraud_stats.get('safe_count', 0) or 0)
    suspicious_count = int(fraud_stats.get('suspicious_count', 0) or 0)
    dangerous_count = int(fraud_stats.get('dangerous_count', 0) or 0)
    # ===== END DEBUG FIX =====
    
    # PART 5: Repeat Scam Detection (High Risk Employer > 3 Dangerous)
    cursor.execute("""
        SELECT company_name FROM scans 
        WHERE classification = 'Dangerous' 
        GROUP BY company_name HAVING COUNT(*) > 3
    """)
    high_risk_employers = [row['company_name'] for row in cursor.fetchall()]

    # PART 6: Scam Alert Panel (Recent Dangerous)
    cursor.execute("""
        SELECT title, company_name, classification, trust_score, scan_date 
        FROM scans WHERE classification = 'Dangerous' 
        ORDER BY id DESC LIMIT 5
    """)
    recent_scam_alerts = cursor.fetchall()
    
    # ===== DEBUG FIX =====
    # PART 7.2: Scam Keyword Detection (Bar Chart)
    cursor.execute("SELECT COUNT(*) as count FROM scans WHERE scam_keywords > 0")
    res1 = cursor.fetchone()
    keyword_count = int(res1['count']) if res1 and res1['count'] is not None else 0
    
    cursor.execute("SELECT COUNT(*) as count FROM scans WHERE scam_keywords = 0")
    res2 = cursor.fetchone()
    clean_count = int(res2['count']) if res2 and res2['count'] is not None else 0
    
    # PART 7.3: Domain Risk Graph
    cursor.execute("SELECT COUNT(*) as count FROM scans WHERE domain_age_days < 90")
    res3 = cursor.fetchone()
    new_domain_count = int(res3['count']) if res3 and res3['count'] is not None else 0
    
    cursor.execute("SELECT COUNT(*) as count FROM scans WHERE domain_age_days >= 90")
    res4 = cursor.fetchone()
    old_domain_count = int(res4['count']) if res4 and res4['count'] is not None else 0
    # ===== END DEBUG FIX =====

    # ===== CORRELATION DETECTION ADDITION =====
    cursor.execute("""
        SELECT website FROM scans 
        WHERE (classification = 'Dangerous' OR classification = 'Suspicious') 
        GROUP BY website HAVING COUNT(*) > 1
    """)
    repeated_suspicious_domains = [row['website'] for row in cursor.fetchall()]
    # ===== END CORRELATION DETECTION ADDITION =====

    # 5. Recent Scans Table
    cursor.execute("SELECT * FROM scans ORDER BY id DESC LIMIT 20")
    raw_scans = cursor.fetchall()
    scans = []
    for s in raw_scans:
        s['impersonation_flag'] = check_impersonation(s['company_name'], s['website'], s.get('email', ''))
        
        # ===== MODIFIED CODE =====
        # PART 5 — DASHBOARD INDICATOR CHECK
        incomplete = False
        if not s.get('company_name') or s.get('company_name') == 'Unknown Company': incomplete = True
        if not s.get('email') or str(s.get('email')).lower() == 'not provided' or not str(s.get('email')).strip(): incomplete = True
        if not s.get('website'): incomplete = True
        if not s.get('job_url'): incomplete = True
        s['incomplete_company_info'] = incomplete
        # ===== END MODIFIED CODE =====
        
        scans.append(s)
    
    cursor.close()
    conn.close()
    
    stats_dict = {row['classification']: row['count'] for row in class_stats}
    
    return render_template('dashboard.html', 
                           scans=scans,
                           total_scans=total_scans,
                           stats=stats_dict,
                           top_domains=top_domains,
                           avg_score=avg_score,
                           most_suspicious=most_suspicious,
                           common_provider=common_provider,
                           cloned_alerts=cloned_alerts,
                           fraud_stats=fraud_stats,
                           high_risk_employers=high_risk_employers,
                           recent_scam_alerts=recent_scam_alerts,
                           # ===== DEBUG FIX =====
                           safe_count=safe_count,
                           suspicious_count=suspicious_count,
                           dangerous_count=dangerous_count,
                           keyword_count=keyword_count,
                           clean_count=clean_count,
                           new_domain_count=new_domain_count,
                           old_domain_count=old_domain_count,
                           # ===== CORRELATION DETECTION ADDITION =====
                           repeated_suspicious_domains=repeated_suspicious_domains)
                           # ===== END CORRELATION DETECTION ADDITION =====
                           # ===== END DEBUG FIX =====

# ===== NEW CODE: Company details route =====
@app.route("/company/<path:website>")
def company_details(website):
    try:
        conn = pymysql.connect(**db_config)
        cursor = conn.cursor(pymysql.cursors.DictCursor)
        # Use simple LIKE or exact match based on the website field in DB
        cursor.execute("SELECT * FROM scans WHERE website LIKE %s ORDER BY id DESC", (f"%{website}%",))
        company_scans = cursor.fetchall()
        cursor.close()
        conn.close()
        return render_template('company_details.html', website=website, scans=company_scans)
    except Exception as e:
        return f"Error fetching company details: {e}", 500
# ===== END NEW CODE =====

@app.route('/api/stats')
def stats():
    conn = pymysql.connect(**db_config)
    cursor = conn.cursor(pymysql.cursors.DictCursor)
    cursor.execute("SELECT classification, COUNT(*) as count FROM scans GROUP BY classification")
    stats = cursor.fetchall()
    cursor.execute("SELECT website, COUNT(*) as count FROM scans GROUP BY website ORDER BY count DESC LIMIT 10")
    top_companies = cursor.fetchall()
    cursor.close()
    conn.close()
    return jsonify({'stats': stats, 'top_companies': top_companies})

if __name__ == '__main__':
    app.run(host='0.0.0.0', debug=True)
