from app import analyze_posting

print("Testing analyze_posting...")
try:
    result = analyze_posting(
        title="Test Job",
        desc="This is a test job description with urgent immediate hire.",
        email="test@example.com",
        website="example.com",
        extracted_text=""
    )
    print("Result:", result)
    for k, v in result.items():
        print(f"{k}: {type(v)}")
except Exception as e:
    print("Error:", e)
