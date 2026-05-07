import sys
print(f"Python: {sys.version}")
print("="*55)
checks = []

# Check 1: sentence-transformers
try:
    from sentence_transformers import SentenceTransformer
    model = SentenceTransformer('all-MiniLM-L6-v2')
    vec = model.encode(["test campus fraud shield"])
    assert vec.shape == (1, 384)
    checks.append(("sentence-transformers", "PASS"))
except Exception as e:
    checks.append(("sentence-transformers", f"FAIL: {e}"))

# Check 2: faiss
try:
    import faiss
    import numpy as np
    index = faiss.IndexFlatIP(384)
    vec = np.random.rand(1, 384).astype('float32')
    faiss.normalize_L2(vec)
    index.add(vec)
    assert index.ntotal == 1
    checks.append(("faiss-cpu", "PASS"))
except Exception as e:
    checks.append(("faiss-cpu", f"FAIL: {e}"))

# Check 3: scikit-learn
try:
    from sklearn.linear_model import LogisticRegression
    from sklearn.cluster import KMeans
    from sklearn.metrics import classification_report
    from sklearn.model_selection import train_test_split
    checks.append(("scikit-learn", "PASS"))
except Exception as e:
    checks.append(("scikit-learn", f"FAIL: {e}"))

# Check 4: streamlit
try:
    import streamlit
    checks.append((f"streamlit {streamlit.__version__}",
                   "PASS"))
except Exception as e:
    checks.append(("streamlit", f"FAIL: {e}"))

# Check 5: plotly
try:
    import plotly.graph_objects as go
    fig = go.Figure()
    checks.append(("plotly", "PASS"))
except Exception as e:
    checks.append(("plotly", f"FAIL: {e}"))

# Check 6: pandas
try:
    import pandas as pd
    df = pd.DataFrame({
        "message": ["test scam message"],
        "label": [1]
    })
    assert len(df) == 1
    checks.append(("pandas", "PASS"))
except Exception as e:
    checks.append(("pandas", f"FAIL: {e}"))

# Check 7: numpy
try:
    import numpy as np
    arr = np.array([1, 2, 3, 4, 5])
    assert arr.mean() == 3.0
    checks.append(("numpy", "PASS"))
except Exception as e:
    checks.append(("numpy", f"FAIL: {e}"))

# Check 8: tldextract
try:
    import tldextract
    r = tldextract.extract("https://internshala.com/jobs")
    assert r.domain == "internshala"
    assert r.suffix == "com"
    checks.append(("tldextract", "PASS"))
except Exception as e:
    checks.append(("tldextract", f"FAIL: {e}"))

# Check 9: Pillow
try:
    from PIL import Image, ImageDraw, ImageFont
    img = Image.new('RGB', (400, 200), color='#0a0f1e')
    draw = ImageDraw.Draw(img)
    draw.text((10, 10), "Campus Fraud Shield", fill='white')
    checks.append(("Pillow", "PASS"))
except Exception as e:
    checks.append(("Pillow", f"FAIL: {e}"))

# Check 10: matplotlib
try:
    import matplotlib
    matplotlib.use('Agg')
    import matplotlib.pyplot as plt
    fig, ax = plt.subplots(figsize=(8, 6))
    ax.bar(['scam', 'safe'], [150, 150])
    ax.set_title("Test Chart")
    plt.close()
    checks.append(("matplotlib", "PASS"))
except Exception as e:
    checks.append(("matplotlib", f"FAIL: {e}"))

# Check 11: sqlite3
try:
    import sqlite3
    conn = sqlite3.connect(':memory:')
    conn.execute('''
        CREATE TABLE reports (
            id      INTEGER PRIMARY KEY,
            text    TEXT,
            score   REAL,
            label   TEXT,
            created TEXT
        )
    ''')
    conn.execute(
        "INSERT INTO reports VALUES (?,?,?,?,?)",
        (1, 'fake internship pay fee', 92.5, 'SCAM', '2024-01-01')
    )
    conn.commit()
    row = conn.execute(
        "SELECT * FROM reports WHERE id=1"
    ).fetchone()
    assert row[3] == 'SCAM'
    assert row[2] == 92.5
    conn.close()
    checks.append(("sqlite3", "PASS"))
except Exception as e:
    checks.append(("sqlite3", f"FAIL: {e}"))

# Check 12: requests
try:
    import requests
    checks.append(("requests", "PASS"))
except Exception as e:
    checks.append(("requests", f"FAIL: {e}"))

# Check 13: python-dotenv
try:
    from dotenv import load_dotenv
    load_dotenv()
    checks.append(("python-dotenv", "PASS"))
except Exception as e:
    checks.append(("python-dotenv", f"FAIL: {e}"))

# Check 14: torch
try:
    import torch
    t = torch.tensor([1.0, 2.0, 3.0])
    assert t.mean().item() == 2.0
    checks.append((f"torch {torch.__version__}", "PASS"))
except Exception as e:
    checks.append(("torch", f"FAIL: {e}"))

# Check 15: transformers
try:
    import transformers
    checks.append((
        f"transformers {transformers.__version__}",
        "PASS"
    ))
except Exception as e:
    checks.append(("transformers", f"FAIL: {e}"))

# Check 16: regex (built-in test)
try:
    import re
    text = "Pay Rs.1500 to 9876543210. Visit bit.ly/scam123"
    phones = re.findall(r'[6-9]\d{9}', text)
    urls   = re.findall(r'bit\.ly/\S+|http\S+', text)
    assert phones == ['9876543210']
    assert 'bit.ly/scam123' in urls
    checks.append(("regex (built-in)", "PASS"))
except Exception as e:
    checks.append(("regex (built-in)", f"FAIL: {e}"))

# Check 17: json (built-in test)
try:
    import json
    data = {
        "entity": "internshala",
        "fee_policy": "never_charges_registration_fee",
        "domains": ["internshala.com"]
    }
    encoded = json.dumps(data)
    decoded = json.loads(encoded)
    assert decoded["entity"] == "internshala"
    checks.append(("json (built-in)", "PASS"))
except Exception as e:
    checks.append(("json (built-in)", f"FAIL: {e}"))

# Check 18: Full pipeline test
try:
    from sentence_transformers import SentenceTransformer
    from sklearn.linear_model import LogisticRegression
    import numpy as np

    embedder = SentenceTransformer('all-MiniLM-L6-v2')

    train_texts = [
        "Pay registration fee to get internship",
        "Send OTP to claim your prize money",
        "You won lottery pay processing fee now",
        "Congratulations selected pay deposit",
        "Your internship offer letter is ready",
        "Interview scheduled for Monday 3PM",
        "Please bring documents for joining",
        "Salary credited to your account",
    ]
    train_labels = [1, 1, 1, 1, 0, 0, 0, 0]

    embeddings = embedder.encode(train_texts)
    clf = LogisticRegression(random_state=42, max_iter=1000)
    clf.fit(embeddings, train_labels)

    test_text = "Pay Rs 2000 fee to confirm your job offer"
    test_vec   = embedder.encode([test_text])
    prediction = clf.predict(test_vec)[0]
    confidence = clf.predict_proba(test_vec)[0][1]

    assert prediction == 1, "Should detect as scam"
    assert confidence > 0.5, "Should be confident"

    checks.append((
        f"Full ML Pipeline (confidence: {confidence:.0%})",
        "PASS"
    ))
except Exception as e:
    checks.append(("Full ML Pipeline", f"FAIL: {e}"))

# ── Print Results ──────────────────────────────────────
print("\nVERIFICATION RESULTS:")
print("="*60)

all_pass  = True
pass_count = 0
fail_count = 0

for name, result in checks:
    if result == "PASS":
        icon = "OK"
        pass_count += 1
    else:
        icon = "XX"
        fail_count += 1
        all_pass = False
    print(f"  [{icon}]  {name:<45} {result}")

print("="*60)
print(f"\n  Passed : {pass_count}/{len(checks)}")
print(f"  Failed : {fail_count}/{len(checks)}")
print()

if all_pass:
    print("  ALL CHECKS PASSED")
    print("  Your environment is ready")
    print("  Campus Fraud Shield v3 can be built")
else:
    print("  SOME CHECKS FAILED")
    print()
    print("  Fix commands:")
    print("  pip install --retries 10 --timeout 120 "
          "-r requirements.txt")
print()