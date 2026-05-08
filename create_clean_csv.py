# create_clean_csv.py
import csv
import os

rows = [
    # ── Core Scams ─────────────────────────────────────────────────
    ("Congratulations! You have been selected for internship at Internshala partner company. Pay Rs.1500 registration fee on Paytm 9876543210 to confirm your slot.", 1, "internship_fee", "dataset"),
    ("Pay Rs.999 joining fee to confirm your work from home internship. Send to PhonePe 8765432109.", 1, "internship_fee", "dataset"),
    ("You have WON Rs.25 lakh in KBC Lucky Draw! Pay Rs.1500 processing fee to claim prize.", 1, "lottery_prize", "dataset"),
    ("Share your OTP to claim KBC prize of Rs.25 lakh. Contact kbc.prize@gmail.com urgently.", 1, "otp_fraud", "dataset"),
    ("NSP Scholarship of Rs.25000 approved. Pay Rs.500 processing fee to PhonePe 8765432109.", 1, "scholarship_fee", "dataset"),
    ("SBI account will be blocked. Verify KYC by sharing OTP sent to your number.", 1, "otp_fraud", "dataset"),
    ("gooogle.com free recharge enter OTP to claim Rs.199 cashback today only", 1, "otp_fraud", "dataset"),
    ("g00gle.com selected you for internship pay Rs.999 fee to confirm your slot immediately", 1, "internship_fee", "dataset"),
    ("g0ogle.com job offer pay Rs.2000 training fee before joining date expires tonight", 1, "job_fee", "dataset"),
    ("google-jobs-india.xyz apply now pay Rs.1500 registration fee", 1, "job_fee", "dataset"),
    ("amazon-winner.xyz you won iPhone pay Rs.299 delivery charge to claim", 1, "lottery_prize", "dataset"),
    ("sbi-kyc-update.xyz urgent KYC required login and share OTP with executive", 1, "otp_fraud", "dataset"),
    ("http://university-portal-login.xyz/auth pay admission fee now", 1, "bank_impersonation", "dataset"),
    ("http://sbi-kyc-verify.xyz/login urgent KYC update required enter OTP", 1, "otp_fraud", "dataset"),
    ("http://amazon-lucky-winner.xyz/claim you won iPhone pay Rs.299", 1, "lottery_prize", "dataset"),
    ("internsha1a.com internship offer selected pay Rs.1500 registration fee", 1, "internship_fee", "dataset"),
    ("facebo0k.com account security alert share OTP to recover access", 1, "otp_fraud", "dataset"),
    ("university-portal-login.xyz complete admission formalities pay Rs.5000 fee", 1, "bank_impersonation", "dataset"),
    ("college-admission-portal.xyz your admission confirmed pay Rs.3000 processing fee", 1, "bank_impersonation", "dataset"),

    # ── Safe Messages ──────────────────────────────────────────────
    ("Your TCS interview is scheduled at nextstep.tcs.com on Monday 10AM. No fee required.", 0, "safe", "dataset"),
    ("Internshala confirmed your internship application. Login at internshala.com to proceed.", 0, "safe", "dataset"),
    ("SBI bank: We will NEVER ask for your OTP. Report fraud at 1930 or visit sbi.co.in", 0, "safe", "dataset"),
    ("Check scholarships.gov.in for NSP status.", 0, "safe", "dataset"),
    ("Your Amazon order has been confirmed. Track at amazon.in. No additional charges.", 0, "safe", "dataset"),
    ("Google Meet interview link sent to your email. Join at meet.google.com. No fees.", 0, "safe", "dataset"),
    ("HDFC bank reminder: Never share OTP. Call 1800-202-6161 for support.", 0, "safe", "dataset"),
    ("Your Infosys offer letter sent to registered email. Joining date 15th March. No charges.", 0, "safe", "dataset"),
    ("NPTEL certificate exam fee Rs.1000 payable only at swayam.gov.in.", 0, "safe", "dataset"),
]

os.makedirs("data", exist_ok=True)

with open("data/scam_dataset.csv", "w", newline="", encoding="utf-8") as f:
    writer = csv.writer(f, quoting=csv.QUOTE_ALL)
    writer.writerow(["text", "label", "category", "source"])
    writer.writerows(rows)

print(f"✅ Clean CSV created with {len(rows)} rows")
print("File saved at: data/scam_dataset.csv")
print("\nNow run training:")
print("python train/train_model.py")