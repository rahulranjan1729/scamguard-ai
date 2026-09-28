import datetime
from google.cloud import firestore

# CRITICAL: Hardcode project ID string as required for Firestore
FIRESTORE_PROJECT = "qwiklabs-gcp-03-c7f26ed5ce67"

INITIAL_SCAMS = [
    {
        "title": "Fake IRS Urgent Tax Audit SMS",
        "scam_type": "imposter",
        "risk_level": "high",
        "description": "Text message claiming to be from IRS demanding immediate payment for overdue taxes via gift cards or wire transfer to avoid arrest.",
        "indicators": [
            "SMS from unknown number",
            "Demand for immediate gift card/wire payment",
            "Link to fake domain: irs-tax-audit-claim.org",
        ],
        "recommended_action": "Do not click links. The IRS never contacts taxpayers via SMS or demands gift card payments. Report to irs.gov.",
        "reported_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
    },
    {
        "title": "Phishing Crypto Airdrop & Wallet Connect Scam",
        "scam_type": "crypto",
        "risk_level": "critical",
        "description": "Social media message or email promoting an exclusive token airdrop leading to a malicious dApp that requests full approval to drain crypto wallets.",
        "indicators": [
            "Unsolicited DM about free token claims",
            "Malicious approval payload requesting setApprovalForAll",
            "Spoofed domain: wallet-connect-airdrop.claim",
        ],
        "recommended_action": "Never approve unknown smart contract transactions or enter seed phrases online. Revoke approvals immediately if signed.",
        "reported_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
    },
    {
        "title": "Fake Bank Tech Support Account Suspension Email",
        "scam_type": "phishing",
        "risk_level": "high",
        "description": "Phishing email mimicking a major bank claiming unusual account activity and directing victims to a fake login portal to steal credentials.",
        "indicators": [
            "Sender address mismatch (@sec-bank-verify-alert.com)",
            "Urgent threat of account lock within 2 hours",
            "Hyperlink leading to credential harvester",
        ],
        "recommended_action": "Do not sign in via email links. Navigate directly to your bank's official website or app to verify account status.",
        "reported_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
    },
    {
        "title": "Urgent Grandparent Emergency Wire Scam",
        "scam_type": "financial",
        "risk_level": "critical",
        "description": "Phone call or message posing as a panicked grandchild or lawyer claiming they are in jail overseas and need bail money wired urgently.",
        "indicators": [
            "Panicked call asking 'Grandma is that you?'",
            "Insistence on secrecy ('don't tell Mom')",
            "Wire transfer or crypto payment requirement",
        ],
        "recommended_action": "Hang up and directly call the family member at their known personal phone number before sending any money.",
        "reported_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
    },
]


def seed_database():
    import google.auth

    credentials, _ = google.auth.default()
    print(
        f"Seeding Firestore project '{FIRESTORE_PROJECT}' into collection"
        " 'scam_incidents'..."
    )
    db = firestore.Client(project=FIRESTORE_PROJECT, credentials=credentials)
    collection_ref = db.collection("scam_incidents")

    for scam in INITIAL_SCAMS:
        doc_ref = collection_ref.document()
        doc_ref.set(scam)
        print(f"  Added document ID: {doc_ref.id} - '{scam['title']}'")

    print("Database seeding completed successfully!")


if __name__ == "__main__":
    seed_database()
