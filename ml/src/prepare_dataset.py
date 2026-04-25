"""Download and normalize the UCI SMS Spam Collection for TrustNet AI."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from urllib.request import urlretrieve
from zipfile import ZipFile

import pandas as pd
from sklearn.model_selection import train_test_split


UCI_SMS_SPAM_URL = (
    "https://archive.ics.uci.edu/ml/machine-learning-databases/00228/"
    "smsspamcollection.zip"
)

CURATED_SCAM_EXAMPLES = [
    "Urgent your bank account has been suspended verify your password immediately at this link",
    "Your card will be blocked today update your login and OTP now",
    "Security alert unusual account activity confirm your PIN to restore access",
    "Your wallet refund is pending share the OTP to release the amount",
    "Congratulations you won a cash prize claim it before midnight",
    "Your parcel delivery failed pay the courier fee through this payment link",
    "Limited time crypto investment double your money in 24 hours",
    "Job offer approved pay the document verification fee now",
    "Your tax refund is ready submit bank details to receive payment",
    "Marketplace buyer is waiting pay insurance deposit to unlock shipping",
    "Loan approved instantly send Aadhaar PAN and processing fee",
    "We detected login from a new device verify account at secure support link",
    "Your subscription payment failed update card details to avoid account closure",
    "Prize department selected your number send registration fee to claim",
    "UPI cashback pending approve collect request to receive reward",
    "Your social media profile will be deleted verify password through this page",
    "Bank KYC expired upload documents and OTP immediately",
    "Legal notice issued pay settlement amount now to avoid arrest",
    "Electricity connection will be disconnected pay pending bill at this link",
    "Investment advisor guaranteed profit transfer joining fee today",
    "Refund team needs your one time password to process money back",
    "Account verification required click here and enter login credentials",
    "Winner notification claim free gift by paying delivery charge",
    "Remote work role confirmed buy starter kit before onboarding",
    "Your device is infected call support and purchase security plan",
    "Payment failed but refund available verify bank password now",
    "Offer expires in 10 minutes click link to unlock bonus reward",
    "KYC update mandatory share OTP or account will be frozen",
    "Courier address incomplete pay small fee to release package",
    "Crypto wallet locked enter seed phrase to restore funds",
]

CURATED_SAFE_EXAMPLES = [
    "Team meeting moved to 4 PM today and the agenda is in the shared folder",
    "Your grocery order has been delivered at the front desk",
    "Reminder your dentist appointment is confirmed for Tuesday morning",
    "The invoice has been attached for your review and payment records",
    "Your ride is arriving in five minutes at the main gate",
    "Please review the project brief before our standup tomorrow",
    "Your monthly statement is ready in the official banking app",
    "The package was delivered successfully and no action is needed",
    "Thanks for the update I will send the revised design tonight",
    "Your password was changed successfully from your account settings",
    "The school bus will arrive ten minutes late because of traffic",
    "Your restaurant booking for two people is confirmed",
    "The service ticket has been closed after the technician visit",
    "Payroll documents are available in the employee portal",
    "Your appointment has been rescheduled to Friday at 11 AM",
    "Please join the video call using the calendar invite",
    "The maintenance team will inspect the office network tomorrow",
    "Your order receipt is attached for your records",
    "I have shared the notes from today's product review",
    "The conference registration confirmation has been sent to your email",
]


def prepare_uci_sms_dataset(
    raw_dir: Path,
    processed_dir: Path,
    test_size: float = 0.2,
    random_state: int = 42,
) -> dict[str, object]:
    """Download UCI SMS Spam data and save full, train, and test CSV files."""

    raw_dir.mkdir(parents=True, exist_ok=True)
    processed_dir.mkdir(parents=True, exist_ok=True)

    zip_path = raw_dir / "uci_sms_spam_collection.zip"
    extracted_path = raw_dir / "SMSSpamCollection"

    if not zip_path.exists():
        print(f"Downloading dataset from {UCI_SMS_SPAM_URL}")
        urlretrieve(UCI_SMS_SPAM_URL, zip_path)

    if not extracted_path.exists():
        with ZipFile(zip_path) as archive:
            archive.extract("SMSSpamCollection", raw_dir)

    dataset = pd.read_csv(
        extracted_path,
        sep="\t",
        names=["raw_label", "text"],
        encoding="latin-1",
    )
    dataset["label"] = dataset["raw_label"].map({"ham": "Safe", "spam": "Scam"})
    dataset = dataset[["text", "label"]].dropna().drop_duplicates()

    train_df, test_df = train_test_split(
        dataset,
        test_size=test_size,
        random_state=random_state,
        stratify=dataset["label"],
    )

    curated_df = pd.DataFrame(
        [{"text": text, "label": "Scam"} for text in CURATED_SCAM_EXAMPLES]
        + [{"text": text, "label": "Safe"} for text in CURATED_SAFE_EXAMPLES]
    )
    augmented_train_df = pd.concat([train_df, curated_df], ignore_index=True)

    full_path = processed_dir / "trustnet_sms_full.csv"
    train_path = processed_dir / "trustnet_sms_train.csv"
    augmented_train_path = processed_dir / "trustnet_sms_train_augmented.csv"
    test_path = processed_dir / "trustnet_sms_test.csv"
    metadata_path = processed_dir / "dataset_metadata.json"

    dataset.to_csv(full_path, index=False)
    train_df.to_csv(train_path, index=False)
    augmented_train_df.to_csv(augmented_train_path, index=False)
    test_df.to_csv(test_path, index=False)

    metadata = {
        "source": "UCI SMS Spam Collection",
        "source_url": UCI_SMS_SPAM_URL,
        "full_path": str(full_path),
        "train_path": str(train_path),
        "augmented_train_path": str(augmented_train_path),
        "test_path": str(test_path),
        "rows": int(len(dataset)),
        "train_rows": int(len(train_df)),
        "augmented_train_rows": int(len(augmented_train_df)),
        "curated_scam_rows": len(CURATED_SCAM_EXAMPLES),
        "curated_safe_rows": len(CURATED_SAFE_EXAMPLES),
        "test_rows": int(len(test_df)),
        "label_counts": dataset["label"].value_counts().to_dict(),
        "augmented_train_label_counts": augmented_train_df["label"]
        .value_counts()
        .to_dict(),
        "test_size": test_size,
        "random_state": random_state,
    }
    metadata_path.write_text(json.dumps(metadata, indent=2), encoding="utf-8")
    return metadata


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Prepare TrustNet AI dataset.")
    parser.add_argument(
        "--raw-dir",
        type=Path,
        default=Path("ml/data/raw"),
        help="Directory for downloaded raw dataset files.",
    )
    parser.add_argument(
        "--processed-dir",
        type=Path,
        default=Path("ml/data/processed"),
        help="Directory for normalized train/test CSV files.",
    )
    parser.add_argument(
        "--test-size",
        type=float,
        default=0.2,
        help="Fraction of rows reserved for evaluation.",
    )
    return parser.parse_args()


if __name__ == "__main__":
    args = parse_args()
    summary = prepare_uci_sms_dataset(
        raw_dir=args.raw_dir,
        processed_dir=args.processed_dir,
        test_size=args.test_size,
    )
    print(json.dumps(summary, indent=2))
