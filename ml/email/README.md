# Email classification

- **Classifier:** `TfidfVectorizer` + `MultinomialNB`
- **Training data:** `puyang2025/seven-phishing-email-datasets`, loaded from
  Hugging Face and cached outside the repository.
- **Training entry point:** `py -m ml.email.train`
- **Model and metrics:** `models/email_phishing_detector.joblib` and
  `models/email_model_metadata.json`
- **Inference:** combines the email subject and body with the shared
  normalization in `features.py`.

The dataset's label `1` includes phishing and other spam/unwanted messages, not
only phishing. Its card notes mixed source licenses and possible PII; see
`datasets/README.md`. Do not redistribute the raw corpus or trained artifacts
without confirming the original sources' terms.
