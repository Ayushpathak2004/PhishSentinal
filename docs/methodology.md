# Cybersecurity Detection Methodology

## 1. Email Fraud & Phishing Detection
- **Authentication Alignment**: Analyzes SPF, DKIM, and DMARC result headers from `Authentication-Results` and `Received-SPF`.
- **Identity Inconsistencies**: Detects mismatches between RFC5322 `From` and `Reply-To` headers, an indicator of Business Email Compromise (BEC).
- **Social Engineering Lexicon**: Identifies coercive urgency markers, account suspension threats, and credential solicitations.
- **Attachment Forensics**: Flags dangerous executable extensions (`.exe`, `.scr`, `.vbs`, `.iso`) and deceptive double extensions (`invoice.pdf.exe`).

## 2. Website & URL Security Analysis
- **SSRF Prevention**: Inspects domain resolutions and rejects access to RFC1918 private subnets, loopbacks (`127.0.0.1`), link-local IPs, and cloud metadata services (`169.254.169.254`).
- **Typosquatting & Homoglyphs**: Computes Levenshtein edit distances against high-value brands (PayPal, Microsoft, Apple, Google, Chase, Amazon, etc.) and detects Punycode/IDN spoofing.
- **DGA Entropy Analysis**: Evaluates Shannon entropy across subdomains to identify algorithmically generated botnet domains.
- **Non-Invasive Safe Probe**: Probes HTTP endpoints with strict 1.0-second timeouts, verifying redirect chains without executing scripts or downloading payloads.

## 3. QR Code & Quishing Forensics
- **Matrix Decoding**: Utilizes OpenCV `QRCodeDetector` with fallback adaptive thresholding to extract embedded strings.
- **Payment Scheme Analysis**: Identifies UPI, Bitcoin, Solana, and PayPal payment directives. Analyzes transaction notes for coercive social engineering (e.g., electricity disconnection notices).
- **Zero-Execution Safeguard**: Permanently blocks automated payment dispatch and destination loading.

## 4. Machine Learning Component
- **Website / URL**: A `RandomForestClassifier` uses 15 lexical and structural features, trained from `ml/url/datasets/url_features_extracted1.csv` (101,218 labeled URLs; 63,678 malicious / 37,540 benign). The source dataset labels `0` as malicious and `1` as benign; training remaps these so model class `1` consistently means malicious. Training and inference share canonical feature extraction, treating an optional `www.` prefix and an empty root path as equivalent. The source is URL-only; email-specific fields are not evidence for email classification.
- **QR / quishing**: An `ExtraTreesClassifier` uses flattened 69x69 binary QR images from `ml/qr/datasets/QuishingDataset.zip` (9,987 labeled images). The training metadata treats label `1` as quishing; verify that mapping against the dataset source before production use.
- **Email**: A `TfidfVectorizer` + `MultinomialNB` classifier uses the subject and body from `puyang2025/seven-phishing-email-datasets` (162,413 train / 40,604 test). Train accuracy/precision are **96.28% / 98.47%**; test accuracy/precision are **96.03% / 98.50%**. Label `1` includes spam as well as phishing. The corpus has mixed source licenses and may contain PII; see `ml/email/datasets/README.md`.
- Each task's training code and artifacts live in `ml/url/`, `ml/qr/`, or `ml/email/`; train an individual model with `py -m ml.url.train`, `py -m ml.qr.train`, or `py -m ml.email.train`. The combined command `py -m ml.training.train_models` prints a final summary table of training and held-out testing accuracy and precision for all three models. Metrics are also shown on the Overview page and at `/api/ml/metrics`.
- Test-split results are dataset-specific and should not be treated as production performance without validation on independent, representative data. A synthetic demo trainer (`py -m ml.training.train`) remains separate from runtime inference.
- **URL model features**:
  1. `url_length`
  2. `domain_length`
  3. `num_dots`
  4. `num_hyphens`
  5. `has_ip`
  6. `has_at_symbol`
  7. `domain_entropy`
  8. `is_shortener`
  9. `has_sensitive_keyword`
  10. `has_brand_mention`
  11. `urgency_count`
  12. `credential_harvest_count`
  13. `sender_reply_mismatch`
  14. `has_executable_attachment`
  15. `dmarc_spf_failure`
- **Output**: Model-estimated probability for the malicious class, with feature contribution explanations.

## 5. Groq LLM Contextual Reasoning
- Leverages structured JSON generation via Groq API models (`openai/gpt-oss-120b`).
- Untrusted inputs are sanitized against prompt injection prior to LLM evaluation.
- Fully operating local fallback ensures 100% platform availability even when the external API key is absent or rate-limited.
