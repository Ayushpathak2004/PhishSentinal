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
- **Model**: `RandomForestClassifier` trained with 100 estimators and 15 explainable numeric features.
- **Primary dataset**: `url_features_extracted1.csv` (101,218 labelled URLs; 63,678 benign / 37,540 malicious). Retrain with `py -m ml.training.train_external`. Current held-out metrics: accuracy 99.05%, precision 98.37%, recall 99.08%, F1 98.73%, ROC AUC 99.95%.
- A synthetic 1,500-sample generator (`py -m ml.training.train`) remains available for demos; its 100% metrics are not real-world accuracy.
- **Features Extracted**:
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
- **Output**: Calibrated probability estimate with feature contribution explanations.

## 5. Groq LLM Contextual Reasoning
- Leverages structured JSON generation via Groq API models (`openai/gpt-oss-120b`).
- Untrusted inputs are sanitized against prompt injection prior to LLM evaluation.
- Fully operating local fallback ensures 100% platform availability even when the external API key is absent or rate-limited.
