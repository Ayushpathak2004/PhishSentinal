# Email training dataset

The trainer loads the pinned Hugging Face dataset
[`puyang2025/seven-phishing-email-datasets`](https://huggingface.co/datasets/puyang2025/seven-phishing-email-datasets)
at revision `b7f3f8d99ebd4fd0af0a5afe027420e53f08d1a4`. Its `train` and `test`
splits contain 162,413 and 40,604 rows respectively. Label `0` is benign/ham;
label `1` includes phishing, spam, and other unwanted email.

The corpus is not copied into this repository; Hugging Face caches it locally.
The dataset card says the aggregate has no single license, inherits restrictions
from its seven source datasets, and may contain personal information. Review the
original source terms before redistributing data or trained model artifacts.
