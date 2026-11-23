# QR / quishing classification

- **Classifier:** `ExtraTreesClassifier`
- **Training data:** `datasets/QuishingDataset.zip`
- **Training entry point:** `py -m ml.qr.train`
- **Inference inputs and artifact paths:** `inference.py`
- **Preprocessing:** `preprocessing.py` converts images to the binary 69x69
  pixel input expected by the model.
- **Model and metrics:** `models/qr_quishing_detector.joblib` and
  `models/qr_model_metadata.json`

The training metadata currently treats label `1` as quishing. Confirm that
mapping against the original dataset documentation before relying on it.
