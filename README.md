# Malicious URL Finder

A Flask demonstration that turns a URL string into lexical features and passes those features to a saved classification model.

## What the code demonstrates

- URL parsing and feature engineering in `model.py`.
- A 21-column pandas feature frame, including URL length, character counts, hostname/path properties and lexical indicators.
- Model inference with `joblib.load('model.pkl')`.
- A browser page at `/` and a form-based prediction endpoint at `/model`.
- Separate exploration and training notebooks.

This is an experimental classifier, not a guarantee that a website is safe. The request handler analyzes the supplied string; it does not fetch the destination page or perform a live reputation lookup.

## Repository map

| Path | Purpose |
| --- | --- |
| `model.py` | Flask routes, feature extraction and prediction |
| `templates/index.html` | Browser interface |
| `training_model.ipynb` | Model-training workflow |
| `EDA_Malicious_URL_Detection.ipynb` | Exploratory analysis |
| `malicious_phish.csv` | Dataset included with the project |
| `model.pkl` | Serialized model artifact |
| `Procfile` | Deployment process entry point |

## Running locally

Use an isolated virtual environment. Review dependencies before installation: `requirements.txt` is an unpinned historical list and contains the legacy `sklearn` package name. A reproducible, version-pinned environment compatible with the model artifact has not yet been documented.

Once compatible dependencies are installed and the trusted model artifact is available, start from the repository root:

```sh
flask --app model run --host 127.0.0.1 --port 5000
```

Use the local development server only. Running `python model.py` instead enables debug mode and binds all interfaces in the current source.

## API example

```sh
curl -X POST http://127.0.0.1:5000/model \
  --data-urlencode "url=https://example.com"
```

The current response has the shape `{"result":{"output":<integer class>}}`. Establish the integer-to-class mapping from the training workflow before presenting a user-facing label. Do not interpret an arbitrary integer as a safety verdict.

## Validation and limitations

A useful next test suite should cover the 21-column feature order, malformed/empty input, missing form keys, model-loading failures and stable predictions on a documented fixture set. The repository does not currently establish an automated test suite, calibrated probabilities or production monitoring.

Before deployment, add input validation, explicit error responses, request limits, pinned dependencies, evaluation results with dataset/split details, and a documented model version. Avoid logging user-submitted URLs, which may contain private query parameters.

Only load trusted pickle/joblib artifacts: deserialization can execute code. Review dataset provenance and reuse rights before redistribution. No accuracy, latency or production-scale claim is made by this README.
