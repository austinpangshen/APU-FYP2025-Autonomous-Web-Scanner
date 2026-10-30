import requests
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
import joblib
import re

class MLXSSScanner:

    def __init__(self):
        self.session = requests.Session()

        # Load trained model
        self.model = joblib.load("model.pkl")
        self.le = joblib.load("label_encoder.pkl")

        self.payloads = [
            "<script>alert(1)</script>",
            "\"><script>alert(1)</script>",
            "<img src=x onerror=alert(1)>",
        ]

    # =========================
    # FEATURE EXTRACTION
    # =========================
    def extract_features(self, payload, response):

        payload_length = len(payload)
        special_chars = len(re.findall(r"[<>'\"/]", payload))
        response_length = len(response)
        length_diff = abs(response_length - payload_length)

        has_script = int("<script" in payload.lower())
        has_event = int("onerror" in payload.lower() or "onclick" in payload.lower())
        has_js_protocol = int("javascript:" in payload.lower())

        has_h1 = int("<h1>" in response.lower())
        has_basic_html = int("<html>" in response.lower())
        has_html_tag = int("<" in response and ">" in response)

        return [[
            payload_length,
            special_chars,
            response_length,
            length_diff,
            has_script,
            has_event,
            has_js_protocol,
            has_h1,
            has_basic_html,
            has_html_tag
        ]]

    # =========================
    # ML PREDICTION
    # =========================
    def predict(self, features):

        pred = self.model.predict(features)
        probs = self.model.predict_proba(features)[0]

        label = self.le.inverse_transform(pred)[0]

        confidence = {
            self.le.classes_[i]: float(probs[i])
            for i in range(len(probs))
        }

        return label, confidence

    # =========================
    # SCAN URL
    # =========================
    def scan_url(self, url):

        print(f"\nScanning: {url}")

        parsed = urlparse(url)
        params = parse_qs(parsed.query)

        if not params:
            print("No parameters found.")
            return

        for param in params:
            print(f"\n--- Testing parameter: {param} ---")

            for payload in self.payloads:

                test_params = params.copy()
                test_params[param] = [payload]

                new_query = urlencode(test_params, doseq=True)

                test_url = urlunparse((
                    parsed.scheme,
                    parsed.netloc,
                    parsed.path,
                    parsed.params,
                    new_query,
                    parsed.fragment
                ))

                print(f"\nPayload: {payload}")

                try:
                    response = self.session.get(test_url, timeout=5)
                    response_text = response.text

                    # Extract features
                    features = self.extract_features(payload, response_text)

                    # Predict
                    label, confidence = self.predict(features)

                    print("Prediction:", label)
                    print("Confidence Meter:")
                    for k, v in confidence.items():
                        print(f"  {k}: {v:.3f}")

                except Exception as e:
                    print("Request error:", e)


# =========================
# RUN
# =========================
if __name__ == "__main__":

    scanner = MLXSSScanner()

    target = input(
        "Enter URL with parameter (example: http://testphp.vulnweb.com/search.php?test=1): "
    )

    scanner.scan_url(target)