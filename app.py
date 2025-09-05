from flask import Flask, request, render_template
from phishing_detector import analyze_url_for_web  # import your phishing detector
import os

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port, debug=True)
app = Flask(__name__)

@app.route("/", methods=["GET", "POST"])
def home():
    results = []
    if request.method == "POST":
        urls = request.form["urls"].split(",")
        for url in urls:
            url = url.strip()
            results.append(analyze_url_for_web(url))
    return render_template("index.html", results=results)

if __name__ == "__main__":
    app.run(debug=True)

