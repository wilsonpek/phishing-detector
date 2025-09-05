from flask import Flask, request, render_template
from phishing_detector import analyze_url_for_web  # import your phishing detector

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

