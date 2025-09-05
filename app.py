from flask import Flask, render_template, request
import os
from phishing_detector import check_url

app = Flask(__name__)

@app.route("/", methods=["GET", "POST"])
def index():
    result = None
    url_input = ""
    if request.method == "POST":
        url_input = request.form.get("url")
        if url_input:
            result = check_url(url_input)
    return render_template("index.html", result=result, url_input=url_input)

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port, debug=True)

