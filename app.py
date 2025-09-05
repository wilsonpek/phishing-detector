from flask import Flask, render_template, request
import os
from phishing_detector import check_url  # your existing logic

# Create Flask app
app = Flask(__name__)

# Route for home page
@app.route("/", methods=["GET", "POST"])
def index():
    result = None
    if request.method == "POST":
        url = request.form.get("url")
        if url:
            result = check_url(url)  # call your phishing detection function
    return render_template("index.html", result=result)

# Run the app
if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port, debug=True)

