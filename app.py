from flask import Flask, render_template, request
from flask_sqlalchemy import SQLAlchemy
import os
from phishing_detector import check_url

app = Flask(__name__)

# SQLite database setup
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///urls.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

# Database model
class URLRecord(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    url = db.Column(db.String(500), unique=True, nullable=False)
    safe_status = db.Column(db.String(50), nullable=False)

# Create DB tables
with app.app_context():
    db.create_all()

@app.route("/", methods=["GET", "POST"])
def index():
    results = []
    urls_input = ""
    if request.method == "POST":
        urls_input = request.form.get("urls")
        if urls_input:
            url_list = [u.strip() for u in urls_input.replace(',', '\n').split('\n') if u.strip()]
            for url in url_list:
                # Check if URL already exists in DB
                record = URLRecord.query.filter_by(url=url).first()
                if record:
                    res = {"URL": url, "Safe/Suspicious": record.safe_status}
                else:
                    res = check_url(url)
                    res["URL"] = url
                    # Store in DB
                    new_record = URLRecord(url=url, safe_status=res["Safe/Suspicious"])
                    db.session.add(new_record)
                    db.session.commit()
                results.append(res)
    return render_template("index.html", results=results, urls_input=urls_input)

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port, debug=True)

