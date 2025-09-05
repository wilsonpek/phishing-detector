from flask import Flask, render_template, request
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime
from phishing_detector import check_url

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///urls.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

# Database model
class URLScan(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    url = db.Column(db.String, unique=True, nullable=False)
    result = db.Column(db.PickleType, nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)

db.create_all()

@app.route('/', methods=['GET', 'POST'])
def index():
    results = []
    urls_input = ''
    if request.method == 'POST':
        urls_input = request.form['urls']
        url_list = [u.strip() for u in urls_input.replace(',', '\n').split('\n') if u.strip()]
        for url in url_list:
            existing = URLScan.query.filter_by(url=url).first()
            if existing:
                # Update timestamp if scanned again
                existing.timestamp = datetime.utcnow()
                results.append(existing.result)
                db.session.commit()
            else:
                result = check_url(url)
                results.append(result)
                new_scan = URLScan(url=url, result=result)
                db.session.add(new_scan)
                db.session.commit()
    return render_template('index.html', results=results, urls_input=urls_input)

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)

