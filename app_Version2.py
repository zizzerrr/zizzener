from flask import Flask, request, jsonify, send_from_directory, render_template
from scanner import scan_website

app = Flask(__name__, static_url_path='/static', static_folder='static', template_folder='static')

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/scan', methods=['POST'])
def scan():
    data = request.json
    url = data.get('url')
    if not url:
        return jsonify({"error": "Missing URL"}), 400
    report = scan_website(url)
    return jsonify(report)

if __name__ == '__main__':
    app.run(debug=True)