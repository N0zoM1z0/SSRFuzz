from flask import Flask, request, jsonify
import datetime

app = Flask(__name__)

@app.route('/report_vuln', methods=['POST'])
def report_vuln():
    report = request.get_json(silent=True) or {}
    print("\n" + "="*60)
    print(f"[{datetime.datetime.now()}] !!! VULNERABILITY CONFIRMED by PHP Agent !!!")
    print(f"  Vuln Type: {report.get('vuln_type', 'N/A')}")
    print(f"  URL: {report.get('url', 'N/A')}")
    print(f"  Tainted Parameter: {report.get('param', 'N/A')}")
    print(f"  Final Payload: {report.get('payload', 'N/A')}")
    print(f"  DB Error: {report.get('error', 'N/A')}")
    print("="*60 + "\n")
    return jsonify({"status": "reported"})

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)