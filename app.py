from flask import Flask, request, jsonify, render_template
from flask_cors import CORS
from urllib.parse import urlparse
from datetime import datetime
import threat_intel

app = Flask(__name__)
CORS(app)  # Enable CORS for browser extension

# ─── In-Memory Scan Storage ───────────────────────────────────────────────────
scan_history = []
MAX_HISTORY = 100

def record_scan(content, content_type, status, confidence):
    """Record a scan to in-memory history."""
    # Truncate content for storage
    preview = content[:80] + '...' if len(content) > 80 else content

    record = {
        'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
        'type': content_type,
        'content': preview,
        'status': status,
        'confidence': confidence
    }

    scan_history.insert(0, record)

    # Keep only the most recent scans
    if len(scan_history) > MAX_HISTORY:
        scan_history.pop()

# ─── Routes ──────────────────────────────────────────────────────────────────

@app.route('/')
def home():
    return render_template('index.html')

@app.route('/predict', methods=['POST'])
def predict():
    data = request.get_json()
    content = data.get('content')
    content_type = data.get('type', 'url')

    if not content:
        return jsonify({'status': 'Error', 'content': '', 'reasons': ['No content provided.']})

    try:
        if content_type == 'url':
            # Run threat intelligence URL analysis
            analysis = threat_intel.analyze_url(content)
            
            # Map verdict to frontend expected status: 'Safe' or 'Phishing Warning'
            status = 'Phishing Warning' if analysis['verdict'] in ['Suspicious', 'Malicious'] else 'Safe'
            confidence = analysis['risk_score']
            reasons = analysis['reasons']
        else:
            # Run threat intelligence email/SMS analysis
            analysis = threat_intel.analyze_text(content, content_type)
            status = 'Phishing Warning' if analysis['verdict'] in ['Suspicious', 'Malicious'] else 'Safe'
            confidence = analysis['risk_score']
            reasons = analysis['reasons']

        record_scan(content, content_type, status, confidence)

        return jsonify({
            'status': status,
            'content': content,
            'confidence': confidence,
            'reasons': reasons
        })

    except Exception as e:
        print(f"!!! ANALYSIS ERROR: {e}")
        return jsonify({'status': 'Error', 'content': content, 'reasons': [f'An error occurred during threat intelligence lookup: {str(e)}']})

# Extension compatibility: alias /check → same logic as /predict
@app.route('/check', methods=['POST'])
def check():
    """Alias endpoint for the browser extension."""
    data = request.get_json()
    url = data.get('url', data.get('content', ''))

    if not url:
        return jsonify({'result': 'Error', 'error': 'No URL provided.'})

    try:
        analysis = threat_intel.analyze_url(url)
        is_phishing = analysis['verdict'] in ['Suspicious', 'Malicious']
        result = "Phishing" if is_phishing else "Safe"
        confidence = analysis['risk_score']

        record_scan(url, 'url', result, confidence)

        return jsonify({
            'prediction': 1 if is_phishing else 0,
            'result': result,
            'confidence': confidence
        })
    except Exception as e:
        print(f"!!! CHECK ERROR: {e}")
        return jsonify({'result': 'Error', 'error': f'Analysis failed: {str(e)}'})

@app.route('/api/stats', methods=['GET'])
def get_stats():
    """Return aggregated scan statistics."""
    total = len(scan_history)
    threats = sum(1 for s in scan_history if s['status'] in ['Phishing Warning', 'Phishing'])
    safe = sum(1 for s in scan_history if s['status'] == 'Safe')
    threat_rate = round((threats / total * 100), 1) if total > 0 else 0

    return jsonify({
        'total_scans': total,
        'threats': threats,
        'safe': safe,
        'threat_rate': threat_rate
    })

@app.route('/api/history', methods=['GET'])
def get_history():
    """Return recent scan history."""
    return jsonify(scan_history[:50])

@app.route('/api/batch', methods=['POST'])
def batch_scan():
    """Scan multiple URLs at once."""
    data = request.get_json()
    urls = data.get('urls', [])

    if not urls:
        return jsonify({'error': 'No URLs provided.', 'results': []})

    results = []
    for url in urls[:20]:  # Limit to 20 URLs per batch
        url = url.strip()
        if not url:
            continue

        try:
            analysis = threat_intel.analyze_url(url)
            is_phishing = analysis['verdict'] in ['Suspicious', 'Malicious']
            status = "Phishing" if is_phishing else "Safe"
            confidence = analysis['risk_score']

            record_scan(url, 'url', status, confidence)
            results.append({'url': url, 'status': status, 'confidence': confidence})
        except Exception:
            results.append({'url': url, 'status': 'Error', 'confidence': 0})

    return jsonify({'results': results})

@app.route('/api/clear-history', methods=['POST'])
def clear_history():
    """Clear all scan history."""
    scan_history.clear()
    return jsonify({'status': 'ok'})

if __name__ == '__main__':
    # Print clean console start message (Windows cp1252 safe)
    print("[OK] PhishGuard threat intelligence server started on port 5000.")
    app.run(debug=True)