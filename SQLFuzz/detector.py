from flask import Flask, request, jsonify
import datetime

app = Flask(__name__)

@app.route('/report_vuln', methods=['POST'])
def report_vuln():
    # 從 POST 請求中獲取 JSON 報告
    report = request.get_json(silent=True) or {}
    
    # 打印一個清晰的標題
    print("\n" + "="*60)
    print(f"[{datetime.datetime.now()}] !!! VULNERABILITY CONFIRMED by PHP Agent !!!")
    
    # ★ 核心修改：解析並打印新的、更詳細的報告欄位
    print(f"  Vuln Type: {report.get('vuln_type', 'N/A')}")
    print(f"  URL: {report.get('url', 'N/A')}")
    print(f"  Tainted Parameter: {report.get('param', 'N/A')}")
    print(f"  Details: {report.get('details', 'N/A')}")
    print(f"  Final Payload: {report.get('payload', 'N/A')}")
    
    # ★ 新增：美觀地打印呼叫堆疊
    print(f"  Call Stack Trace:")
    # 從報告中獲取呼叫堆疊字串，如果不存在則顯示提示
    call_stack = report.get('call_stack', '  (Not provided)')
    # 為了對齊，給每一行前面都加上縮排
    for line in call_stack.strip().split('\n'):
        print(f"    {line.strip()}")
        
    print("="*60 + "\n")
    
    return jsonify({"status": "reported"})

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)

