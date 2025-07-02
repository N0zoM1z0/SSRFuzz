import requests
import mysql.connector
import time
from urllib.parse import urlparse, urlunsplit, parse_qsl, urlencode
import uuid

# 我們的特色標記
TAINT_MARKER = "N0zo"
SQLI_PAYLOAD = "' OR '1'='1"

class Fuzzer:
    def __init__(self):
        self.db_config = {'host': "ssrf_db", 'user': "root", 'password': "123456", 'database': "sqli_analysis_db"}
        # ★ 就在同一个容器内
        self.php_app_host = "localhost:8000" 
        print("[FUZZER] Initialized.")

    def discover(self):
        """階段一：探測。對所有參數附加「隨機」+ N0zo 標記來尋找候選點。"""
        random_prefix = uuid.uuid4().hex[:4]
        
        # 為演示，我們手動定義一個目標
        base_url = f"http://{self.php_app_host}/test_sqli.php?name={random_prefix+TAINT_MARKER}&id=1&user=test"
        print(f"\n--- [STAGE 1: DISCOVERY] ---")
        print(f"Base URL: {base_url}")
        
        parts = urlparse(base_url)
        params_list = parse_qsl(parts.query) # 得到 [('id', '1'), ('user', 'test')]

        # ★ 修正 #1：使用 enumerate 來正確遍歷索引和元組
        for i, (param_name, param_value) in enumerate(params_list):
            # 建立一個探測請求
            test_params_list = params_list.copy()
            
            # ★ 修正 #2：透過索引來修改特定參數的值
            test_params_list[i] = (param_name, param_value + TAINT_MARKER)
            
            # urlencode可以直接處理由元組組成的列表
            new_query = urlencode(test_params_list)
            test_url = urlunsplit((parts.scheme, parts.netloc, parts.path, new_query, parts.fragment))
            
            print(f"[DISCOVERY] Sending probe to param '{param_name}': {test_url}")
            try:
                requests.get(test_url, timeout=3)
            except requests.RequestException:
                pass
    
    def confirm(self):
        """階段二：驗證。讀取候選點，發射真實 Payload。"""
        print(f"\n--- [STAGE 2: CONFIRMATION] ---")
        try:
            conn = mysql.connector.connect(**self.db_config)
            cursor = conn.cursor(dictionary=True)
            cursor.execute("SELECT * FROM candidates WHERE status = 0")
            candidates = cursor.fetchall()

            if not candidates:
                print("[CONFIRM] No new candidates to confirm.")
                cursor.close()
                conn.close()
                return

            for candidate in candidates:
                print(f"[CONFIRM] Testing candidate ID {candidate['id']} on param '{candidate['source_param_name']}'")
                
                # 構建攻擊 URL
                parts = urlparse(candidate['request_url'])
                params_list = parse_qsl(parts.query)
                
                # ★ 修正 #3：建立一個新的列表來存放修改後的參數
                new_params_list = []
                for name, value in params_list:
                    if name == candidate['source_param_name']:
                        # 如果是目標參數，就替換成 Payload
                        new_params_list.append((name, SQLI_PAYLOAD))
                    else:
                        # 否則，保持原樣
                        new_params_list.append((name, value))

                attack_query = urlencode(new_params_list)
                attack_url = urlunsplit(('http', self.php_app_host, parts.path, attack_query, ''))

                # 發送帶有特殊標頭的攻擊請求
                target_param_name = candidate['source_param_name']
                headers = {
                    'X-Fuzzer-Confirm': 'SQLI',
                    'X-Fuzzer-Param': target_param_name  # ★ 新增標頭，傳遞目標參數名
                }
                print(f"[CONFIRM] Sending attack on param '{target_param_name}': {attack_url}")
                try:
                    requests.get(attack_url, headers=headers, timeout=3)
                except requests.RequestException as e:
                    print(f"[CONFIRM] Request failed {e}")
                
                # 更新狀態為已 Fuzz
                # DEBUG先不更新
                update_cursor = conn.cursor()
                update_cursor.execute(f"UPDATE candidates SET status = 1 WHERE id = {candidate['id']}")
                conn.commit()
                update_cursor.close()

            cursor.close()
            conn.close()
        except mysql.connector.Error as e:
            print(f"[CONFIRM] DB Error: {e}")

    def run(self):
        # 為了演示，我們先探測一次，然後進入迴圈進行驗證
        self.discover()
        while True:
            self.confirm()
            print("\n[FUZZER] Cycle finished. Waiting 5 seconds...")
            time.sleep(5)

if __name__ == "__main__":
    fuzzer = Fuzzer()
    fuzzer.run()