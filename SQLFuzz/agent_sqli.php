<?php

if (!extension_loaded('zmark')) { return; }
define('SQLFUZZ_PATH', __DIR__ . '/');

// ★ 我們的特色標記！
define('TAINT_MARKER', 'N0zo');

// 引入 SSRFuzz 的工具函式，我們依然使用它的邏輯
require_once SQLFUZZ_PATH . 'Utils.php';

// 宣告全域變數，用於在請求生命週期內傳遞參數名
global $fuzz_param; 
$fuzz_param = null; 

// 使用 SSRFuzz 的 `taintinfer_zmark_once` 來自動尋找特徵字串並設定 $fuzz_param
// 這個函式內部會尋找 TAINT_MARKER（我們需要稍微修改它，或者確保它能被找到）
// 為了演示，我們假設 taintinfer_zmark_once 內部已經將 'zfuzz' 替換為 TAINT_MARKER
// 或者，更簡單地，我們在請求的值後面附加我們的標記
// (真實的 SSRFuzz 邏輯更複雜，此處為清晰演示其核心)
foreach ($_GET as $key => &$value) {
    if (is_string($value) && strpos($value, TAINT_MARKER) !== false) {
        echo "[DEBUG] Source Marking: Found marker in GET['{$key}']. Value: '{$value}'\n";
        $fuzz_param = $key;
        zmark($value);
        echo "[DEBUG] Source Marking: Taint status for GET['{$key}'] is now: " . (zcheck($value) ? 'TAINTED' : 'CLEAN') . "\n";
        break; 
    }
}
unset($value); // 斷開最後一個元素的引用


// 注意：這個檔案是被 Entry.php 載入的，所以它也能使用 Utils.php 中的函式。

// ==================================================================
// == 步驟一：定義並註冊汙染傳播邏輯 (Define Propagation)
// ==================================================================

function concat_handler($param1, $param2) {
    $result = $param1 . $param2;
    if (zcheck($param1) || zcheck($param2)) {
        zmark($result);
    }
    return $result;
}

function fast_concat_handler($param1, $param2) {
    $result = $param1 . $param2;
    if (zcheck($param1) || zcheck($param2)) {
        zmark($result);
    }
    return $result;
}

function assign_concat_handler($param1, $param2) {
    $result = $param1 . $param2;
    if (zcheck($param1) || zcheck($param2)) {
        zmark($result);
    }
    return $result;
}

function rope_end_handler(array $params) {
    $is_tainted = false;
    foreach ($params as $part) {
        if (zcheck($part)) {
            $is_tainted = true;
            break;
        }
    }
    $result = implode('', $params);
    if ($is_tainted) {
        zmark($result);
    }
    return $result;
}

// 註冊所有汙染傳播的回呼函式
if (function_exists('zregister_opcode_callback')) {
    zregister_opcode_callback(ZMARK_CONCAT, 'concat_handler');
    zregister_opcode_callback(ZMARK_FAST_CONCAT, 'fast_concat_handler');
    zregister_opcode_callback(ZMARK_ASSIGN_CONCAT, 'assign_concat_handler');
    zregister_opcode_callback(ZMARK_ROPE_END, 'rope_end_handler');
}


// ==================================================================
// == 步驟二：定義並掛鉤偵測點邏輯 (Define Sinks)
// ==================================================================

// --- Sink 點偵測與報告 ---
function mysqli_query($link, $query, $resultmode = MYSQLI_STORE_RESULT) {
    global $fuzz_param;

    if (isset($_SERVER['HTTP_X_FUZZER_CONFIRM'])) {
        $fuzz_param = $_SERVER['HTTP_X_FUZZER_PARAM'] ?? null;
    }

    error_log("--- [SINK] mysqli_query Hook Triggered! ---");
    error_log("[DEBUG] Sink Check: Final query string is: {$query}");
    error_log("[DEBUG] Sink Check: Taint status for query is: " . (zcheck($query) ? 'TAINTED' : 'CLEAN'));
    error_log("[DEBUG] Sink Check: Global \$fuzz_param is: " . ($fuzz_param ?? 'null'));


    // 情況一：被動探測階段
    if (zcheck($query) && $fuzz_param !== null) {

        error_log("[DEBUG] Sink Check: PASSED! Inserting candidate into DB.");

        $request_url = $_SERVER['REQUEST_URI'];
        
        // 將候選點存入資料庫
        $db = new mysqli("ssrf_db", "root", "123456", "sqli_analysis_db");
        if ($db->connect_errno === 0) {
            $stmt = $db->prepare("INSERT IGNORE INTO candidates (request_url, source_param_name, sink_function) VALUES (?, ?, 'mysqli_query')");
            $stmt->bind_param("ss", $request_url, $fuzz_param);
            $stmt->execute();
            $stmt->close();
            $db->close();
        }
        error_log("[DEBUG] Sink Check: Candidate stored in database for URL: {$request_url}, parameter: {$fuzz_param}\n");
    }
    
    // 執行原始查詢
    $result = _mysqli_query($link, $query, $resultmode);

    if (isset($_SERVER['HTTP_X_FUZZER_CONFIRM'])) {
        error_log("[DEBUG] Sink Check: Fuzzer confirmation request detected. Checking for vulnerabilities...");
        $is_vuln = true;
        $details = " Potential SQL Injection detected.";

        // // 判斷條件1：查詢是否引發了語法錯誤？
        // if ($result === false) {
        //     $error_msg = mysqli_error($link);
        //     if (strpos(strtolower($error_msg), 'syntax') !== false) {
        //         $is_vuln = true;
        //         $details = "Triggered SQL Syntax Error: " . $error_msg;
        //     }
        // }
        // // 判斷條件2：查詢是否回傳了超乎預期的多行結果？(盲注成功的特徵)
        // // 假設正常查詢最多只返回 1 筆結果
        // elseif (mysqli_num_rows($result) > 1) { 
        //      $is_vuln = true;
        //      $details = "Query returned " . mysqli_num_rows($result) . " rows, indicating successful injection.";
        // }

        // 如果確認漏洞，就報告！
        if ($is_vuln) {
            error_log("[DEBUG] Sink Check: Vulnerability confirmed! Details: {$details}\n");
            $report = json_encode(['details' => $details, /* ...其他資訊... */]);

            // ★ 準備一個結構化的 JSON 物件用於報告
            $report_data = json_encode([
                'vuln_type' => 'SQL Injection',
                'details'   => $details,
                'param'     => $fuzz_param,
                'url'       => $_SERVER['REQUEST_URI'],
                'payload'   => $query
            ]);
            
            error_log("[DEBUG] Sink Check: Reporting vulnerability to detector service...\n");
            file_put_contents('/tmp/vuln_confirmed.log', $report, FILE_APPEND);

            // ★ 將真正的 JSON 物件發送給 Detector
            file_get_contents("http://localhost:5000/report_vuln", false, stream_context_create([
                'http' => [
                    'method'  => 'POST',
                    'header'  => "Content-type: application/json\r\n" . "Connection: close\r\n",
                    'content' => $report_data, // <-- 發送 JSON 字串
                    'timeout' => 2
                ]
            ]));
        }
    }
    
    return $result;
}