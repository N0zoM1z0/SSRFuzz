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
        $fuzz_param = $key; // 捕獲參數名
        zmark($value);      // 汙染這個值
    }
}
unset($value); // 斷開最後一個元素的引用

// 鏈式載入核心分析引擎
require_once SQLFUZZ_PATH . 'agent_sqli.php';