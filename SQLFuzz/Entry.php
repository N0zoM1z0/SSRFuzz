<?php

// 確保 zmark 擴充功能已載入
if (!extension_loaded('zmark')) {
    return;
}

// 定義路徑常量
define('SQLFUZZ_PATH', __DIR__ . '/');

// 僅載入標記所需的工具函式
require_once SQLFUZZ_PATH . 'Utils.php';
require_once SQLFUZZ_PATH . 'Config.php';


// ==========================================================
// == Entry.php 的唯一職責：自動標記所有汙染源
// ==========================================================

taintinfer_zmark($_GET, '$_GET');
taintinfer_zmark($_POST, '$_POST');
taintinfer_zmark($_COOKIE, '$_COOKIE');


// ==========================================================
// == 鏈式載入：將執行權交給核心分析引擎
// ==========================================================
// 在完成標記後，載入包含所有分析邏輯的 agent 檔案。
require_once SQLFUZZ_PATH . 'agent_sqli.php';