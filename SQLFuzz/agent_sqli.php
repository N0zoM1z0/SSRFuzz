<?php
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

function mysqli_query($link, $query, $resultmode = MYSQLI_STORE_RESULT) {
    echo "\n--- [SINK] mysqli_query Hook Triggered! ---\n";

    if (zcheck($query)) {
        echo "    [!] ALERT: SQL Query is tainted by user input!\n";
    }
    
    return _mysqli_query($link, $query, $resultmode);
}