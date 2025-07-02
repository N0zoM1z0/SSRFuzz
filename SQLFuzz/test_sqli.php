<?php

// 1. 我們現在透過 'name' 參數來查詢
if (empty($_GET['name'])) {
    header("HTTP/1.1 400 Bad Request");
    echo "Error: 'name' parameter is missing.";
    exit;
}

// 2. 獲取用戶名
$userName = $_GET['name'];

$servername = "ssrf_db";
$username = "root";
$password = "123456";
$dbname = "sqli_test";

$conn = mysqli_connect($servername, $username, $password, $dbname);
if (!$conn) {
    die("Connection failed: " . mysqli_connect_error());
}

// // BEGIN SANITIZER TEST
// // ★ 新增：模擬開發者做了安全處理
// error_log("Before sanitization, taint status is: " . (zcheck($userName) ? 'TAINTED' : 'CLEAN'));
// $userName = addslashes($userName); // 或者 intval($userName)
// error_log("After sanitization, taint status is: " . (zcheck($userName) ? 'TAINTED' : 'CLEAN'));
// // END SANITIZER TEST

// 3. ★★★ 核心修改：模擬字串型注入點，用單引號包裹變數 ★★★ 要用存在sqli漏洞的代码来测试）
$sql = "SELECT id, name FROM users WHERE name = '" . $userName . "'";

echo "[DEBUG] Executing SQL: " . htmlspecialchars($sql) . "<br>\n";

$result = mysqli_query($conn, $sql);

if ($result) {
    echo "--- Query Result ---<br>\n";
    // ★ 如果注入成功，這裡會印出所有用戶，而不只是一個
    echo "Rows returned: " . mysqli_num_rows($result) . "<br>\n";
    while ($row = mysqli_fetch_assoc($result)) {
        echo "ID: " . $row["id"] . " - Name: " . $row["name"] . "<br>\n";
    }
    mysqli_free_result($result);
} else {
    // 如果注入的 payload 造成語法錯誤，會執行到這裡
    echo "Error: " . mysqli_error($conn);
}

mysqli_close($conn);
?>