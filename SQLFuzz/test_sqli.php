<?php

// 1. 檢查 GET 請求中是否存在 'id' 參數
if (empty($_GET['id'])) {
    // 在 Web 環境中，返回一個錯誤訊息比 die() 更友好
    header("HTTP/1.1 400 Bad Request");
    echo "Error: 'id' parameter is missing.";
    exit;
}

// 2. 從 $_GET 超全局變數中獲取使用者輸入
$userId = $_GET['id'];

// 注意：我們不再需要手動呼叫 zmark($userId)！
// 這個工作將由 auto_prepend_file 指定的檔案自動完成。

$servername = "ssrf_db";
$username = "root";
$password = "123456";
$dbname = "sqli_test";

// 建立連線
$conn = mysqli_connect($servername, $username, $password, $dbname);

// 檢查連線
if (!$conn) {
    die("Connection failed: " . mysqli_connect_error());
}

// 3. 將來自 Web 的輸入直接拼接到 SQL 查詢中
$sql = "SELECT id, name FROM users WHERE id = " . $userId;

// 4. 執行查詢，這將會觸發 agent.php 中的 sink handler
$result = mysqli_query($conn, $sql);

// 為了在瀏覽器或 curl 中更清晰地顯示，我們輸出 HTML 換行符 <br>
if ($result) {
    echo "--- Query Result ---<br>\n";
    while ($row = mysqli_fetch_assoc($result)) {
        echo "ID: " . $row["id"] . " - Name: " . $row["name"] . "<br>\n";
    }
    mysqli_free_result($result);
} else {
    echo "Error: " . mysqli_error($conn);
}

mysqli_close($conn);
?>