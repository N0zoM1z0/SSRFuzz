<?php
// 测试类似json这种嵌套的参数，看能否被taint捕获到

// 假设从GET请求中获取复杂的JSON数据
$json_data = isset($_GET['data']) ? $_GET['data'] : '{"config":{"api":{"endpoints":[{"primary":false,"settings":{"timeout":30}},{"primary":true,"settings":{"timeout":10,"connection":{"url":"https://example.com/api/data","method":"GET","headers":{"Authorization":"Bearer token123"}}}}],"version":"1.2.3"},"options":{"debug":true,"cache":false}}}';

// 解析复杂的嵌套JSON结构
$parsed_data = json_decode($json_data, true);

// 通过多层嵌套访问URL参数
if (isset($parsed_data['config']['api']['endpoints'][1]['settings']['connection']['url'])) {
    $url = $parsed_data['config']['api']['endpoints'][1]['settings']['connection']['url'];
    
    // 额外的URL处理 - 从嵌套对象中提取查询参数
    if (isset($parsed_data['config']['api']['options']['query'])) {
        $query_string = http_build_query($parsed_data['config']['api']['options']['query']);
        $url .= '?' . $query_string;
    }
    
    echo "Extracted URL: " . $url . "\n";
    $result = file_get_contents($url);
    echo "Result: " . $result . "\n";
} else {
    echo "URL not found in the JSON structure\n";
}

/*
<?php
// 测试类似json这种嵌套的参数，看能否被taint捕获到

// 假设从POST请求中获取复杂的JSON数据
$json_data = isset($_POST['data']) ? $_POST['data'] : '{"config":{"api":{"endpoints":[{"primary":false,"settings":{"timeout":30}},{"primary":true,"settings":{"timeout":10,"connection":{"url":"https://example.com/api/data","method":"GET","headers":{"Authorization":"Bearer token123"}}}}],"version":"1.2.3"},"options":{"debug":true,"cache":false}}}';

// 解析复杂的嵌套JSON结构
$parsed_data = json_decode($json_data, true);

// 通过多层嵌套访问URL参数
if (isset($parsed_data['config']['api']['endpoints'][1]['settings']['connection']['url'])) {
    $url = $parsed_data['config']['api']['endpoints'][1]['settings']['connection']['url'];
    
    // 额外的URL处理 - 从嵌套对象中提取查询参数
    if (isset($parsed_data['config']['api']['options']['query'])) {
        $query_string = http_build_query($parsed_data['config']['api']['options']['query']);
        $url .= '?' . $query_string;
    }
    
    echo "Extracted URL: " . $url . "\n";
    $result = file_get_contents($url);
    echo "Result: " . $result . "\n";
} else {
    echo "URL not found in the JSON structure\n";
}
*/