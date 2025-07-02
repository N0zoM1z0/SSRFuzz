<?php


if (!function_exists('zmark')) {
    function zmark($str)
    {
        return false;
    }
}

if (!function_exists('zcheck')) {
    function zcheck($str)
    {
        return false;
    }
}

if (!function_exists('zregister_opcode_callback')) {
    function zregister_opcode_callback($opcode, $funcname)
    {
    }
}

if (!function_exists('zclear')) {
    function zclear($str)
    {
        return false;
    }
}

/**
 * Detecting whether a variable is tagged
 * @param $var
 * @param bool $recursive
 * @return int
 */
function taintinfer_zcheck($var, $recursive = true)
{
    if (!TAINTINFER_TAINT_ENABLE) return false;
// check if tagged
    if (is_string($var)) {
        return zcheck($var); // zcheck is implemented in the Hooked ZEND VM extension
    } elseif (is_array($var) && $recursive) { // recursive check
        foreach ($var as $key => &$value) {
            if (taintinfer_zcheck($value, $recursive)) return true;
        }
    }

    return false;
}

function get_variable_name(&$var, $scope = NULL)
{
//    if (NULL == $scope) {
//        $scope = $_GET;
//    }

    switch ($scope) {
        case '$_GET':
            $scope = $_GET;
            break;
        case '$_POST':
            $scope = $_POST;
            break;
        case '$_COOKIE':
            $scope = $_COOKIE;
            break;
        default:
            $scope = $_GET;
    }

    $tmp = $var;
    $var = "tmp_exists_" . mt_rand();
    $name = array_search($var, $scope);
    $var = $tmp;
    return $name;
}

/**
 * Marking the input variables
 * @param $var
 * @param bool $recursive
 */
function taintinfer_zmark_once(&$var, $scope = null, $recursive = true)
{
    global $fuzz_param; // Parameter names that can trigger the vulnerability
    global $fuzz_value; // The value corresponding to the parameter that triggered the vulnerability
//    if (!TAINTINFER_TAINT_ENABLE) return;
    if (is_string($var) && strpos($var, "zfuzz") !== false) {
        $fuzz_param = get_variable_name($var, $scope);
    //    var_dump('get_variable_name()',$fuzz_param);
        $fuzz_value = $var;
        zmark($var);
    } elseif (is_array($var) && $recursive) {
        foreach ($var as $key => &$value) {
            if (strpos($value, "zfuzz") !== false) {
                $fuzz_param = $key;
                $fuzz_value = $value;
                taintinfer_zmark_once($value, $scope, $recursive);
            }
        }
    }
}

/**
 * Tagging variables
 * @param $var
 * @param bool $recursive
 */
function taintinfer_zmark(&$var, $recursive = true)
{
    if (!TAINTINFER_TAINT_ENABLE) return;

    if (is_string($var)) {
        zmark($var);
    } elseif (is_array($var) && $recursive) {
        foreach ($var as $key => &$value) {
            taintinfer_zmark($value, $recursive);
        }
    }
}

/**
 * ★ 新增：遞迴地清除變數的汙染標記
 * 結構與 taintinfer_zmark 完全對稱
 * @param mixed $var 要清除標記的變數，可以是字串或陣列
 * @param bool $recursive 是否遞迴處理陣列
 */
function taintinfer_zclear(&$var, $recursive = true)
{
    // 如果 zclear 函式不存在，則不執行任何操作
    if (!function_exists('zclear')) {
        return;
    }

    if (is_string($var)) {
        // 對字串直接呼叫底層的 zclear()
        zclear($var);
    } elseif (is_array($var) && $recursive) {
        // 如果是陣列，則遍歷每一個元素，遞迴呼叫自身
        foreach ($var as &$value) {
            taintinfer_zclear($value, $recursive);
        }
        // 斷開最後一個元素的引用，這是 foreach(&$value) 的好習慣
        unset($value);
    }
    // 對於非字串和非陣列的類型，我們不進行任何操作
}


/**
 * Detecting callback-related variables
 * @param $call
 * @param $params
 * @param $message
 */
function taintinfer_check_callback($call, $params, $message)
{ // wow! detect potential RCE!
    global $taintinfer_sentry_client;
    if (!$taintinfer_sentry_client) return;

    if (empty($params)) return;

    $calls = array(
        "array_diff_uassoc" => -1,
        "array_diff_ukey" => -1,
        "array_filter" => 1,
        "array_intersect_uassoc" => -1,
        "array_intersect_ukey" => -1,
        "array_map" => 0,
        "array_reduce" => 1,
        "array_udiff" => -1,
        "array_udiff_assoc" => -1,
        "array_udiff_uassoc" => -1,
        "array_uintersect" => -1,
        "array_uintersect_assoc" => -1,
        "array_uintersect_uassoc" => -1,
        "array_walk" => 1,
        "array_walk_recursive" => 1,
        "iterator_apply" => 1,
        "ob_start" => 0,
        "preg_replace_callback" => 1,
        "register_shutdown_function" => 0,
        "register_tick_function" => 0,
        "set_error_handler" => 0,
        "set_exception_handler" => 0,
        "spl_autoload_register" => 0,
        "uasort" => 1,
        "uksort" => 1,
        "usort" => 1,
    );

    $reported = false;

    if (!is_string($call) && !is_array($call)) return;
    if (is_array($call)) $call = $call[0] . '::' . $call[1]; // namespaced class method call
    if (!isset($calls[$call])) return;

    $callback_index = $calls[$call];

    if ($callback_index >= 0 && isset($params[$callback_index]))
        $callback = $params[$callback_index];
    elseif ($callback_index < 0 && isset($params[count($params) + $callback_index]))
        $callback = $params[count($params) + $callback_index];
    else
        return;

    if (is_string($callback)) {
        if (stripos($callback, TAINTINFER_TANZI) !== false) {
            $taintinfer_sentry_client->captureVuln($message);
            $reported = true;
        }
    } elseif (is_array($callback)) {
        if (is_string($callback[0]) && stripos($callback[0], TAINTINFER_TANZI) !== false) {
            $taintinfer_sentry_client->captureVuln($message);
            $reported = true;
        }
        if (is_string($callback[1]) && stripos($callback[1], TAINTINFER_TANZI) !== false) {
            $taintinfer_sentry_client->captureVuln($message);
            $reported = true;
        }
    }

    if (TAINTINFER_TAINT_ENABLE && !$reported && taintinfer_zcheck($callback)) {
        $taintinfer_sentry_client->captureVuln($message, "debug");
    }
}


/**
 * Detecting if a dynamically called function name is controllable
 * @param $funcname
 * @param $message
 */
function taintinfer_check_dynamic_call(&$funcname, $message)
{
    global $taintinfer_sentry_client;
    if (!$taintinfer_sentry_client) return;

    $reported = false;

    if (is_string($funcname)) {
        if (stripos($funcname, TAINTINFER_TANZI) !== false) {
            $taintinfer_sentry_client->captureVuln($message);
            $reported = true;
        }
    } else if (is_array($funcname)) {
        if (is_string($funcname[0]) && (stripos($funcname[0], TAINTINFER_TANZI) !== false)) {
            $taintinfer_sentry_client->captureVuln($message);
            $reported = true;
        }

        if (is_string($funcname[1]) && (stripos($funcname[1], TAINTINFER_TANZI) !== false)) {
            $taintinfer_sentry_client->captureVuln($message);
            $reported = true;
        }
    }

    if (TAINTINFER_TAINT_ENABLE && !$reported && taintinfer_zcheck($funcname)) {
        $taintinfer_sentry_client->captureVuln($message, "debug");
    }
}


/**
 * Detecting path-related variables
 * @param $path
 * @param $message
 */
function taintinfer_check_path(&$path, $message)
{
    global $taintinfer_sentry_client;
    if (!$taintinfer_sentry_client) return;

    $reported = false;

    if (stripos($path, "../" . TAINTINFER_TANZI) !== false || stripos($path, "..\\" . TAINTINFER_TANZI) !== false) {
        $taintinfer_sentry_client->captureVuln($message);
        $reported = true;
    }

    if (TAINTINFER_TAINT_ENABLE && !$reported && taintinfer_zcheck($path)) {
        $taintinfer_sentry_client->captureVuln($message, "debug");
    }
}


/**
 * Phased discrimination algorithm
 * @param $cmd_string
 * @return bool
 */
function taintinfer_check_ssrf(&$cmd_string, $message) {

    // Type inference algorithm 
    // Type inference algorithm will be carried out when the current row data is complete
    global $fuzz_param;
    global $fuzz_value;
    global $vuln_stack;
    global $taintinfer_vuln_type;
    global $taintinfer_sentry_client;

    taintinfer_log("fuzz_param:".$fuzz_param."\n");
    taintinfer_log("fuzz_value:".$fuzz_value."\n");

    taintinfer_log("TAINTINFER_IS_VULN_TYPE_FUZZER_REQUEST:".TAINTINFER_IS_VULN_TYPE_FUZZER_REQUEST."\n",FILE_APPEND);
    if (TAINTINFER_IS_VULN_TYPE_FUZZER_REQUEST){
        cleanVulnInfo();
        return false;
    }

    if (strcmp($taintinfer_vuln_type, "FUZZ") !==0  || !TAINTINFER_IS_FUZZER_REQUEST) {
        return false;
    }
    taintinfer_log("start alg");

    // The first stage: sub-string discrimination stage
    if (substring($cmd_string, $fuzz_value)) {
        global $taintinfer_vuln_type;
        $taintinfer_vuln_type = "SSRF";
        updateVulnType($taintinfer_vuln_type, $fuzz_param);
        taintinfer_log("substring:" . $taintinfer_vuln_type . "\n", FILE_APPEND);

        $taintinfer_sentry_client = new TAINTINFER_Sentry_Client(TAINTINFER_SENTRY_DSN);
        $vuln_stack = $taintinfer_sentry_client->captureStack();
        $vuln_stack_string = json_encode($vuln_stack);
        $encoded_vuln_stack = base64_encode($vuln_stack_string);
        taintinfer_log("vuln_stack2:".$encoded_vuln_stack."\n",FILE_APPEND);
        return true;
    }

    // The second stage: If it is not a substring, then the editing distance should be judged.
    $L = max(strlen($fuzz_value), strlen($cmd_string));
    $D = edit_distance($fuzz_value, $cmd_string);
    $Di = $D[1];
    $Dd = $D[2];

    if (($L - $Di - $Dd) / $L < 0.1) { // similarity
        return false;
    }
    updateVulnType($taintinfer_vuln_type, $fuzz_param);
    return true;
}

// Determine whether string2 is a substring of string1, and if the matching threshold is less than 3, it can be considered that there is a stain flow here.
function substring($string1, $string2)
{
    $string1 = strtolower($string1);
    $string2 = strtolower($string2);

    if (stristr($string1, $string2) !== false) {
        $nosimlen = strlen($string1) - strlen($string2);

        if ($nosimlen <= 3) {
            return true;
        }
    }
    return false;
}

// Using the editing distance, only consider the deletion and addition of strings.
function edit_distance($string1, $string2)
{
    $string1 = strtolower($string1);
    $string2 = strtolower($string2);
    $c0 = levenshtein($string1, $string2, 1, 10, 1000);
    $cost_del = intval($c0 / 1000);
    $cost_ins = $c0 % 1000;
    return array($c0, $cost_ins, $cost_del);
}

function sink_check($param, $Bv) // not used by other code?
{
    $mysql_conf = array(
        'host' => TAINTINFER_MYSQL_HOST,
        'db' => TAINTINFER_MYSQL_DB,
        'db_user' => TAINTINFER_MYSQL_USER,
        'db_pwd' => TAINTINFER_MYSQL_PASS,
    );
    $mysqli = @new mysqli($mysql_conf['host'], $mysql_conf['db_user'], $mysql_conf['db_pwd']);
    if ($mysqli->connect_errno) {
        die("could not connect to the database:\n" . $mysqli->connect_error);
    }
    $mysqli->query("set names 'utf8';");
    $select_db = $mysqli->select_db($mysql_conf['db']);
    if (!$select_db) {
        die("could not connect to the db:\n" . $mysqli->error);
    }

    $sql = "select Bv1,Bv2 from ssrf_info where param = '$param';";
    $res = $mysqli->query($sql);
    if (!$res) {
        die("sql error:\n" . $mysqli->error);
    }

    while ($row = $res->fetch_assoc()) {
        $Bv1 = $row['Bv1'];
        $Bv2 = $row['Bv2'];
    }

    $res->free();
    if ($Bv1 === NULL) {
        $sql = "UPDATE ssrf_info SET Bv1 = '$Bv' WHERE param = '$param'";
        $res = $mysqli->query($sql);
        if (!$res) {
            die("sql error:\n" . $mysqli->error);
        }
        $mysqli->close();
        return "UPDATE";
    }

    if ($Bv1 !== NULL && $Bv2 === NULL) {
    $sql = "UPDATE ssrf_info SET Bv2 = '$Bv' WHERE param = '$param'";
    $res = $mysqli->query($sql);
    if (!$res) {
        die("sql error:\n" . $mysqli->error);
    }
}

    $sql = "select Bv1,Bv2 from ssrf_info where param = '$param'";
    $res = $mysqli->query($sql);
    if (!$res) {
        die("sql error:\n" . $mysqli->error);
    }

    while ($row = $res->fetch_assoc()) {
        if (count($row) == 1) {
            $Bv1 = $row['Bv1'];
        } elseif (count($row) == 2) {
            $Bv1 = $row['Bv1'];
            $Bv2 = $row['Bv2'];
        } else {
            $Bv1 = NULL;
            $Bv2 = NULL;
        }
    }

    $res->free();

    if ($Bv1 !== NULL && $Bv2 !== NULL) {
        if ($Bv1 === $Bv2) {
            $mysqli->close();
            return "NOVULN";
        }
        $mysqli->close();
        return "VULN";
    }
}


function checkVulnType($vuln_type, $param){
    $mysql_conf = array(
        'host' => TAINTINFER_MYSQL_HOST,
        'db' => TAINTINFER_MYSQL_DB,
        'db_user' => TAINTINFER_MYSQL_USER,
        'db_pwd' => TAINTINFER_MYSQL_PASS,
    );

    $mysqli = @new mysqli($mysql_conf['host'], $mysql_conf['db_user'], $mysql_conf['db_pwd']);
    if ($mysqli->connect_errno) {
        die("could not connect to the database:\n" . $mysqli->connect_error);
    }

    $mysqli->query("set names 'utf8';");
    $select_db = $mysqli->select_db($mysql_conf['db']);
    if (!$select_db) {
        die("could not connect to the db:\n" . $mysqli->error);
    }

    $sql = "select vulntype from ssrf_info where param = '$param';";
    $res = $mysqli->query($sql);
    if (!$res) {
        die("sql error:\n" . $mysqli->error);
    }

    while ($row = $res->fetch_assoc()) {
        if (count($row) >= 1) {
            $vulntype = $row['vulntype'];
        } else {
            $vulntype = NULL;
        }
    }

    taintinfer_log("DB check vulntype:" . $vulntype . "\n");

    $res->free();
    $mysqli->close();
    if (strcmp($vulntype, $vuln_type) == 0) {
        return true;
    }
    return false;
}


function updateVulnType($vuln_type, $param){
    taintinfer_log("Start Update VulnType");
    $mysql_conf = array(
        'host' => TAINTINFER_MYSQL_HOST,
        'db' => TAINTINFER_MYSQL_DB,
        'db_user' => TAINTINFER_MYSQL_USER,
        'db_pwd' => TAINTINFER_MYSQL_PASS,
    );
    $mysqli = @new mysqli($mysql_conf['host'], $mysql_conf['db_user'], $mysql_conf['db_pwd']);
    if ($mysqli->connect_errno) {
        die("could not connect to the database:\n" . $mysqli->connect_error);
    }
    
    $mysqli->query("set names 'utf8';");
    $select_db = $mysqli->select_db($mysql_conf['db']);
    if (!$select_db) {
        die("could not connect to the db:\n" . $mysqli->error);
    }

    $sql_info = "UPDATE ssrf_info SET vulntype = '$vuln_type' WHERE param = '$param';";
    $res = $mysqli->query($sql_info);
    if (!$res) {
        die("sql error:\n" . $mysqli->error);
    }

 
    $check_vuln = "SELECT vulntype FROM ssrf_vuln WHERE id = 1;";
    $res = $mysqli->query($check_vuln);

    if (!$res) {
        die("sql error:\n" . $mysqli->error);
    }

    if ($res->num_rows != 0) {
        $sql_vuln = "UPDATE ssrf_vuln SET vulntype = '$vuln_type', vulnparam = '$param'  WHERE id = 1;";
        $res = $mysqli->query($sql_vuln);
        if (!$res) {
            die("sql error:\n" . $mysqli->error);
        }
    } else {
        $sql_vuln = "INSERT INTO ssrf_vuln (id, vulnparam, vulntype) VALUES (1, '$param','$vuln_type');";
        $res = $mysqli->query($sql_vuln);
        if (!$res) {
            die("sql error:\n" . $mysqli->error);
        }
    }
    
    taintinfer_log("DB update vulntype:" . $param . "\n");

    $mysqli->close();
}

function cleanVulnInfo(){
    $mysql_conf = array(
        'host' => TAINTINFER_MYSQL_HOST,
        'db' => TAINTINFER_MYSQL_DB,
        'db_user' => TAINTINFER_MYSQL_USER,
        'db_pwd' => TAINTINFER_MYSQL_PASS,
    );
    $mysqli = @new mysqli($mysql_conf['host'], $mysql_conf['db_user'], $mysql_conf['db_pwd']);
    if ($mysqli->connect_errno) {
        die("could not connect to the database:\n" . $mysqli->connect_error);
    }
    $mysqli->query("set names 'utf8';");
    $select_db = $mysqli->select_db($mysql_conf['db']);
    if (!$select_db) {
        die("could not connect to the db:\n" . $mysqli->error);
    }

    $clean_sql = "TRUNCATE TABLE ssrf_info;";
    $res = $mysqli->query($clean_sql);
    if (!$res) {
        die("sql error:\n" . $mysqli->error);
    }

    $mysqli->close();
}


function taintinfer_log($content)
{
    $file_put_contents = taintinfer_get_function('file_put_contents');
    $file_put_contents(TAINTINFER_LOG_FILE, $content . "\n", FILE_APPEND);
}


/**
 * Load the file
 * @param $pattern
 */
function taintinfer_load_file($pattern)
{
    $glob = taintinfer_get_function("glob");
    $ksort = taintinfer_get_function("ksort");
    $basename = taintinfer_get_function("basename");

    $file_list = $glob($pattern);

    $result_list = array();
    foreach ($file_list as $absfilename) {
        if (in_array($basename($absfilename), $result_list)) {
            taintinfer_log("error: function " . $basename($absfilename) . " already exists in " . $file_list[$basename($absfilename)]);
            continue;
        }

        $result_list[$basename($absfilename)] = $absfilename;
    }

    $ksort($result_list);
    foreach ($result_list as $filename => $absfilename) { // here to(load the modified code and) hook the original function/class
        $funcname = preg_replace("/\d{3}\-/", "", $filename);
        $funcname = preg_replace("/.php$/", "", $funcname);

        if (!function_exists(TAINTINFER_RENAME_PREFIX . $funcname) && !class_exists(TAINTINFER_RENAME_PREFIX . $funcname)) {
            taintinfer_log("error: function/class " . TAINTINFER_RENAME_PREFIX . $funcname . " not exists");
            continue;
        }

        if (function_exists($funcname) || class_exists($funcname)) {
            taintinfer_log("error: function/class " . $funcname . " already exists");
            continue;
        }

        require($absfilename);
    }
}


/**
 * Load opcode related files
 * @param $pattern
 */
function taintinfer_load_opcode($pattern)
{
    $glob = taintinfer_get_function("glob");
    $ksort = taintinfer_get_function("ksort");
    $basename = taintinfer_get_function("basename");

    $file_list = $glob($pattern);

    $result_list = array();
    foreach ($file_list as $absfilename) {
        $result_list[$basename($absfilename)] = $absfilename;
    }

    $ksort($result_list);
    foreach ($result_list as $filename => $absfilename) {
        require($absfilename);
    }
}


$taintinfer_translate_lang = array(
    "File Inclusion" => "FI",
    "Arbitrary File Access" => "AFA",
    "Server Side Request Forgery" => "SSRF",
);


/**
 * @param $str
 * @return string
 */
function taintinfer_translate($str)
{
    global $taintinfer_translate_lang;
    if (isset($taintinfer_translate_lang[$str])) {
        return $taintinfer_translate_lang[$str];
    } else {
        return $str;
    }
}
