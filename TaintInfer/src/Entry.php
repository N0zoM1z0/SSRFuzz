<?php

if (!extension_loaded('zmark')) {
    trigger_error("zmark not installed", E_USER_WARNING);
    return;
}

define("TAINTINFER_RENAME_PREFIX", "taintinfer_");

$taintinfer_sentry_client = null;
$fuzz_param = null;
$vuln_stack = null;

// taintinfer_log("prober start:"."\n");
// taintinfer_log("TAINTINFER_IS_FUZZER_REQUEST in SERVER?:".in_array("hello_from_fuzzer", $_SERVER)."\n");
// taintinfer_log("TAINTINFER_IS_VULN_TYPE_FUZZER_REQUEST in SERVER?:".in_array("type_vuln_fuzzer", $_SERVER)."\n");

//if (isset($_SERVER['HTTP_TAINTINFER_FUZZER'])) {
if (in_array("hello_from_fuzzer", $_SERVER)) {
    define("TAINTINFER_IS_FUZZER_REQUEST", true);
} else {
    define("TAINTINFER_IS_FUZZER_REQUEST", false);
}

//if (isset($_SERVER['HTTP_TAINTINFER_FUZZER'])) {
if (in_array("type_vuln_fuzzer", $_SERVER)) {
    define("TAINTINFER_IS_VULN_TYPE_FUZZER_REQUEST", true);
} else {
    define("TAINTINFER_IS_VULN_TYPE_FUZZER_REQUEST", false);
}

//$file_put_contents = taintinfer_get_function("file_put_contents");
// $file_put_contents("/tmp/1.txt","prober start:".$_SERVER['HTTP_X_SENTRY_AUTH']."\n",FILE_APPEND);
if (isset($_SERVER['HTTP_X_SENTRY_AUTH'])) {
    define("TAINTINFER_IS_SENTRY_REQUEST", true);
} else {
    define("TAINTINFER_IS_SENTRY_REQUEST", false);
}


function taintinfer_get_function($funcname)
{
    if (function_exists(TAINTINFER_RENAME_PREFIX . $funcname)) {
        return TAINTINFER_RENAME_PREFIX . $funcname;
    } else if (function_exists($funcname)) {
        return $funcname;
    } else {
        exit("error: function " . $funcname . " does not exists");
    }
}


$taintinfer_dirname = taintinfer_get_function("dirname");
define('TAINTINFER_ABSPATH', $taintinfer_dirname(__FILE__) . '/');
require(TAINTINFER_ABSPATH . "Config.php");
require(TAINTINFER_ABSPATH . "Utils.php");

// Global variable, directly associated with Fuzzer's DSN
$taintinfer_vuln_type = "FUZZ";

// mark input variables
taintinfer_zmark_once($_GET, '$_GET', true);
taintinfer_zmark_once($_POST, '$_POST', true);
//taintinfer_zmark_once($_COOKIE, '$_COOKIE',true);
//taintinfer_zmark_once($_REQUEST, '$_REQUEST',true);

// For the time being, zmark only supports arrays, which can be supported later.
//foreach ($_SERVER as $key => &$value) {
//    if (stripos($key, 'HTTP_') === 0) {
//        taintinfer_zmark_once($value);
//    }
//}


// 1. Load sink
taintinfer_load_file(TAINTINFER_ABSPATH . "sink/*/*.php");

// 2. Load filter
taintinfer_load_file(TAINTINFER_ABSPATH . "filter/*.php");

// 3. Load opcode
taintinfer_load_opcode(TAINTINFER_ABSPATH . "opcode/*.php");


// delay require
require(TAINTINFER_ABSPATH . "../vendor/autoload.php");
require(TAINTINFER_ABSPATH . "Client.php");

if (!TAINTINFER_IS_SENTRY_REQUEST) {
    $taintinfer_sentry_client = new TAINTINFER_Sentry_Client(TAINTINFER_SENTRY_DSN);
}

function check_vulnable()
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

    $sql = "select vulnable from check_info where id = 1;";
    $res = $mysqli->query($sql);
    if (!$res) {
        die("sql error:\n" . $mysqli->error);
    }

    while ($row = $res->fetch_assoc()) {
//        var_dump("array?",$row);
        if (count($row) >= 1) {
            $vulnable = $row['vulnable'];
        } else {
            $vulnable = NULL;
        }
    }

    // taintinfer_log("check_vulnable:" . $vulnable . "\n");

    $res->free();
    $mysqli->close();
    if ($vulnable == 1) {
        return true;
    }
    return false;
}

function save_stack($stack)
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

    $stack_serialize = serialize($stack);

    $sql_info = "UPDATE check_info SET stack = '$stack_serialize' WHERE id = 1;";
    $res = $mysqli->query($sql_info);
    if (!$res) {
        die("sql error:\n" . $mysqli->error);
    }

    $mysqli->close();
}

function get_stack()
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

    $sql = "select stack from check_info where id = 1;";
    $res = $mysqli->query($sql);
    if (!$res) {
        die("sql error:\n" . $mysqli->error);
    }

    while ($row = $res->fetch_assoc()) {
//        var_dump("array?",$row);
        if (count($row) >= 1) {
            $stack = $row['stack'];
        } else {
            $stack = NULL;
        }
    }

   taintinfer_log("save_stack:" . $stack . "\n");

    $res->free();
    $mysqli->close();
    if (!is_null($stack)) {
        return unserialize($stack);
    }
    return false;
}


function taintinfer_shutdown_capture_request()
{
    global $taintinfer_vuln_type;
    global $vuln_stack;
    global $taintinfer_sentry_client;
    taintinfer_log("SSRFuzz Find VulnType: ".$taintinfer_vuln_type);
    
    switch ($taintinfer_vuln_type) {
        case  "SSRF":
            taintinfer_log("SSRF Fuzz Start" . "\n");
            if (TAINTINFER_SSRF_FUZZER_DSN && !TAINTINFER_IS_SENTRY_REQUEST) {
                $taintinfer_fuzzer_client = new TAINTINFER_Fuzzer_Client(TAINTINFER_SSRF_FUZZER_DSN);
                $taintinfer_fuzzer_client->captureRequest();
            }
            break;
        default:
            taintinfer_log("TAINTINFER_IS_FUZZER_REQUEST:" .TAINTINFER_IS_FUZZER_REQUEST. "\n");
            taintinfer_log("TAINTINFER_IS_VULN_TYPE_FUZZER_REQUEST:" .TAINTINFER_IS_VULN_TYPE_FUZZER_REQUEST. "\n");
            if (TAINTINFER_FUZZER_DSN && !TAINTINFER_IS_FUZZER_REQUEST && !TAINTINFER_IS_SENTRY_REQUEST && !TAINTINFER_IS_VULN_TYPE_FUZZER_REQUEST) {
                $taintinfer_fuzzer_client = new TAINTINFER_Fuzzer_Client(TAINTINFER_FUZZER_DSN);
                $taintinfer_fuzzer_client->captureRequest();
            }
    }

    $vulncheck = 0;
    if (TAINTINFER_IS_VULN_TYPE_FUZZER_REQUEST) {
        $vulncheck = check_vulnable();
    }


    if (!is_null($vuln_stack)) {
        save_stack($vuln_stack);
    }

//    taintinfer_file_put_contents("/tmp/1.txt","vuln_stack:".$vuln_stack."\n",FILE_APPEND);
//    taintinfer_file_put_contents("/tmp/1.txt","taintinfer_sentry_client:".is_null($taintinfer_sentry_client)."\n",FILE_APPEND);
    if (!is_null($taintinfer_sentry_client) && $vulncheck) {
        $vuln_stack = get_stack();
//        taintinfer_file_put_contents("/tmp/1.txt", "vuln_stack:" . $vuln_stack . "\n", FILE_APPEND);
//        taintinfer_file_put_contents("/tmp/1.txt", "send message" . "\n", FILE_APPEND);
        $message = taintinfer_translate("Server Side Request Forgery");
        $taintinfer_sentry_client->captureVuln($message, "error", $vuln_stack);
    }

    // It must be reset to the FUZZ interface after execution so that the next packet will also enter the fuzz process
    $taintinfer_vuln_type = "FUZZ";
}

register_shutdown_function('taintinfer_shutdown_capture_request');

