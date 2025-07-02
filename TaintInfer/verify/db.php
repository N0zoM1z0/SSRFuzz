<?php

    $mysql_conf = array(
        'host' => TAINTINFER_MYSQL_HOST,
        'db' => TAINTINFER_MYSQL_DB,
        'db_user' => TAINTINFER_MYSQL_USER,
        'db_pwd' => TAINTINFER_MYSQL_PASS,
    );
    var_dump($mysql_conf);
    
    $mysqli = @new mysqli($mysql_conf['host'], $mysql_conf['db_user'], $mysql_conf['db_pwd']);
    if ($mysqli->connect_errno) {
        die("could not connect to the database:\n" . $mysqli->connect_error);
    }
    
    $mysqli->query("set names 'utf8';");
    $select_db = $mysqli->select_db($mysql_conf['db']);
    if (!$select_db) {
        die("could not connect to the db:\n" . $mysqli->error);
    }


    $check_vuln = "SELECT vulntype FROM ssrf_vuln WHERE id = 1;";
    $res = $mysqli->query($check_vuln);

    if (!$res) {
        die("sql error:\n" . $mysqli->error);
    }


    $mysqli->close();
?>