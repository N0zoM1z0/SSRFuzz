<?php

define("TAINTINFER_FUZZER_DSN", "http://admin:password@127.0.0.1:9191/fuzz");
define("TAINTINFER_SSRF_FUZZER_DSN", "http://admin:password@127.0.0.1:9191/ssrf");
define("TAINTINFER_SENTRY_DSN", "");
define("TAINTINFER_TAINT_ENABLE", true);
define("TAINTINFER_TANZI", "xtanzi");
define("TAINTINFER_LOG_FILE", "/tmp/taintinfer.log");
define("TAINTINFER_MYSQL_HOST", "ssrf_db");
define("TAINTINFER_MYSQL_USER", "root");
define("TAINTINFER_MYSQL_PASS", "123456");
define("TAINTINFER_MYSQL_DB", "sql_test");