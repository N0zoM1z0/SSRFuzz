<?php

$TAINTINFER_FUZZER_DSN = getenv("TAINTINFER_FUZZER_DSN");
$TAINTINFER_SENTRY_DSN = getenv("TAINTINFER_SENTRY_DSN");
$TAINTINFER_TAINT_ENABLE = getenv("TAINTINFER_TAINT_ENABLE");
$TAINTINFER_TANZI = getenv("TAINTINFER_TANZI");
$TAINTINFER_LOG_FILE = getenv("TAINTINFER_LOG_FILE");

$config_file = '/home/zero/Desktop/SSRFuzz/src/Config.php';

$content = file_get_contents($config_file);

if ($TAINTINFER_FUZZER_DSN)
    $content = str_replace('define("TAINTINFER_FUZZER_DSN", "")',
        'define("TAINTINFER_FUZZER_DSN", "'.addslashes($TAINTINFER_FUZZER_DSN).'")', $content);

if ($TAINTINFER_SENTRY_DSN)
    $content = str_replace('define("TAINTINFER_SENTRY_DSN", "")',
        'define("TAINTINFER_SENTRY_DSN", "'.addslashes($TAINTINFER_SENTRY_DSN).'")', $content);

if ($TAINTINFER_TAINT_ENABLE)
    $content = str_replace('define("TAINTINFER_TAINT_ENABLE", true)',
        'define("TAINTINFER_TAINT_ENABLE", '.$TAINTINFER_TAINT_ENABLE.')', $content);

if ($TAINTINFER_TANZI)
    $content = str_replace('define("TAINTINFER_TANZI", "xtanzi")',
        'define("TAINTINFER_TANZI", "'.addslashes($TAINTINFER_TANZI).'")', $content);

if ($TAINTINFER_LOG_FILE)
    $content = str_replace('define("TAINTINFER_LOG_FILE", "/tmp/taintinfer.log")',
        'define("TAINTINFER_LOG_FILE", "'.addslashes($TAINTINFER_LOG_FILE).'")', $content);

file_put_contents($config_file, $content);

system("apache2-foreground");