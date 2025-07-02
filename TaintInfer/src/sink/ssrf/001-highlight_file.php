<?php


function highlight_file($filename, ...$args) {
    taintinfer_check_ssrf($filename, taintinfer_translate("Server Side Request Forgery"));
    return call_user_func(TAINTINFER_RENAME_PREFIX."highlight_file", $filename, ...$args);
}