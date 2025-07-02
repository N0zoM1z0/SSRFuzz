<?php


function file_get_contents($filename, ...$args) {
    taintinfer_log("start check file_get_contents");
    taintinfer_check_ssrf($filename, taintinfer_translate("Server Side Request Forgery"));
    return call_user_func(TAINTINFER_RENAME_PREFIX."file_get_contents", $filename, ...$args);
}
