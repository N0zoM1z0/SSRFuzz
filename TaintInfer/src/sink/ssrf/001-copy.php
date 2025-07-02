<?php


function copy($source, $dest, ...$args) {
    taintinfer_check_ssrf($source, taintinfer_translate("Server Side Request Forgery"));
    taintinfer_check_ssrf($dest, taintinfer_translate("Server Side Request Forgery"));
    return call_user_func(TAINTINFER_RENAME_PREFIX."copy", $source, $dest, ...$args);
}