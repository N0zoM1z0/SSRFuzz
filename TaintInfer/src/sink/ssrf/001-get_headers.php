<?php

function get_headers($url, ...$args) {
    taintinfer_check_ssrf($url, taintinfer_translate("Server Side Request Forgery"));
    return call_user_func(TAINTINFER_RENAME_PREFIX."get_headers", $url, ...$args);
}