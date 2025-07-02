<?php


function urldecode($str) {
    $result = call_user_func(TAINTINFER_RENAME_PREFIX."urldecode", $str);
    if (TAINTINFER_TAINT_ENABLE && taintinfer_zcheck($str)) {
        taintinfer_zmark($result);
    }

    return $result;
}