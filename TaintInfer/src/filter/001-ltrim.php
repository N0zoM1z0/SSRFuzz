<?php


function ltrim($str, ...$args) {
    $result = call_user_func(TAINTINFER_RENAME_PREFIX."ltrim", $str, ...$args);
    if (TAINTINFER_TAINT_ENABLE && taintinfer_zcheck($str)) {
        taintinfer_zmark($result);
    }

    return $result;
}