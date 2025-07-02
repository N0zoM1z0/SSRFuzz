<?php


function json_decode($string, ...$args) {
    $result = call_user_func(TAINTINFER_RENAME_PREFIX."json_decode", $string, ...$args);
    if (TAINTINFER_TAINT_ENABLE && taintinfer_zcheck($string)) {
        taintinfer_zmark($result);
    }

    return $result;
}