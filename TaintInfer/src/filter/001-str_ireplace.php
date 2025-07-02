<?php


function str_ireplace($search, $replace, $subject, ...$args) {
    $result = call_user_func(TAINTINFER_RENAME_PREFIX."str_ireplace", $search, $replace, $subject, ...$args);

    if (TAINTINFER_TAINT_ENABLE) {
        if (taintinfer_zcheck($replace)) {
            taintinfer_zmark($result);
        } elseif (taintinfer_zcheck($subject)) {
            taintinfer_zmark($result);
        }
    }

    return $result;
}
