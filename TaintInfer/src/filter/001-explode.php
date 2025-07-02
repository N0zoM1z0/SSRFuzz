<?php


function explode($delimiter, $string, ...$args) {
    $result = call_user_func(TAINTINFER_RENAME_PREFIX."explode", $delimiter, $string, ...$args);
    if (TAINTINFER_TAINT_ENABLE && taintinfer_zcheck($string)) {
        taintinfer_zmark($result);
    }

    return $result;
}
