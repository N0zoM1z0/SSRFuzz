<?php


function dirname($path, ...$args) {
    $result = call_user_func(TAINTINFER_RENAME_PREFIX."dirname", $path, ...$args);
    if (TAINTINFER_TAINT_ENABLE && taintinfer_zcheck($path)) {
        taintinfer_zmark($result);
    }

    return $result;
}
