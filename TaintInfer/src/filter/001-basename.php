<?php


function basename($path, ...$args) {
    $result = call_user_func(TAINTINFER_RENAME_PREFIX."basename", $path, ...$args);
    if (TAINTINFER_TAINT_ENABLE && taintinfer_zcheck($path)) {
        taintinfer_zmark($result);
    }

    return $result;
}
