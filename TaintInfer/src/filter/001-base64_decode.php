<?php


function base64_decode($data, ...$args) {
    $result = call_user_func(TAINTINFER_RENAME_PREFIX."base64_decode", $data, ...$args);
    if (TAINTINFER_TAINT_ENABLE && taintinfer_zcheck($data)) {
        taintinfer_zmark($result);
    }

    return $result;
}
