<?php


function hex2bin($data) {
    $result = call_user_func(TAINTINFER_RENAME_PREFIX."hex2bin", $data);
    if (TAINTINFER_TAINT_ENABLE && taintinfer_zcheck($data)) {
        taintinfer_zmark($result);
    }

    return $result;
}
