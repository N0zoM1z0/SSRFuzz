<?php


function pathinfo($path, $options=PATHINFO_DIRNAME|PATHINFO_BASENAME|PATHINFO_EXTENSION|PATHINFO_FILENAME) {
    $result = call_user_func(TAINTINFER_RENAME_PREFIX."pathinfo", $path, $options);
    if (TAINTINFER_TAINT_ENABLE && taintinfer_zcheck($path)) {
        taintinfer_zmark($result);
    }

    return $result;
}