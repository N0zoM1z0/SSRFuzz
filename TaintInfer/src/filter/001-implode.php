<?php


function implode($glue, $pieces=NULL) {
    $result = call_user_func(TAINTINFER_RENAME_PREFIX."implode", $glue, $pieces);

    if (TAINTINFER_TAINT_ENABLE) {
        if (taintinfer_zcheck($glue)) {
            taintinfer_zmark($result);
        } else if (taintinfer_zcheck($pieces)) {
            taintinfer_zmark($result);
        }
    }

    return $result;
}
