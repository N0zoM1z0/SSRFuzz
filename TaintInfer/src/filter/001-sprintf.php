<?php


function sprintf($format, ...$args) {
    $result = call_user_func(TAINTINFER_RENAME_PREFIX."sprintf", $format, ...$args);

    if (TAINTINFER_TAINT_ENABLE) {
        if (taintinfer_zcheck($format)) {
            taintinfer_zmark($result);
        } else {
            foreach ($args as &$arg) {
                if (taintinfer_zcheck($arg)) {
                    taintinfer_zmark($result);
                    break;
                }
            }
        }
    }

    return $result;
}