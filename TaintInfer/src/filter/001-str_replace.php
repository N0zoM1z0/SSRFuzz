<?php


function str_replace($search, $replace, $subject, &$count=NULL) {
    // reference params
    $result = call_user_func_array(TAINTINFER_RENAME_PREFIX."str_replace", array($search, $replace, $subject, &$count));

    if (TAINTINFER_TAINT_ENABLE) {
        if (taintinfer_zcheck($replace)) {
            taintinfer_zmark($result);
        } elseif (taintinfer_zcheck($subject)) {
            taintinfer_zmark($result);
        }
    }

    return $result;
}
