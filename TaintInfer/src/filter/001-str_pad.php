<?php

function str_pad($input, ...$args) {
    $result = call_user_func(TAINTINFER_RENAME_PREFIX."str_pad", $input, ...$args);
    if (TAINTINFER_TAINT_ENABLE && taintinfer_zcheck($input)) {
        taintinfer_zmark($result);
    }

    return $result;
}

