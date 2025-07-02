<?php


function taintinfer_assign_concat_handler($param1, $param2) {
    $result = $param1.$param2;

    if (taintinfer_zcheck($param1) || taintinfer_zcheck($param2)) {
        taintinfer_zmark($result);
    }

    return $result;
}


if (TAINTINFER_TAINT_ENABLE)
    zregister_opcode_callback(ZMARK_ASSIGN_CONCAT, 'taintinfer_assign_concat_handler');
