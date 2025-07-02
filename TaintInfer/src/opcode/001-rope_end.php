<?php


function taintinfer_rope_end_handler($params) {
    $result = implode($params);
    if (taintinfer_zcheck($params)) {
        taintinfer_zmark($result);
    }
    return $result;
}


if (TAINTINFER_TAINT_ENABLE)
    zregister_opcode_callback(ZMARK_ROPE_END, 'taintinfer_rope_end_handler');