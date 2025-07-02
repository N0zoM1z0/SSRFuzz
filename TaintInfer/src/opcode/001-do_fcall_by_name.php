<?php


function taintinfer_do_fcall_by_name($call, $params) {
    taintinfer_check_callback($call, $params, taintinfer_translate("Remote Code Execute"));
}


zregister_opcode_callback(ZMARK_DO_FCALL_BY_NAME, 'taintinfer_do_fcall_by_name');
