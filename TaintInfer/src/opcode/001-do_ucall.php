<?php


function taintinfer_do_ucall($call, $params) {
    taintinfer_check_callback($call, $params, taintinfer_translate("Remote Code Execute"));
}


zregister_opcode_callback(ZMARK_DO_UCALL, 'taintinfer_do_ucall');
