<?php


function taintinfer_do_icall($call, $params) {
    taintinfer_check_callback($call, $params, taintinfer_translate("Remote Code Execute"));
}


zregister_opcode_callback(ZMARK_DO_ICALL, 'taintinfer_do_icall');
