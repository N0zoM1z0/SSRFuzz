<?php


function taintinfer_init_user_call_handler($funcname) {
    taintinfer_check_dynamic_call($funcname, taintinfer_translate("Remote Code Execute"));
}


zregister_opcode_callback(ZMARK_INIT_USER_CALL, 'taintinfer_init_user_call_handler');
