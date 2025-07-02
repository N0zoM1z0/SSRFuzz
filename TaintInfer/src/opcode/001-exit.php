<?php


function taintinfer_exit_handler($string) {
}

zregister_opcode_callback(ZMARK_EXIT, "taintinfer_exit_handler");
