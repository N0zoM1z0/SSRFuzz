<?php


function taintinfer_echo_handler($string) {
}

zregister_opcode_callback(ZMARK_ECHO, "taintinfer_echo_handler");

