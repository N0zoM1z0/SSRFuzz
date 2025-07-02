<?php


function taintinfer_include_or_eval_handler($param) {
    global $taintinfer_sentry_client;

    $reported = false;

    if (stripos($param,  TAINTINFER_TANZI) !== false) {
        $backtrace = debug_backtrace(DEBUG_BACKTRACE_IGNORE_ARGS, 2);
        if ($backtrace[1]['function'] == 'eval') {
            $taintinfer_sentry_client->captureVuln(taintinfer_translate("Remote Code Execute"));
            $reported = true;
        } elseif (stripos($param, "../". TAINTINFER_TANZI) !== false || stripos($param, "..\\". TAINTINFER_TANZI) !== false) {
            $taintinfer_sentry_client->captureVuln(taintinfer_translate("Remote Code Execute"));
            $reported = true;
        }
    }

    if (TAINTINFER_TAINT_ENABLE && !$reported && taintinfer_zcheck($param)) {
        $taintinfer_sentry_client->captureVuln(taintinfer_translate("Remote Code Execute"), "debug");
    }
}

zregister_opcode_callback(ZMARK_INCLUDE_OR_EVAL, "taintinfer_include_or_eval_handler");
