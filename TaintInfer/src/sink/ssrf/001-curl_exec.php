<?php
function curl_exec($ch) {
    // $url not marked.
    $url = curl_getinfo($ch, CURLINFO_EFFECTIVE_URL);
    taintinfer_check_ssrf($url, taintinfer_translate("Server Side Request Forgery"));
    return call_user_func(TAINTINFER_RENAME_PREFIX."curl_exec", $ch);
}