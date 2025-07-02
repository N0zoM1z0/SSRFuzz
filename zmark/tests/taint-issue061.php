<?php

function substr(...$args) {
    return call_user_func_array("my_substr", $args);
}

function trim(...$args) {
    return call_user_func_array("my_trim", $args);
}

function rtrim(...$args) {
    return call_user_func_array("my_rtrim", $args);
}

function ltrim(...$args) {
    return call_user_func_array("my_ltrim", $args);
}

function implode(...$args) {
    return call_user_func_array("my_implode", $args);
}


var_dump(substr('abc', 0, 2));
var_dump(trim('abc', 'c'));
var_dump(rtrim('abc', 'c'));
var_dump(ltrim('abc', 'c'));
var_dump(implode(array('a', 'c'), 'b'));
?>
