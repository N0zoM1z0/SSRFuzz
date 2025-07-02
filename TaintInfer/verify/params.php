<?php
$url = $_GET['url'];
$nnn = $_GET['nnn'];
$result = file_get_contents($url);
echo $nnn;
?>