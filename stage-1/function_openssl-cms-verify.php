$web3_1 = 'signed.cms';
$web3_2 = 0;
$web3_3 = null;
$web3_4 = [];
$web3_5 = null;
$web3_6 = null;
$web3_7 = null;
$web3_8 = null;
$web3_9 = OPENSSL_ENCODING_SMIME;

$web3_result = openssl_cms_verify(
    $web3_1,
    $web3_2,
    $web3_3,
    $web3_4,
    $web3_5,
    $web3_6,
    $web3_7,
    $web3_8,
    $web3_9
);

echo $web3_result ? 'Verification successful' : 'Verification failed';