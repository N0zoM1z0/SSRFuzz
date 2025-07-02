$web3_1 = fopen('php://temp', 'r+');
$web3_2 = 1;
$web3_3 = dbase_delete_record($web3_1, $web3_2);
var_dump($web3_3);