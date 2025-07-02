$web3_connect_string = "host=localhost port=5432 user=web3_user password=web3_pass dbname=web3_db options='--client_encoding=UTF8'";
$web3_1 = pg_connect($web3_connect_string, PGSQL_CONNECT_ASYNC);
$web3_result = pg_connect_poll($web3_1);
echo $web3_result;