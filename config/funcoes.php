<?php
function gerarSugestaoUsername($nome, $conn) {
    $p = explode(' ', strtolower(trim($nome)));
    $primeiro = preg_replace('/[^a-z]/', '', $p[0]);
    $ultimo = preg_replace('/[^a-z]/', '', end($p));
    
    $base = $primeiro . "." . $ultimo;
    $sug = $base; 
    $i = 2;
    
    while(true){
        $res = $conn->query("SELECT id FROM pre_registros WHERE username_criado = '$sug'");
        if($res->num_rows == 0) {
            return $sug;
        }
        $sug = $base . $i; 
        $i++;
    }
}
?>
