<?php
ini_set('display_errors', 1);
error_reporting(E_ALL);
require_once '../config/database.php';
require_once '../config/microsoft_api.php';

if ($_POST) {
    $id = (int)$_POST['id'];
    $username = $_POST['username'];
    $senha = $_POST['senha'];
    
    $res = $conn->query("SELECT nome_completo FROM pre_registros WHERE id = $id")->fetch_assoc();
    $nome = $res['nome_completo'];

    $ms = new MicrosoftGraph();
    
    // Agora capturamos a resposta bruta da Microsoft para diagnostico
    $url = "https://login.microsoftonline.com/" . MS_TENANT_ID . "/oauth2/v2.0/token";
    $data = ['client_id' => MS_CLIENT_ID, 'client_secret' => MS_CLIENT_SECRET, 'scope' => 'https://graph.microsoft.com/.default', 'grant_type' => 'client_credentials'];
    $ch = curl_init($url);
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    curl_setopt($ch, CURLOPT_POSTFIELDS, http_build_query($data));
    $tokenRes = json_decode(curl_exec($ch), true);
    curl_close($ch);

    if (!isset($tokenRes['access_token'])) {
        die("<h1>Erro de Autenticacao</h1><p>A Microsoft nao aceitou seu Client ID ou Secret. Verifique se copiou o valor correto (e nao o ID do Secret).</p><pre>".print_r($tokenRes,true)."</pre>");
    }

    $token = $tokenRes['access_token'];
    $url = "https://graph.microsoft.com/v1.0/users";
    $payload = ["accountEnabled" => true, "displayName" => $nome, "mailNickname" => $username, "userPrincipalName" => $username . "@enfas.com.br", "passwordProfile" => ["forceChangePasswordNextSignIn" => true, "password" => $senha]];

    $ch = curl_init($url);
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    curl_setopt($ch, CURLOPT_HTTPHEADER, ["Authorization: Bearer $token", "Content-Type: application/json"]);
    curl_setopt($ch, CURLOPT_POST, true);
    curl_setopt($ch, CURLOPT_POSTFIELDS, json_encode($payload));
    $response = curl_exec($ch);
    $code = curl_getinfo($ch, CURLINFO_HTTP_CODE);
    curl_close($ch);

    if ($code == 201) {
        $conn->query("UPDATE pre_registros SET status = 'ativo', username_criado = '$username' WHERE id = $id");
        echo "<h1>Sucesso! Usuario criado.</h1>";
    } else {
        echo "<h1>Erro da Microsoft (Codigo $code)</h1>";
        echo "<p>A API respondeu o seguinte:</p>";
        echo "<pre style='background:#000; color:#0f0; padding:20px;'>" . print_r(json_decode($response, true), true) . "</pre>";
        echo "<a href='index.php'>Voltar e tentar novamente</a>";
    }
}
?>
