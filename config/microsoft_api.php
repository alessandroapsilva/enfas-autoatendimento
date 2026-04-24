<?php
require_once 'microsoft_config.php';
class MicrosoftGraph {
    private function getAccessToken() {
        $url = "https://login.microsoftonline.com/" . MS_TENANT_ID . "/oauth2/v2.0/token";
        $data = ['client_id'=>MS_CLIENT_ID, 'client_secret'=>MS_CLIENT_SECRET, 'scope'=>'https://graph.microsoft.com/.default', 'grant_type'=>'client_credentials'];
        $ch = curl_init($url); curl_setopt($ch, CURLOPT_RETURNTRANSFER, true); curl_setopt($ch, CURLOPT_POSTFIELDS, http_build_query($data));
        $res = json_decode(curl_exec($ch), true); curl_close($ch);
        return $res['access_token'] ?? null;
    }

    public function gerenciarConta($upn, $status) {
        $token = $this->getAccessToken(); if(!$token) return false;
        $enabled = ($status == 'ativo') ? true : false;
        $url = "https://graph.microsoft.com/v1.0/users/" . $upn;
        $payload = json_encode(["accountEnabled" => $enabled]);
        $ch = curl_init($url);
        curl_setopt($ch, CURLOPT_CUSTOMREQUEST, "PATCH");
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($ch, CURLOPT_POSTFIELDS, $payload);
        curl_setopt($ch, CURLOPT_HTTPHEADER, ["Authorization: Bearer $token", "Content-Type: application/json"]);
        $code = curl_getinfo($ch, CURLINFO_HTTP_CODE); curl_exec($ch); curl_close($ch);
        return ($code == 204 || $code == 200);
    }

    public function criarUsuario($username, $nome, $senha) {
        $token = $this->getAccessToken(); if(!$token) return false;
        $url = "https://graph.microsoft.com/v1.0/users";
        $payload = json_encode([
            "accountEnabled" => true, "displayName" => $nome, "mailNickname" => $username,
            "userPrincipalName" => $username . "@enfas.com.br",
            "passwordProfile" => ["forceChangePasswordNextSignIn" => true, "password" => $senha]
        ]);
        $ch = curl_init($url); curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($ch, CURLOPT_HTTPHEADER, ["Authorization: Bearer $token", "Content-Type: application/json"]);
        curl_setopt($ch, CURLOPT_POST, true); curl_setopt($ch, CURLOPT_POSTFIELDS, $payload);
        $res = curl_exec($ch); $code = curl_getinfo($ch, CURLINFO_HTTP_CODE); curl_close($ch);
        return ($code == 201);
    }
}
?>
