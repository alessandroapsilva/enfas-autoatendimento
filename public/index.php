<?php
ob_start();
session_start();
date_default_timezone_set('America/Sao_Paulo');
ini_set('display_errors', 0); 
error_reporting(0);

// FORÇA O UTF-8
header('Content-Type: text/html; charset=utf-8');
header("Cache-Control: no-store, no-cache, must-revalidate, max-age=0");

require_once '../config/database.php';
$conn->query("SET time_zone = '-03:00'");
$conn->query("SET NAMES 'utf8'");
$conn->query("SET CHARACTER SET utf8");

$check_col_tok = $conn->query("SHOW COLUMNS FROM pre_registros LIKE 'token_recuperacao'");
if($check_col_tok && $check_col_tok->num_rows == 0) { 
    $conn->query("ALTER TABLE pre_registros ADD COLUMN token_recuperacao VARCHAR(255) NULL"); 
}

$uri = (string) parse_url($_SERVER['REQUEST_URI'] ?? '', PHP_URL_PATH); 
$m = 'home';
if (strpos($uri, '/Conta/Login') !== false) { $m = 'home'; } 
elseif (strpos($uri, '/Conta/Logout') !== false) { $m = 'logout'; } 
elseif (strpos($uri, '/User/ResetPassword') !== false) { $m = 'recuperar'; } 
elseif (strpos($uri, '/User/Validate') !== false) { $m = 'validar_codigo'; } 
elseif (strpos($uri, '/User/NewPassword') !== false) { $m = 'nova_senha'; } 
elseif (strpos($uri, '/User/NewUser') !== false) { $m = 'wizard'; } 
elseif (strpos($uri, '/Conta/Termos') !== false) { $m = 'termo'; } 
elseif (strpos($uri, '/Conta/Manual') !== false) { $m = 'manual'; } 
elseif (strpos($uri, '/Conta/Perfil') !== false) { $m = 'perfil'; } 

if(isset($_GET['code']) && $m == 'validar_codigo') {
    $code = $conn->real_escape_string(trim($_GET['code']));
    $q_tok = $conn->query("SELECT id, username_criado FROM pre_registros WHERE token_recuperacao='$code' AND token_recuperacao IS NOT NULL");
    $res = $q_tok ? $q_tok->fetch_assoc() : null;
    
    if($res) {
        $_SESSION['tmp_recupera'] = ['id' => $res['id'], 'usr' => $res['username_criado']];
        header("Location: /User/NewPassword"); exit;
    } else {
        $erro = "Link de recuperação inválido ou já utilizado.";
    }
}

if($m == 'logout' || isset($_GET['logout'])){ 
    $_SESSION = array(); session_destroy(); header("Location: /Conta/Login"); exit; 
}
if(!isset($_SESSION['colab']) && in_array($m, ['perfil', 'termo'])) { 
    header("Location: /Conta/Login"); exit; 
}

$etapa = $_SESSION['etapa'] ?? 1; 
$erro = $erro ?? ""; $msg_perfil = ""; $erro_perfil = "";

function registrarErro($conn, $modulo, $mensagem) {
    $stmt = $conn->prepare("INSERT INTO logs_erros (modulo, mensagem) VALUES (?, ?)");
    $stmt->bind_param("ss", $modulo, $mensagem); $stmt->execute();
}

function enviarEmailSMTP($conn, $to, $subject, $message) {
    try {
        $cfg = []; 
        $q_cfg = $conn->query("SELECT chave, valor FROM configuracoes WHERE chave IN ('smtp_host','smtp_port','smtp_user','smtp_pass','mail_from')"); 
        if($q_cfg) { while($row = $q_cfg->fetch_assoc()) { $cfg[$row['chave']] = trim($row['valor']); } }
        if(empty($cfg['smtp_host']) || empty($cfg['smtp_user'])) return false;

        $host = $cfg['smtp_host']; $port = (int)($cfg['smtp_port'] ?: 587); 
        $user = $cfg['smtp_user']; $pass = $cfg['smtp_pass']; $from = !empty($cfg['mail_from']) ? $cfg['mail_from'] : $user;

        $context = stream_context_create(['ssl' => [ 'verify_peer' => false, 'verify_peer_name' => false, 'allow_self_signed' => true ]]);
        $socket = @stream_socket_client(($port == 465 ? "ssl://" : "tcp://") . $host . ":" . $port, $errno, $errstr, 15, STREAM_CLIENT_CONNECT, $context);
        if (!$socket) return false;
        stream_set_timeout($socket, 15);

        $read_res = function($sock) { $data = ''; while($str = @fgets($sock, 515)) { $data .= $str; if(substr($str, 3, 1) == ' ') break; } return $data; };
        $read_res($socket); fwrite($socket, "EHLO $host\r\n"); $read_res($socket);
        if($port == 587 || $port == 25) { 
            fwrite($socket, "STARTTLS\r\n"); $read_res($socket); 
            @stream_socket_enable_crypto($socket, true, STREAM_CRYPTO_METHOD_TLS_CLIENT); 
            fwrite($socket, "EHLO $host\r\n"); $read_res($socket); 
        }
        fwrite($socket, "AUTH LOGIN\r\n"); $read_res($socket); fwrite($socket, base64_encode($user)."\r\n"); $read_res($socket); fwrite($socket, base64_encode($pass)."\r\n"); $auth = $read_res($socket);
        if(strpos($auth, '235') === false) return false;

        fwrite($socket, "MAIL FROM: <$from>\r\n"); $read_res($socket); fwrite($socket, "RCPT TO: <$to>\r\n"); $read_res($socket); fwrite($socket, "DATA\r\n"); $read_res($socket);
        $headers = "Date: ".date("r")."\r\nFrom: =?UTF-8?B?".base64_encode("Clínica ENFAS")."?= <$from>\r\nTo: <$to>\r\nSubject: =?UTF-8?B?".base64_encode($subject)."?=\r\nMIME-Version: 1.0\r\nContent-Type: text/html; charset=UTF-8\r\n\r\n";
        fwrite($socket, $headers . $message . "\r\n.\r\n"); $last_res = $read_res($socket);
        fwrite($socket, "QUIT\r\n"); fclose($socket);
        if(strpos($last_res, '250') === false) return false; return true;
    } catch (Exception $e) { return false; }
}

function gerenciarAcessoM365_Wizard($conn, $email_m365, $acao = 'criar', $nova_senha = null, $dados_sync = []) { 
    $cfg = []; $q_cfg = $conn->query("SELECT chave, valor FROM configuracoes"); 
    if($q_cfg) { while($row = $q_cfg->fetch_assoc()) { $cfg[$row['chave']] = trim($row['valor']); } }
    if(empty($cfg['m365_tenant'])) return ['sucesso'=>false]; 
    
    $ch = curl_init("https://login.microsoftonline.com/{$cfg['m365_tenant']}/oauth2/v2.0/token"); curl_setopt($ch, CURLOPT_RETURNTRANSFER, true); curl_setopt($ch, CURLOPT_POSTFIELDS, http_build_query(['client_id' => $cfg['m365_client'], 'scope' => 'https://graph.microsoft.com/.default', 'client_secret' => $cfg['m365_secret'], 'grant_type' => 'client_credentials'])); $token_resp = json_decode(curl_exec($ch), true); curl_close($ch); 
    if(!isset($token_resp['access_token'])) return ['sucesso'=>false]; $token = $token_resp['access_token']; 
    
    $metodo = "PATCH"; $payload = []; $endpoint = "https://graph.microsoft.com/v1.0/users/$email_m365";
    if($acao == 'criar') {
        $metodo = "POST"; $endpoint = "https://graph.microsoft.com/v1.0/users";
        $payload = [ "accountEnabled" => true, "displayName" => $dados_sync['nome'], "mailNickname" => explode('@', $email_m365)[0], "userPrincipalName" => $email_m365, "passwordProfile" => [ "forceChangePasswordNextSignIn" => false, "password" => $nova_senha ], "usageLocation" => "BR" ];
        if(!empty($dados_sync['cargo'])) $payload['jobTitle'] = $dados_sync['cargo']; if(!empty($dados_sync['setor'])) $payload['department'] = $dados_sync['setor']; if(!empty($dados_sync['telefone'])) $payload['mobilePhone'] = "+55" . preg_replace('/[^0-9]/', '', $dados_sync['telefone']); $payload['companyName'] = "Clínica ENFAS";
    } elseif($acao == 'atualizar') {
        if(!empty($dados_sync['nome'])) $payload['displayName'] = $dados_sync['nome']; if(!empty($dados_sync['telefone'])) $payload['mobilePhone'] = "+55" . preg_replace('/[^0-9]/', '', $dados_sync['telefone']);
    }

    $ch2 = curl_init($endpoint); curl_setopt($ch2, CURLOPT_CUSTOMREQUEST, $metodo); if(!empty($payload)) curl_setopt($ch2, CURLOPT_POSTFIELDS, json_encode($payload)); curl_setopt($ch2, CURLOPT_RETURNTRANSFER, true); curl_setopt($ch2, CURLOPT_HTTPHEADER, ["Authorization: Bearer $token", "Content-Type: application/json"]); $resp_graph = curl_exec($ch2); $http_code = curl_getinfo($ch2, CURLINFO_HTTP_CODE); curl_close($ch2); 
    
    if($http_code == 201 || $http_code == 200 || $http_code == 204) {
        if(isset($dados_sync['m365_perfil']) && $dados_sync['m365_perfil'] == 'Basic') {
            $sku_basic = trim($cfg['m365_sku_basic'] ?? '');
            if(!empty($sku_basic)) { sleep(2); $ch_lic = curl_init("https://graph.microsoft.com/v1.0/users/$email_m365/assignLicense"); curl_setopt($ch_lic, CURLOPT_CUSTOMREQUEST, "POST"); curl_setopt($ch_lic, CURLOPT_POSTFIELDS, json_encode(['addLicenses' => [["skuId" => $sku_basic]], 'removeLicenses' => []])); curl_setopt($ch_lic, CURLOPT_RETURNTRANSFER, true); curl_setopt($ch_lic, CURLOPT_HTTPHEADER, ["Authorization: Bearer $token", "Content-Type: application/json"]); curl_exec($ch_lic); curl_close($ch_lic); }
        } return ['sucesso'=>true]; 
    } return ['sucesso'=>false]; 
}

function gerenciarAcessoGoogle_Wizard($conn, $email_google, $acao = 'criar', $nova_senha = null, $dados_sync = []) {
    $cfg = []; $q_cfg = $conn->query("SELECT chave, valor FROM configuracoes WHERE chave IN ('gw_domain', 'gw_json')");
    if($q_cfg) { while($row = $q_cfg->fetch_assoc()) { $cfg[$row['chave']] = trim($row['valor']); } }
    if(empty($cfg['gw_domain']) || empty($cfg['gw_json'])) return ['sucesso'=>false];

    $key = @json_decode($cfg['gw_json'], true); if(!$key || !isset($key['private_key'])) return ['sucesso'=>false];
    $header = json_encode(['alg'=>'RS256','typ'=>'JWT']); $claim = json_encode([ 'iss' => $key['client_email'], 'scope' => 'https://www.googleapis.com/auth/admin.directory.user', 'aud' => $key['token_uri'], 'exp' => time() + 3600, 'iat' => time() ]);
    $b64Header = str_replace(['+', '/', '='], ['-', '_', ''], base64_encode($header)); $b64Claim = str_replace(['+', '/', '='], ['-', '_', ''], base64_encode($claim));
    $sig = ''; openssl_sign($b64Header . "." . $b64Claim, $sig, $key['private_key'], "sha256WithRSAEncryption");
    $b64Sig = str_replace(['+', '/', '='], ['-', '_', ''], base64_encode($sig)); $jwt = $b64Header . "." . $b64Claim . "." . $b64Sig;
    $ch = curl_init($key['token_uri']); curl_setopt($ch, CURLOPT_POST, true); curl_setopt($ch, CURLOPT_POSTFIELDS, http_build_query(['grant_type' => 'urn:ietf:params:oauth:grant-type:jwt-bearer', 'assertion' => $jwt])); curl_setopt($ch, CURLOPT_RETURNTRANSFER, true); $token_resp = json_decode(curl_exec($ch), true); curl_close($ch);
    if(!isset($token_resp['access_token'])) return ['sucesso'=>false]; $token = $token_resp['access_token'];

    $metodo = "PUT"; $endpoint = "https://admin.googleapis.com/admin/directory/v1/users/$email_google"; $payload = [];
    if($acao == 'criar') {
        $metodo = "POST"; $endpoint = "https://admin.googleapis.com/admin/directory/v1/users";
        $partes = explode(' ', $dados_sync['nome'] ?? ''); $primeiro = $partes[0]; $ultimo = count($partes) > 1 ? end($partes) : $primeiro;
        $payload = [ "primaryEmail" => $email_google, "password" => $nova_senha, "name" => [ "givenName" => $primeiro, "familyName" => $ultimo ], "changePasswordAtNextLogin" => false, "organizations" => [ [ "title" => $dados_sync['cargo'] ?? '', "department" => $dados_sync['setor'] ?? '' ] ] ];
        if(!empty($dados_sync['telefone'])) $payload["phones"] = [ [ "value" => "+55".$dados_sync['telefone'], "type" => "mobile" ] ];
    } elseif ($acao == 'reset_senha') { $metodo = "PUT"; $endpoint .= "/$email_google"; $payload = [ "password" => $nova_senha, "suspended" => false ]; }

    $ch2 = curl_init($endpoint); if($metodo != 'POST') curl_setopt($ch2, CURLOPT_CUSTOMREQUEST, $metodo); else curl_setopt($ch2, CURLOPT_POST, true);
    curl_setopt($ch2, CURLOPT_POSTFIELDS, json_encode($payload)); curl_setopt($ch2, CURLOPT_RETURNTRANSFER, true); curl_setopt($ch2, CURLOPT_HTTPHEADER, ["Authorization: Bearer $token", "Content-Type: application/json"]); $resp = curl_exec($ch2); $hc = curl_getinfo($ch2, CURLINFO_HTTP_CODE); curl_close($ch2);
    if($hc == 200 || $hc == 201) return ['sucesso'=>true]; return ['sucesso'=>false];
}

if(isset($_POST['login_colaborador'])){ 
    $u = trim($_POST['usuario']); $p = trim($_POST['senha']); 
    $q_res = $conn->query("SELECT pr.*, c.nome as crg, c.perfil_id, perf.sistemas_ids, u.nome as unid FROM pre_registros pr LEFT JOIN cargos c ON pr.cargo_id=c.id LEFT JOIN perfis_acesso perf ON c.perfil_id=perf.id LEFT JOIN unidades u ON pr.unidade_id=u.id WHERE pr.username_criado='$u'");
    $res = $q_res ? $q_res->fetch_assoc() : null; 
    
    $senha_valida = false;
    if($res && !empty($res['senha_criada'])) {
        if(password_verify($p, $res['senha_criada'])) $senha_valida = true;
        else if($p === $res['senha_criada']) $senha_valida = true; 
    }

    if($senha_valida){ 
        if($res['status'] != 'ativo') { $erro = "Sua conta está inativa ou bloqueada. Procure o RH."; } 
        else { 
            $ip = $_SERVER['REMOTE_ADDR'] ?? 'Desconhecido'; $disp = 'Desktop/Mobile';
            $conn->query("INSERT INTO logs_acesso_user (pre_registro_id, ip, dispositivo) VALUES (".$res['id'].", '$ip', '$disp')");
            $_SESSION['colab'] = $res; header("Location: " . ($res['termo_aceito'] == 1 ? "/Conta/Perfil" : "/Conta/Termos")); exit; 
        } 
    } else { $erro = "Usuário ou senha corporativos incorretos."; } 
}

if(isset($_POST['trocar_senha_interna']) && isset($_SESSION['colab'])){
    $atual = $_POST['senha_atual']; $nova = $_POST['nova_senha']; $id = $_SESSION['colab']['id'];
    $q_chk = $conn->query("SELECT senha_criada FROM pre_registros WHERE id=$id");
    $check = $q_chk ? $q_chk->fetch_assoc() : null;
    
    if($check && (password_verify($atual, $check['senha_criada']) || $atual === $check['senha_criada'])){ 
        $hash_nova = password_hash($nova, PASSWORD_DEFAULT);
        $conn->query("UPDATE pre_registros SET senha_criada='$hash_nova', data_ultima_senha=NOW() WHERE id=$id"); $msg_perfil = "Senha alterada com sucesso!"; 
    } 
    else { $erro_perfil = "A senha atual está incorreta."; }
}

$dados_recuperacao = null; $cpf_salvo = "";
if(isset($_POST['buscar_cpf'])){ 
    $cpf_salvo = $_POST['cpf_recupera']; $cpf_limpo = preg_replace('/[^0-9]/','',$cpf_salvo); 
    $q_cpf = $conn->query("SELECT id, username_criado, e_mail_pessoal, telefone FROM pre_registros WHERE cpf='$cpf_limpo'"); 
    $res = $q_cpf ? $q_cpf->fetch_assoc() : null;
    
    if($res){ 
        // Lógica de Máscara (Estilo HC)
        $email_original = $res['e_mail_pessoal'] ?: '';
        $tel_original = $res['telefone'] ?: '';
        $email_masc = "N/A"; $tel_masc = "N/A";
        
        if(!empty($email_original) && strpos($email_original, '@') !== false) {
            $parts = explode("@", $email_original);
            $email_masc = substr($parts[0], 0, 1) . "*****" . substr($parts[0], -1) . "@" . $parts[1];
        }
        if(!empty($tel_original)) {
            $tel_masc = "XXXX-" . substr($tel_original, -4);
        }
        
        $dados_recuperacao = ['email_masc' => $email_masc, 'tel_masc' => $tel_masc]; 
        $_SESSION['tmp_recupera'] = ['id' => $res['id'], 'usr' => $res['username_criado'], 'email_real' => $res['e_mail_pessoal'], 'telefone_real' => $res['telefone']]; 
    } 
    else { $erro = "CPF não localizado em nossa base."; } 
}

if(isset($_POST['enviar_codigo'])){ 
    $metodo = $_POST['metodo'] ?? 'email'; 
    if($metodo == 'email' && !empty($_SESSION['tmp_recupera']['email_real'])){ 
        $codigo_otp = md5(uniqid(rand(), true)); 
        $conn->query("UPDATE pre_registros SET token_recuperacao='$codigo_otp' WHERE id=".$_SESSION['tmp_recupera']['id']);
        $protocolo = isset($_SERVER['HTTPS']) && $_SERVER['HTTPS'] === 'on' ? "https" : "http";
        $magic_link = $protocolo . "://" . $_SERVER['HTTP_HOST'] . "/User/Validate?code=" . $codigo_otp;
        $q_tpl = $conn->query("SELECT valor FROM configuracoes WHERE chave='tpl_email'");
        $tpl_email = ($q_tpl && $q_tpl->num_rows > 0) ? $q_tpl->fetch_assoc()['valor'] : "<a href='{LINK}'>Clique aqui</a> para redefinir a senha do usuário {USUARIO}.";
        $message = str_replace(['{USUARIO}', '{LINK}'], [$_SESSION['tmp_recupera']['usr'], $magic_link], $tpl_email);
        $to = $_SESSION['tmp_recupera']['email_real']; $subject = "Recuperação de Senha ENFAS"; 
        
        if(enviarEmailSMTP($conn, $to, $subject, $message)) { header("Location: /User/Validate?msg=email"); exit; } 
        else { $erro = "Falha ao conectar no Servidor de E-mail."; }
    } else if ($metodo == 'sms' && !empty($_SESSION['tmp_recupera']['telefone_real'])) { 
        $codigo_otp_sms = sprintf("%06d", mt_rand(100000, 999999)); 
        $conn->query("UPDATE pre_registros SET token_recuperacao='$codigo_otp_sms' WHERE id=".$_SESSION['tmp_recupera']['id']);
        
        $cfg = []; $q_cfg2 = $conn->query("SELECT chave, valor FROM configuracoes WHERE chave IN ('wp_token', 'wp_phone_id', 'wp_template', 'sms_gateway', 'sms_user', 'sms_token', 'sms_from')"); 
        if($q_cfg2) { while($row = $q_cfg2->fetch_assoc()) { $cfg[$row['chave']] = trim($row['valor']); } }
        $telefone = '55' . preg_replace('/[^0-9]/', '', $_SESSION['tmp_recupera']['telefone_real']); 
        
        if(!empty($cfg['wp_token']) && !empty($cfg['wp_phone_id'])) {
            $tpl_meta = !empty($cfg['wp_template']) ? $cfg['wp_template'] : "codigo_recuperacao_enfas";
            $payload = json_encode([ "messaging_product" => "whatsapp", "to" => $telefone, "type" => "template", "template" => [ "name" => $tpl_meta, "language" => ["code" => "pt_BR"], "components" => [ [ "type" => "body", "parameters" => [ ["type" => "text", "text" => $codigo_otp_sms] ] ], [ "type" => "button", "sub_type" => "url", "index" => "0", "parameters" => [ ["type" => "text", "text" => $codigo_otp_sms] ] ] ] ] ]); 
            $ch = curl_init("https://graph.facebook.com/v18.0/" . $cfg['wp_phone_id'] . "/messages"); curl_setopt($ch, CURLOPT_HTTPHEADER, ["Authorization: Bearer " . $cfg['wp_token'], "Content-Type: application/json"]); curl_setopt($ch, CURLOPT_POST, true); curl_setopt($ch, CURLOPT_POSTFIELDS, $payload); curl_setopt($ch, CURLOPT_RETURNTRANSFER, true); curl_exec($ch); curl_close($ch); 
        } else if(!empty($cfg['sms_gateway'])) {
            $mensagem_sms = "ENFAS - Seu codigo OTP e: $codigo_otp_sms.";
            if($cfg['sms_gateway'] == 'twilio') {
                $url = "https://api.twilio.com/2010-04-01/Accounts/{$cfg['sms_user']}/Messages.json";
                $data = http_build_query([ 'To' => "+$telefone", 'From' => $cfg['sms_from'], 'Body' => $mensagem_sms ]);
                $ch = curl_init($url); curl_setopt($ch, CURLOPT_POST, true); curl_setopt($ch, CURLOPT_POSTFIELDS, $data); curl_setopt($ch, CURLOPT_USERPWD, "{$cfg['sms_user']}:{$cfg['sms_token']}"); curl_setopt($ch, CURLOPT_RETURNTRANSFER, true); curl_exec($ch); curl_close($ch);
            }
        }
        header("Location: /User/Validate?msg=sms"); exit; 
    }
}

if(isset($_POST['validar_otp'])){ 
    $code = $conn->real_escape_string(trim($_POST['codigo_digitado']));
    $q_val = $conn->query("SELECT id, username_criado FROM pre_registros WHERE token_recuperacao='$code' AND token_recuperacao IS NOT NULL");
    $res = $q_val ? $q_val->fetch_assoc() : null;
    if($res) { $_SESSION['tmp_recupera'] = ['id' => $res['id'], 'usr' => $res['username_criado']]; header("Location: /User/NewPassword"); exit; } 
    else { $erro = "Código inválido."; } 
}

if(isset($_POST['salvar_nova_senha'])){ 
    $nova_senha = $conn->real_escape_string($_POST['nova_senha']);
    $hash_senha = password_hash($nova_senha, PASSWORD_DEFAULT);
    $token_url = $conn->real_escape_string($_POST['token_url'] ?? '');
    
    if(!empty($token_url)) {
        $conn->query("UPDATE pre_registros SET senha_criada='$hash_senha', data_ultima_senha=NOW(), token_recuperacao=NULL WHERE token_recuperacao='$token_url'"); 
        $q_usr = $conn->query("SELECT username_criado FROM pre_registros WHERE senha_criada='$hash_senha' ORDER BY id DESC LIMIT 1");
        if($q_usr && $q_usr->num_rows > 0) { $usr_m365 = $q_usr->fetch_assoc()['username_criado']; gerenciarAcessoM365_Wizard($conn, $usr_m365."@enfas.com.br", 'reset_senha', $nova_senha); gerenciarAcessoGoogle_Wizard($conn, $usr_m365."@enfas.com.br", 'reset_senha', $nova_senha); }
    } else if(isset($_SESSION['tmp_recupera']['id'])) {
        $conn->query("UPDATE pre_registros SET senha_criada='$hash_senha', data_ultima_senha=NOW(), token_recuperacao=NULL WHERE id=".$_SESSION['tmp_recupera']['id']); 
        $usr_m365 = $_SESSION['tmp_recupera']['usr']; gerenciarAcessoM365_Wizard($conn, $usr_m365."@enfas.com.br", 'reset_senha', $nova_senha); gerenciarAcessoGoogle_Wizard($conn, $usr_m365."@enfas.com.br", 'reset_senha', $nova_senha); unset($_SESSION['tmp_recupera']); 
    }
    header("Location: /Conta/Login?msg=senha_alterada"); exit; 
}

if(isset($_POST['avancar_1'])){ 
    $cpf = preg_replace('/[^0-9]/','',$_POST['cpf']); $nasc = $_POST['nasc']; 
    $q_usr = $conn->query("SELECT p.*, c.nome as crg, u.nome as unid, s.nome as setor FROM pre_registros p LEFT JOIN cargos c ON p.cargo_id=c.id LEFT JOIN unidades u ON p.unidade_id=u.id LEFT JOIN setores s ON p.setor_id=s.id WHERE p.cpf='$cpf' AND p.data_nascimento='$nasc' AND p.status='pendente'"); 
    $res = $q_usr ? $q_usr->fetch_assoc() : null;
    
    if($res){ 
        $_SESSION['tmp_colab'] = $res; 
        $nome_limpo = strtolower(preg_replace('/[áàãâä]/ui', 'a', preg_replace('/[éèêë]/ui', 'e', preg_replace('/[íìîï]/ui', 'i', preg_replace('/[óòõôö]/ui', 'o', preg_replace('/[úùûü]/ui', 'u', preg_replace('/[ç]/ui', 'c', $res['nome_completo'])))))));
        $partes_nome = explode(' ', trim($nome_limpo)); $primeiro = preg_replace('/[^a-z0-9]/', '', $partes_nome[0]); $ultimo = preg_replace('/[^a-z0-9]/', '', end($partes_nome));
        if($primeiro == $ultimo) { $ultimo = $primeiro . rand(10,99); }
        $_SESSION['email_opts'] = [ $primeiro . '.' . $ultimo, $primeiro . '.' . substr($ultimo, 0, 1), substr($primeiro, 0, 1) . '.' . $ultimo, $primeiro . '.' . $ultimo . rand(10,99) ];
        $_SESSION['etapa'] = 2; header("Location: /User/NewUser"); exit; 
    } else { $erro = "Cadastro não localizado, já ativo ou dados incorretos."; } 
}

if(isset($_POST['avancar_2'])){ 
    $_SESSION['tmp_colab']['username_criado'] = $_POST['email_escolhido']; 
    $conn->query("UPDATE pre_registros SET e_mail_pessoal='".$_POST['mail_wizard']."', telefone='".preg_replace('/[^0-9]/','',$_POST['tel_wizard'])."' WHERE id=".$_SESSION['tmp_colab']['id']); 
    $_SESSION['tmp_colab']['e_mail_pessoal'] = $_POST['mail_wizard'];
    $_SESSION['tmp_colab']['telefone'] = preg_replace('/[^0-9]/','',$_POST['tel_wizard']);
    $_SESSION['etapa'] = 3; header("Location: /User/NewUser"); exit; 
}

if(isset($_POST['finalizar'])){ 
    $pwd = $_POST['senha']; $id = $_SESSION['tmp_colab']['id']; $usr = $_SESSION['tmp_colab']['username_criado']; 
    $dados_sync = [ 'nome' => $_SESSION['tmp_colab']['nome_completo'], 'cargo' => $_SESSION['tmp_colab']['crg'], 'setor' => $_SESSION['tmp_colab']['setor'], 'telefone' => $_SESSION['tmp_colab']['telefone'], 'm365_perfil' => $_SESSION['tmp_colab']['m365_perfil'] ]; 
    
    $m365_resp = gerenciarAcessoM365_Wizard($conn, $usr."@enfas.com.br", 'criar', $pwd, $dados_sync); 
    $gw_resp = gerenciarAcessoGoogle_Wizard($conn, $usr."@enfas.com.br", 'criar', $pwd, $dados_sync);
    $hash_senha = password_hash($pwd, PASSWORD_DEFAULT);

    if($m365_resp['sucesso'] || $gw_resp['sucesso']) {
        $conn->query("UPDATE pre_registros SET username_criado='$usr', senha_criada='$hash_senha', status='ativo', data_ultima_senha=NOW() WHERE id=$id"); 
        session_destroy(); header("Location: /Conta/Login?msg=sucesso"); exit; 
    } else { $erro = "Falha de provisionamento Cloud."; }
}

if(isset($_POST['aceitar_termo'])){ $conn->query("UPDATE pre_registros SET termo_aceito=1 WHERE id=".$_SESSION['colab']['id']); $_SESSION['colab']['termo_aceito']=1; header("Location: /Conta/Perfil"); exit; }
if(isset($_POST['recusar_termo'])){ header("Location: /Conta/Logout"); exit; }
if(isset($_SESSION['colab']['id'])) { 
    $q_ft = $conn->query("SELECT foto_path FROM pre_registros WHERE id=".$_SESSION['colab']['id']);
    $db_foto = $q_ft ? $q_ft->fetch_assoc() : null; if($db_foto) $_SESSION['colab']['foto_path'] = $db_foto['foto_path']; 
}
?>
<!DOCTYPE html>
<html lang="pt-BR">
<head>
    <meta charset="utf-8"/>
    <title>Autoatendimento - ENFAS</title>
    <meta name="viewport" content="width=device-width, initial-scale=1.0"/>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
    <style>
        /* LIGHT THEME INSTITUCIONAL (Estilo HC) */
        body { background-color: #f0f4f8; font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; display: flex; flex-direction: column; min-height: 100vh; margin:0; color: #333;}
        
        .topbar-hc { background-color: #337ab7; height: 60px; display: flex; align-items: center; justify-content: space-between; padding: 0 40px; box-shadow: 0 2px 5px rgba(0,0,0,0.2); width: 100%; color: white; z-index: 10;}
        .hc-footer { background-color: #2c3e50; color: white; padding: 20px 40px; display: flex; align-items: center; justify-content: space-between; border-top: 4px solid #337ab7; margin-top: auto; }
        
        .main-content { flex: 1; display: flex; flex-direction: column; align-items: center; justify-content: center; padding: 40px 20px; width: 100%; box-sizing: border-box; }

        .hc-card { background-color: #fff; width: 100%; max-width: 600px; box-shadow: 0 4px 12px rgba(0,0,0,0.1); border-radius: 4px; padding: 40px; }
        .login-container { display: flex; width: 100%; max-width: 800px; background-color: #fff; box-shadow: 0 4px 12px rgba(0,0,0,0.1); margin-top: 20px; border-radius: 4px; overflow: hidden;}
        .login-left { width: 50%; padding: 40px; border-right: 1px solid #eee; }
        .login-right { width: 50%; padding: 40px; display: flex; flex-direction: column; background: #fafafa;}
        
        .hc-title { color: #337ab7; font-size: 22px; margin-bottom: 5px; font-weight: 400;}
        .hc-subtitle { color: #666; font-size: 13px; border-bottom: 1px solid #eee; padding-bottom: 15px; margin-bottom: 25px;}

        /* Input Login Estilo HC (Ícone à direita) */
        .hc-input-group { display: flex; align-items: center; background-color: #fff; border: 1px solid #ccc; margin-bottom: 20px; border-radius: 3px; transition: 0.3s; }
        .hc-input-group input { background: transparent; border: none; color: #333; padding: 12px 15px; width: 100%; outline: none; }
        .hc-input-group i { padding: 0 15px; color: #888; border-left: 1px solid #eee; }
        .hc-input-group:focus-within { border-color: #337ab7; box-shadow: 0 0 5px rgba(51,122,183,0.3);}

        .btn-hc-blue { background-color: #337ab7; border: none; color: white; padding: 10px 20px; font-weight: 600; border-radius: 3px; transition: 0.2s;}
        .btn-hc-blue:hover { background-color: #286090; color: white; }
        .btn-hc-green { background-color: #5cb85c; border: none; color: white; padding: 10px 20px; font-weight: 600; border-radius: 3px; transition: 0.2s;}
        .btn-hc-green:hover { background-color: #449d44; color: white; }
        .btn-hc-grey { background-color: #e7e7e7; border: 1px solid #ccc; color: #333; padding: 10px 20px; font-weight: 600; border-radius: 3px; text-decoration: none; transition: 0.2s;}
        .btn-hc-grey:hover { background-color: #d4d4d4; color: #333; }
        .btn-hc-danger { background-color: #d9534f; border: none; color: white; padding: 10px 20px; font-weight: 600; border-radius: 3px; transition: 0.2s;}
        .btn-hc-danger:hover { background-color: #c9302c; color: white; }

        /* FITA (RIBBON) DO PERFIL */
        .ribbon-wrapper { position: relative; margin: 30px 0 20px 0; text-align: center; }
        .ribbon-hc { background: #337ab7; color: white; display: inline-block; width: 100%; padding: 12px; position: relative; font-weight: 600; text-transform: uppercase; font-size: 15px; letter-spacing: 0.5px;}
        .ribbon-hc::before, .ribbon-hc::after { content: ""; position: absolute; top: 0; width: 0; height: 0; border-top: 23px solid transparent; border-bottom: 23px solid transparent; }
        .ribbon-hc::before { left: 0; border-left: 15px solid #fff; }
        .ribbon-hc::after { right: 0; border-right: 15px solid #fff; }

        /* TABELA DE DADOS (Striped Vertical) */
        .data-table { border: 1px solid #ddd; width: 100%; text-align: center; font-size: 14px; margin-bottom: 20px;}
        .data-header { background-color: #f0f4f8; color: #337ab7; padding: 8px; border-bottom: 1px solid #ddd; border-top: 1px solid #ddd; font-weight: 600; }
        .data-value { background-color: #fff; color: #555; padding: 10px; border-bottom: 1px solid #ddd; }

        .wizard-steps { display: flex; justify-content: space-between; position: relative; margin: 20px 0 40px; }
        .wizard-steps::before { content: ''; position: absolute; top: 15px; left: 16%; width: 68%; height: 3px; background: #337ab7; z-index: 1; opacity:0.3;}
        .step { text-align: center; position: relative; z-index: 2; width: 33.33%; font-size: 13px; color: #999; }
        .step-circle { width: 34px; height: 34px; border-radius: 50%; background: #fff; border: 3px solid #ccc; display: inline-flex; align-items: center; justify-content: center; font-weight: bold; margin: 0 auto 10px;}
        .step.active .step-circle { border-color: #337ab7; color: #337ab7; }
        .step.done .step-circle { background: #337ab7; color: white; border-color: #337ab7; }
        .step.active { color: #337ab7; font-weight:bold; }

        .sys-card { background: #fff; border: 1px solid #ddd; padding: 20px; text-align: center; text-decoration: none; color: #337ab7; font-weight: bold; transition: 0.2s; display:block; margin-bottom:15px; border-radius:4px; box-shadow:0 2px 4px rgba(0,0,0,0.05);}
        .sys-card:hover { border-color: #337ab7; background: #f0f4f8; text-decoration:none; transform: translateY(-2px);}

        .btn-loading { pointer-events: none; opacity: 0.8; }
        .btn-loading::after { content: " ⏳"; animation: spin 1s infinite linear; }
        @keyframes spin { 0% { transform: rotate(0deg); } 100% { transform: rotate(360deg); } }

        @media (max-width: 768px) { .login-container { flex-direction: column; } .login-left, .login-right { width: 100%; padding: 30px; } .login-left { border-bottom: 1px solid #eee; border-right:none;} }
    </style>
</head>
<body>

<?php if($m != 'home'): ?>
    <div class="topbar-hc">
        <a href="/Conta/Perfil" style="color:white; text-decoration:none; font-size:22px; font-weight:bold; display:flex; align-items:center;">
            <i class="fa-solid fa-hospital-user fa-lg me-2"></i> ENFAS
        </a>
        <?php if(isset($_SESSION['colab'])): ?>
            <div style="font-size:13px; text-align:right;">
                Bem-vindo,<br> <b style="color:#fff;"><?=$_SESSION['colab']['username_criado']?></b> 
            </div>
        <?php endif; ?>
    </div>
<?php endif; ?>

<div class="main-content">
    
    <?php if($m == 'home'): ?>
        <div class="text-center mb-4">
            <img src="https://autoatendimento.enfas.com.br/Content/images/logo_enfas.png" style="max-width:250px;" onerror="this.outerHTML='<h1 style=\'color:#337ab7;font-weight:bold;\'>+ ENFAS</h1>';">
        </div>
        
        <?php if(!empty($aviso_login)): ?>
            <div class="alert alert-warning text-center fw-bold mb-4 mx-auto" style="max-width:800px; border-radius:3px; width:100%;"><i class="fa-solid fa-bullhorn"></i> <?=$aviso_login?></div>
        <?php endif; ?>
        
        <div class="login-container">
            <div class="login-left">
                <div class="hc-title">Acessar minha conta</div>
                <div class="hc-subtitle">Acesse utilizando seu usuário e senha corporativa</div>
                
                <?php if($erro) echo "<div class='alert alert-danger p-2 mb-3 small fw-bold text-center'>$erro</div>"; ?>
                <?php if(isset($_GET['msg']) && $_GET['msg']=='deslogado') echo "<div class='alert alert-info p-2 mb-3 small fw-bold text-center'>Deslogado com segurança.</div>"; ?>
                <?php if(isset($_GET['msg']) && $_GET['msg']=='senha_alterada') echo "<div class='alert alert-success p-2 mb-3 small fw-bold text-center'>Senha alterada! Faça login.</div>"; ?>
                <?php if(isset($_GET['msg']) && $_GET['msg']=='sucesso') echo "<div class='alert alert-success p-2 mb-3 small fw-bold text-center'>Conta criada! Faça login.</div>"; ?>
                
                <form method="POST" action="/Conta/Login" onsubmit="this.querySelector('button').classList.add('btn-loading');">
                    <div class="hc-input-group">
                        <input type="text" name="usuario" placeholder="Usuário" required>
                        <i class="fa-solid fa-user"></i>
                    </div>
                    <div class="hc-input-group mb-4">
                        <input type="password" name="senha" placeholder="Senha" required>
                        <i class="fa-solid fa-lock"></i>
                    </div>
                    <div class="d-flex justify-content-between align-items-center">
                        <a href="/User/ResetPassword" style="font-size:13px; color:#337ab7; text-decoration:none;">Esqueci minha senha</a>
                        <button name="login_colaborador" class="btn-hc-blue"><i class="fa-solid fa-key me-1"></i> Acessar</button>
                    </div>
                </form>
            </div>
            
            <div class="login-right">
                <div class="hc-title">Novo na ENFAS?</div>
                <div class="hc-subtitle">Crie uma conta</div>
                <div class="text-center mt-3 mb-4">
                    <a href="/User/NewUser" class="btn-hc-blue" style="text-decoration:none; display:inline-block; width:100%;"><i class="fa-solid fa-user-plus me-2"></i> Criar conta ENFAS</a>
                </div>
                <div style="font-size:12px; color:#666; text-align:center; margin-top:auto;">
                    <a href="/Conta/Manual" style="color:#337ab7; text-decoration:none;">Clique aqui</a> para acessar a<br>
                    <b>Política de Segurança da Informação</b>
                </div>
            </div>
        </div>

    <?php elseif($m == 'perfil'): ?>
        <div class="hc-card">
            <div class="d-flex justify-content-between align-items-center border-bottom pb-2 mb-4">
                <h4 style="color:#337ab7; margin:0;"><i class="fa-solid fa-user me-2"></i> Dados do Usuário</h4>
                <div>
                    <button onclick="document.getElementById('modal_senha').style.display='flex'" class="btn btn-sm btn-outline-secondary me-2"><i class="fa-solid fa-lock"></i> Senha</button>
                    <a href="/Conta/Logout" class="btn btn-sm btn-outline-danger"><i class="fa-solid fa-right-from-bracket"></i> Sair</a>
                </div>
            </div>
            
            <?php if($msg_perfil) echo "<div class='alert alert-success text-center fw-bold p-2'>$msg_perfil</div>"; ?>
            <?php if($erro_perfil) echo "<div class='alert alert-danger text-center fw-bold p-2'>$erro_perfil</div>"; ?>
            
            <div class="text-center">
                <?php $foto_url = !empty($_SESSION['colab']['foto_path']) ? '//cadcolab.enfas.com.br/'.$_SESSION['colab']['foto_path'].'?v='.time() : 'https://via.placeholder.com/150'; ?>
                <img src="<?=$foto_url?>" style="width:140px; height:140px; object-fit:cover; border:2px solid #ccc; padding:3px; background:#fff;">
            </div>
            
            <div class="ribbon-wrapper">
                <div class="ribbon-hc"><?=$_SESSION['colab']['nome_completo']?></div>
            </div>
            
            <div class="data-table">
                <div class="data-header">Matrícula</div>
                <div class="data-value"><?=$_SESSION['colab']['matricula']?:'N/A'?></div>
                
                <div class="data-header">CPF</div>
                <div class="data-value"><?=preg_replace("/(\d{3})(\d{3})(\d{3})(\d{2})/", "\$1.\$2.\$3-\$4", $_SESSION['colab']['cpf'])?></div>
                
                <div class="data-header">Data Nasc.</div>
                <div class="data-value"><?=!empty($_SESSION['colab']['data_nascimento']) && $_SESSION['colab']['data_nascimento'] != '0000-00-00' ? date('d/m/Y', strtotime($_SESSION['colab']['data_nascimento'])) : 'N/A'?></div>
                
                <div class="data-header">Nome da mãe</div>
                <div class="data-value"><?=$_SESSION['colab']['nome_mae']?:'N/A'?></div>
                
                <div class="data-header">Admissão</div>
                <div class="data-value"><?=!empty($_SESSION['colab']['data_admissao']) && $_SESSION['colab']['data_admissao'] != '0000-00-00' ? date('d/m/Y', strtotime($_SESSION['colab']['data_admissao'])) : 'N/A'?></div>
                
                <div class="data-header">Usuário</div>
                <div class="data-value"><b style="color:#337ab7;"><?=$_SESSION['colab']['username_criado']?>@enfas.com.br</b></div>
                
                <div class="data-header">E-mail Pessoal</div>
                <div class="data-value"><?=$_SESSION['colab']['e_mail_pessoal']?:'N/A'?></div>
                
                <div class="data-header">Telefone</div>
                <div class="data-value"><?=$_SESSION['colab']['telefone']?:'N/A'?></div>
                
                <div class="data-header">Lotação</div>
                <div class="data-value"><?=$_SESSION['colab']['unid']?> - <?=$_SESSION['colab']['crg']?></div>
            </div>
            
            <h5 style="color:#337ab7; margin-top:30px; border-bottom:1px solid #eee; padding-bottom:10px;"><i class="fa-solid fa-layer-group me-2"></i> Sistemas Autorizados</h5>
            <div class="row mt-3">
                <?php 
                $sist_perfil = !empty($_SESSION['colab']['sistemas_ids']) ? explode(',', $_SESSION['colab']['sistemas_ids']) : [];
                $sist_colab = !empty($_SESSION['colab']['sistemas_liberados']) ? explode(',', $_SESSION['colab']['sistemas_liberados']) : [];
                $sistemas = $conn->query("SELECT * FROM sistemas_hc"); $temSist = false;
                if($sistemas){ while($s = $sistemas->fetch_assoc()){
                    if(in_array($s['id'], $sist_perfil) || in_array($s['nome'], $sist_colab)){
                        $temSist = true; 
                        $url = preg_match("~^(?:f|ht)tps?://~i", $s['link']) ? $s['link'] : "http://".$s['link'];
                        echo "<div class='col-md-6 col-sm-12'><a href='$url' target='_blank' class='sys-card'><i class='".$s['icone']." fa-2x mb-2' style='display:block;'></i>".$s['nome']."</a></div>";
                    }
                } }
                if(!$temSist) echo "<div class='col-12'><div class='alert alert-secondary text-center'>Nenhum sistema vinculado.</div></div>";
                ?>
            </div>
        </div>

    <?php elseif($m == 'wizard'): ?>
        <div class="hc-card">
            <h4 style="color:#337ab7; text-align:center; font-weight:300; margin-bottom:0;">Auto Atendimento ENFAS »</h4>
            <div style="text-align:center; color:#777; margin-bottom:20px;">Criação de Conta</div>
            
            <div class="wizard-steps">
                <div class="step <?=($etapa>=1?'done':'')?> <?=($etapa==1?'active':'')?>"><div class="step-circle"><?=($etapa>1?'<i class="fa-solid fa-check"></i>':'1')?></div>Pesquisa<br>colaborador</div>
                <div class="step <?=($etapa>=2?'done':'')?> <?=($etapa==2?'active':'')?>"><div class="step-circle"><?=($etapa>2?'<i class="fa-solid fa-check"></i>':'2')?></div>Opções de<br>e-mail</div>
                <div class="step <?=($etapa==3?'active':'')?>"><div class="step-circle">3</div>Cadastro de<br>senha</div>
            </div>

            <?php if($erro) echo "<div class='alert alert-danger text-center fw-bold p-2 small'>$erro</div>"; ?>

            <div style="max-width:500px; margin: 0 auto;">
                <?php if($etapa == 1): ?>
                    <form method="POST" action="/User/NewUser" onsubmit="this.querySelector('button[name=\'avancar_1\']').classList.add('btn-loading');">
                        <div class="mb-3">
                            <label class="fw-bold text-muted small">Data de Nascimento:</label>
                            <input type="date" name="nasc" class="form-control" required>
                        </div>
                        <div class="mb-4">
                            <label class="fw-bold text-muted small">CPF:</label>
                            <input type="text" name="cpf" class="form-control" placeholder="Apenas números" required>
                        </div>
                        <div class="text-center border-top pt-3">
                            <a href="/Conta/Login" class="btn-hc-grey me-2">Voltar</a>
                            <button name="avancar_1" class="btn-hc-blue px-4">Avançar</button>
                        </div>
                    </form>

                <?php elseif($etapa == 2): ?>
                    <form method="POST" action="/User/NewUser" onsubmit="this.querySelector('button[name=\'avancar_2\']').classList.add('btn-loading');">
                        
                        <div class="data-table mb-4">
                            <div class="data-header">Nome</div>
                            <div class="data-value"><?=$_SESSION['tmp_colab']['nome_completo']?></div>
                            <div class="data-header">Data Nasc.</div>
                            <div class="data-value"><?=date('d/m/Y', strtotime($_SESSION['tmp_colab']['data_nascimento']))?></div>
                            <div class="data-header">Nome da mãe</div>
                            <div class="data-value"><?=$_SESSION['tmp_colab']['nome_mae']?:'N/A'?></div>
                            <div class="data-header">CPF</div>
                            <div class="data-value"><?=preg_replace("/(\d{3})(\d{3})(\d{3})(\d{2})/", "\$1.\$2.\$3-\$4", $_SESSION['tmp_colab']['cpf'])?></div>
                        </div>
                        
                        <div style="text-align: left; margin-bottom: 30px;">
                            <?php foreach($_SESSION['email_opts'] as $index => $opcao): ?>
                                <div style="margin-bottom: 10px;">
                                    <label style="cursor: pointer; display: flex; align-items: center; color: #555;">
                                        <input type="radio" name="email_escolhido" value="<?=$opcao?>" <?=($index==0?'checked':'')?> style="margin-right: 10px; transform: scale(1.2);">
                                        <span style="font-size:15px;"><?=$opcao?>@enfas.com.br</span>
                                    </label>
                                </div>
                            <?php endforeach; ?>
                        </div>

                        <div class="mb-3">
                            <label class="fw-bold text-muted small">Celular / WhatsApp Pessoal:</label>
                            <input type="text" name="tel_wizard" class="form-control" value="<?=$_SESSION['tmp_colab']['telefone']?>" required>
                        </div>
                        <div class="mb-4">
                            <label class="fw-bold text-muted small">E-mail Pessoal Alternativo:</label>
                            <input type="email" name="mail_wizard" class="form-control" value="<?=$_SESSION['tmp_colab']['e_mail_pessoal']?>" required>
                        </div>
                        
                        <div class="text-center border-top pt-3">
                            <a href="/Conta/Login" class="btn-hc-grey me-2">Cancelar</a>
                            <button name="avancar_2" class="btn-hc-blue px-4">Avançar</button>
                        </div>
                    </form>

                <?php elseif($etapa == 3): ?>
                    <form method="POST" action="/User/NewUser" onsubmit="this.querySelector('button[name=\'finalizar\']').classList.add('btn-loading');">
                        <div class="alert alert-info text-center small mb-4">
                            Sua conta será: <b><?=$_SESSION['tmp_colab']['username_criado']?>@enfas.com.br</b>
                        </div>
                        <div class="mb-4">
                            <label class="fw-bold text-muted small">Definir Senha de Acesso:</label>
                            <input type="password" name="senha" class="form-control text-center" placeholder="Mínimo 8 caracteres" minlength="8" required>
                        </div>
                        <div class="text-center border-top pt-3">
                            <a href="/Conta/Login" class="btn-hc-grey me-2">Cancelar</a>
                            <button name="finalizar" class="btn-hc-green px-4">Concluir Cadastro</button>
                        </div>
                    </form>
                <?php endif; ?>
            </div>
        </div>

    <?php elseif(in_array($m, ['recuperar', 'validar_codigo', 'nova_senha'])): ?>
        <div class="hc-card text-center">
            
            <?php 
            $token_url = $_GET['code'] ?? ($_GET['token'] ?? '');
            $id_valido = false;
            
            if(!empty($token_url) && $m == 'nova_senha') {
                $code_limpo = $conn->real_escape_string($token_url);
                $res_tok = $conn->query("SELECT id FROM pre_registros WHERE token_recuperacao='$code_limpo' AND token_recuperacao IS NOT NULL")->fetch_assoc();
                if($res_tok) { $id_valido = true; } 
                else { $erro = "Link inválido ou expirado."; $m = 'recuperar'; }
            } else if (isset($_SESSION['tmp_recupera']['id'])) {
                $id_valido = true; 
            }
            ?>

            <?php if($m == 'recuperar'): ?>
                <h3 style="color:#337ab7; font-weight:300; margin-bottom:30px;"><i class="fa-solid fa-key me-2"></i> Recuperação de Senha</h3>
                
                <form method="POST" action="/User/ResetPassword" onsubmit="this.querySelector('button[name=\'buscar_cpf\']').classList.add('btn-loading');">
                    <div class="mb-4 text-start" style="max-width:300px; margin:0 auto;">
                        <label class="text-muted small mb-1">CPF do colaborador:</label>
                        <input type="text" name="cpf_recupera" value="<?=$cpf_salvo?>" class="form-control text-center fs-5" required>
                    </div>
                    <?php if(!$dados_recuperacao): ?>
                        <div class="border-top pt-3 mt-4">
                            <a href="/Conta/Login" class="btn-hc-grey me-2">Voltar</a>
                            <button name="buscar_cpf" class="btn-hc-blue px-4">Avançar</button>
                        </div>
                    <?php endif; ?>
                </form>
                
                <?php if($erro) echo "<div class='alert alert-danger mt-3 p-2 small fw-bold'>$erro</div>"; ?>
                
                <?php if($dados_recuperacao): ?>
                    <div style="text-align:center; margin-top:20px;">
                        <p class="text-muted small mb-3">Escolha uma das opções para recuperação:</p>
                        <form method="POST" action="/User/ResetPassword" onsubmit="this.querySelector('button[name=\'enviar_codigo\']').classList.add('btn-loading');">
                            
                            <div class="d-flex justify-content-center gap-4 mb-4">
                                <label style="cursor: pointer; color: #555;">
                                    <input type="radio" name="metodo" value="sms" checked onclick="document.getElementById('box-sms').style.display='block'; document.getElementById('box-email').style.display='none';"> SMS/WhatsApp
                                </label>
                                <label style="cursor: pointer; color: #555;">
                                    <input type="radio" name="metodo" value="email" onclick="document.getElementById('box-sms').style.display='none'; document.getElementById('box-email').style.display='block';"> E-mail Alternativo
                                </label>
                            </div>

                            <div id="box-sms" style="border:1px solid #ddd; padding:20px; border-radius:4px; margin-bottom:20px;">
                                <h6 style="color:#337ab7;">SMS / WhatsApp</h6>
                                <p style="color:#d9534f; font-weight:bold; font-size:13px; margin:15px 0;">* Ao clicar em "Enviar", será enviado um código para o celular cadastrado:<br><br><span style="font-size:16px; color:#333;"><?=$dados_recuperacao['tel_masc']?></span></p>
                            </div>

                            <div id="box-email" style="border:1px solid #ddd; padding:20px; border-radius:4px; margin-bottom:20px; display:none;">
                                <h6 style="color:#337ab7;">E-mail</h6>
                                <p style="color:#d9534f; font-weight:bold; font-size:13px; margin:15px 0;">Um link de alteração de senha será enviado para:<br><br><span style="font-size:16px; color:#333;"><?=$dados_recuperacao['email_masc']?></span></p>
                            </div>

                            <button name="enviar_codigo" class="btn-hc-green px-5 py-2 w-100 fs-6">Enviar Solicitação</button>
                        </form>
                    </div>
                <?php endif; ?>
                
            <?php elseif($m == 'validar_codigo'): ?>
                <h3 style="color:#337ab7; font-weight:300; margin-bottom:30px;"><i class="fa-solid fa-shield-halved me-2"></i> Validação</h3>
                
                <?php if(isset($_GET['msg']) && $_GET['msg'] == 'email'): ?>
                    <div class="alert alert-success fw-bold p-3 small text-center mb-4">
                        E-mail enviado com sucesso! Verifique a sua caixa de entrada e a pasta Spam.
                    </div>
                    <p class="text-muted small mb-4">Abra o e-mail que enviámos e clique no link para ser redirecionado diretamente para o ecrã de Nova Senha.</p>
                    <a href="/Conta/Login" class="btn-hc-grey">Voltar ao Início</a>
                <?php else: ?>
                    <div class="alert alert-info fw-bold p-3 small text-center mb-4">
                        Código enviado ao seu dispositivo!
                    </div>
                    <p class="text-muted small mb-3">Digite o código de 6 dígitos para validar o seu acesso.</p>
                    <form method="POST" action="/User/Validate" onsubmit="this.querySelector('button[name=\'validar_otp\']').classList.add('btn-loading');">
                        <input type="text" name="codigo_digitado" class="form-control form-control-lg text-center mx-auto mb-4" style="max-width:200px; font-size:24px; letter-spacing:8px; font-weight:bold; color:#337ab7;" maxlength="6" required>
                        <button name="validar_otp" class="btn-hc-green px-5 py-2">Validar Código</button>
                    </form>
                <?php endif; ?>
                <?php if($erro) echo "<div class='alert alert-danger mt-3 p-2 small fw-bold'>$erro</div>"; ?>
                
            <?php elseif($m == 'nova_senha' && $id_valido): ?>
                <h3 style="color:#337ab7; font-weight:300; margin-bottom:30px;"><i class="fa-solid fa-lock me-2"></i> Nova Senha</h3>
                <p class="text-muted small mb-4">A sua identidade foi validada. Defina a nova senha corporativa.</p>
                <form method="POST" action="/User/NewPassword" onsubmit="this.querySelector('button[name=\'salvar_nova_senha\']').classList.add('btn-loading');">
                    <input type="hidden" name="token_url" value="<?=htmlspecialchars($token_url)?>">
                    <input type="password" name="nova_senha" class="form-control form-control-lg text-center mx-auto mb-4" style="max-width:250px;" placeholder="Mín. 8 caracteres" minlength="8" required>
                    <button name="salvar_nova_senha" class="btn-hc-blue px-5 py-2">Salvar Senha</button>
                </form>
            <?php endif; ?>
        </div>

    <?php elseif(in_array($m, ['termo', 'manual'])): ?>
        <div class="hc-card" style="max-width:800px;">
            <div style="text-align:center; margin-bottom:20px;">
                <img src="https://autoatendimento.enfas.com.br/Content/images/logo_enfas.png" style="max-width:150px; margin-bottom:10px;">
                <h4 style="color:#337ab7; font-weight:300;">Termo de uso</h4>
            </div>
            
            <?php if($m=='termo' && isset($_SESSION['colab'])): ?>
                <p class="text-muted small mb-3">Olá <b style="color:#337ab7;"><?=$_SESSION['colab']['username_criado']?></b>, antes de acessar os sistemas você precisa aceitar os termos abaixo.</p>
            <?php endif; ?>

            <div style="background:#fff; border:1px solid #ddd; padding:20px; height:300px; overflow-y:auto; font-size:13px; color:#555; text-align:justify; margin-bottom:20px; box-shadow: inset 0 2px 4px rgba(0,0,0,0.05);">
                <p><b>DIRETRIZES CORPORATIVAS ENFAS</b></p>
                <p>O acesso aos sistemas corporativos é concedido exclusivamente para o desempenho de suas funções profissionais. O compartilhamento de senhas é estritamente proibido e considerado infração grave.</p>
                <p>Todo acesso, tráfego de dados e envio de e-mails institucionais são monitorados para fins de segurança da informação e compliance com a Lei Geral de Proteção de Dados (LGPD).</p>
                <p>Em caso de perda ou suspeita de violação da sua credencial, você deve imediatamente utilizar o recurso de recuperação de senha ou comunicar o departamento de TI.</p>
            </div>
            
            <div class="text-end border-top pt-3">
                <?php if($m == 'termo'): ?>
                    <form method="POST" class="d-inline">
                        <button name="recusar_termo" class="btn-hc-danger me-2">Recusar</button>
                        <button name="aceitar_termo" class="btn-hc-green">Aceitar</button>
                    </form>
                <?php else: ?>
                    <a href="/Conta/Login" class="btn-hc-grey px-5">Voltar</a>
                <?php endif; ?>
            </div>
        </div>

    <?php endif; ?>
</div>

<?php if($m != 'home'): ?>
    <div class="hc-footer">
        <div><i class="fa-solid fa-hospital-user fa-2x align-middle me-2"></i> <b>ENFAS</b> <span class="ms-2" style="font-size:11px; opacity:0.8;">| GESTÃO DE IDENTIDADE E ACESSOS</span></div>
        <div style="font-size:12px;">© 2016-<?=date('Y')?> Todos os direitos reservados</div>
    </div>
<?php endif; ?>

<div id="modal_senha" style="display:none; position:fixed; top:0; left:0; width:100%; height:100%; background:rgba(0,0,0,0.6); z-index:3000; align-items:center; justify-content:center;">
    <div style="background:#fff; padding:30px; border-radius:4px; max-width:400px; width:100%; text-align:center; box-shadow: 0 5px 15px rgba(0,0,0,0.3);">
        <h5 style="color:#337ab7; border-bottom:1px solid #eee; padding-bottom:15px; margin-bottom:20px; font-weight:400;">Alterar Senha</h5>
        <form method="POST" action="/Conta/Perfil">
            <div class="hc-input-group mb-3"><input type="password" name="senha_atual" placeholder="Senha Atual" required><i class="fa-solid fa-lock"></i></div>
            <div class="hc-input-group mb-4"><input type="password" name="nova_senha" placeholder="Nova Senha" minlength="8" required><i class="fa-solid fa-key"></i></div>
            <div class="d-flex justify-content-between border-top pt-3 mt-2">
                <button type="button" onclick="document.getElementById('modal_senha').style.display='none'" class="btn-hc-grey" style="width:48%;">Cancelar</button>
                <button name="trocar_senha_interna" class="btn-hc-blue" style="width:48%;">Salvar</button>
            </div>
        </form>
    </div>
</div>

</body>
</html>