<?php
session_start();
require_once '../config/database.php';

// Simula um atraso de 2 segundos para mostrar o loader chique
sleep(2);

$u = $_GET['user'] ?? ''; $p = $_GET['pass'] ?? ''; $erro = $_GET['error'] ?? '';

// Tenta logar de novo aqui so para ter certeza
$stmt = $conn->prepare("SELECT id FROM pre_registros WHERE username_criado = ? AND senha_criada = ? AND status = 'ativo'");
$stmt->bind_param("ss", $u, $p); $stmt->execute();
$res = $stmt->get_result()->fetch_assoc();

if ($res) {
    $_SESSION['auth_user'] = true;
    header("Location: dashboard.php"); exit;
} else {
    // Se falhar, vamos para a tela de erro falsa e depois voltamos para o login
    $_SESSION['erro_login'] = "Falha no login: $erro";
    header("Location: mostrar_erro.php"); exit;
}
?>
