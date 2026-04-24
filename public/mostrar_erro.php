<?php session_start(); $msg = $_SESSION['erro_login'] ?? "Falha"; ?>
<!DOCTYPE html>
<html lang="pt-BR">
<head>
    <meta charset="UTF-8"><title>Falha no Login</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
    <style>
        body { background: #0088b3; height: 100vh; display: flex; align-items: center; justify-content: center; font-family: sans-serif; }
        .error-modal { background: #fff; padding: 30px; border-radius: 8px; box-shadow: 0 10px 30px rgba(0,0,0,0.3); text-align: center; width: 400px; border-top: 5px solid #721c24; }
        .error-icon { color: #d32f2f; font-size: 50px; margin-bottom: 20px; }
    </style>
</head>
<body>
    <div class="error-modal">
        <i class="fa fa-times-circle error-icon"></i>
        <h3>Falha</h3>
        <p><?php echo $msg; ?></p>
        <button class="btn btn-danger w-100 p-2 mt-3" onclick="window.location.href='index.php'">TENTAR NOVAMENTE</button>
    </div>
</body>
</html>
