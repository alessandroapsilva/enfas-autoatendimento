<!DOCTYPE html>
<html lang="pt-BR">
<head>
    <meta charset="UTF-8"><title>Um momento...</title>
    <style>
        body { background: #0088b3; height: 100vh; display: flex; align-items: center; justify-content: center; font-family: sans-serif; }
        .loading-box { background: rgba(0,0,0,0.7); padding: 40px; border-radius: 12px; text-align: center; color: white; width: 300px; box-shadow: 0 10px 30px rgba(0,0,0,0.5); border: 2px solid #005a96; }
        .loading-dots div { width: 10px; height: 10px; background-color: #fff; border-radius: 50%; display: inline-block; animation: loader 1.4s infinite ease-in-out; }
        .loading-dots .dot2 { animation-delay: -1.2s; } .loading-dots .dot3 { animation-delay: -1.0s; }
        @keyframes loader { 0%, 80%, 100% { transform: scale(0); } 40% { transform: scale(1); } }
    </style>
</head>
<body>
    <div class="loading-box">
        <img src="images/logo_enfas.png" style="max-width:180px; margin-bottom:20px;" onerror="this.src='https://via.placeholder.com/180x80?text=LOGO+ENFAS'">
        <h3>Um momento...</h3>
        <div class="loading-dots">
            <div class="dot1"></div> <div class="dot2"></div> <div class="dot3"></div>
        </div>
    </div>
</body>
</html>
