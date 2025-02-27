// static/script.js
document.addEventListener('DOMContentLoaded', function() {
    const loginForm = document.getElementById('loginForm');
    const googleLogin = document.getElementById('googleLogin');

    if (loginForm) {
      loginForm.addEventListener('submit', function(e) {
          e.preventDefault();
          const email = document.getElementById('email').value;
          const password = document.getElementById('password').value;

          // Requisição para o endpoint de login do backend
          fetch('/login', {
              method: 'POST',
              headers: {
                  'Content-Type': 'application/json'
              },
              body: JSON.stringify({ email, password })
          })
          .then(response => response.json())
          .then(data => {
              if (data.success) {
                  // Redireciona para o dashboard se o login for bem-sucedido.
                  window.location.href = '/dashboard';
              } else {
                  alert('Erro no login: ' + data.message);
              }
          })
          .catch(err => console.error('Erro:', err));
      });
    }

    if (googleLogin) {
      googleLogin.addEventListener('click', function() {
          // Redireciona para a rota de login via Google OAuth.
          window.location.href = '/login/google';
      });
    }
});
