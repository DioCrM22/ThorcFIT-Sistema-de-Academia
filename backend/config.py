# config.py
import os

class Config:
    # SECRET_KEY: usada para sessões e criptografia.
    # Você pode trocar 'minha_chave_secreta' por qualquer string complexa de sua preferência.
    SECRET_KEY = os.environ.get('SECRET_KEY') or 'minha_chave_secreta'
    
    # SQLALCHEMY_DATABASE_URI: string de conexão com o PostgreSQL.
    # Substitua 'usuario', 'senha', 'localhost' e 'cartoon_login' pelos seus dados.
    SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL') or 'postgresql://usuario:senha@localhost/cartoon_login'
    
    # Desativa notificações de modificações no SQLAlchemy (melhora a performance).
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    
    # Credenciais do Google OAuth (se utilizar login via Google).
    GOOGLE_CLIENT_ID = os.environ.get('GOOGLE_CLIENT_ID') or 'sua_google_client_id'
    GOOGLE_CLIENT_SECRET = os.environ.get('GOOGLE_CLIENT_SECRET') or 'sua_google_client_secret'
    
    # Permite o OAuth sem HTTPS em desenvolvimento. Em produção, use HTTPS.
    OAUTHLIB_INSECURE_TRANSPORT = os.environ.get('OAUTHLIB_INSECURE_TRANSPORT') or '1'
