# models.py
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin

db = SQLAlchemy()

class User(UserMixin, db.Model):
    __tablename__ = 'users'  # Nome da tabela no banco de dados. Você pode mudar se desejar.
    
    # id: chave primária, não deve ser alterada.
    id = db.Column(db.Integer, primary_key=True)
    
    # email: email do usuário (único). Pode ser renomeado para 'usuario_email', se preferir.
    email = db.Column(db.String(150), unique=True, nullable=False)
    
    # name: nome do usuário. Você pode trocar para 'nome'.
    name = db.Column(db.String(150), nullable=True)
    
    # password_hash: armazena o hash da senha, não a senha em texto puro.
    password_hash = db.Column(db.String(128))
    
    # google_id: armazena o ID do Google se o login via OAuth for usado.
    google_id = db.Column(db.String(150), unique=True, nullable=True)
    
    # profile_pic: armazena o caminho para a foto de perfil.
    # Você pode renomear para 'foto_perfil'.
    profile_pic = db.Column(db.String(150), nullable=True)

    def __repr__(self):
        return f'<User {self.email}>'
