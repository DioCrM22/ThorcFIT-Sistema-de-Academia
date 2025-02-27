# app.py
from flask import Flask, request, jsonify, redirect, url_for, render_template, flash
from flask_bcrypt import Bcrypt
from flask_login import LoginManager, login_user, logout_user, login_required, current_user
from authlib.integrations.flask_client import OAuth
import os
from config import Config
from models import db, User
from werkzeug.utils import secure_filename

# Inicializa o Flask com as pastas de templates e arquivos estáticos.
app = Flask(__name__, template_folder='templates', static_folder='static')
app.config.from_object(Config)

# Configura a pasta para uploads de arquivos (ex.: fotos de perfil).
UPLOAD_FOLDER = os.path.join(os.getcwd(), 'static/uploads')
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

bcrypt = Bcrypt(app)
login_manager = LoginManager(app)
login_manager.login_view = 'index'
oauth = OAuth(app)

# Configuração do Google OAuth. Se não utilizar, essa parte pode ser removida.
google = oauth.register(
    name='google',
    client_id=app.config['GOOGLE_CLIENT_ID'],  # Personalize se necessário.
    client_secret=app.config['GOOGLE_CLIENT_SECRET'],  # Personalize se necessário.
    access_token_url='https://accounts.google.com/o/oauth2/token',
    authorize_url='https://accounts.google.com/o/oauth2/auth',
    api_base_url='https://www.googleapis.com/oauth2/v1/',
    client_kwargs={'scope': 'openid email profile'},
)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Cria as tabelas no banco na primeira requisição e garante que a pasta de uploads exista.
@app.before_first_request
def create_tables():
    db.create_all()
    if not os.path.exists(app.config['UPLOAD_FOLDER']):
        os.makedirs(app.config['UPLOAD_FOLDER'])

# Função para verificar se o arquivo enviado tem uma extensão permitida.
def allowed_file(filename):
    ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}  # Você pode adicionar ou remover extensões.
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

# Rota: Página principal (Login)
@app.route('/')
def index():
    return render_template('index.html')

# API Endpoint: Login (envia JSON)
@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    if not data:
        return jsonify(success=False, message="Dados não fornecidos."), 400

    email = data.get('email')
    password = data.get('password')

    if not email or not password:
        return jsonify(success=False, message="Email e senha são necessários."), 400

    user = User.query.filter_by(email=email).first()
    if user and user.password_hash and bcrypt.check_password_hash(user.password_hash, password):
        login_user(user)
        return jsonify(success=True)
    else:
        return jsonify(success=False, message="Credenciais inválidas."), 401

# Rota: Cadastro (Registro de novos usuários)
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        # Você pode alterar os nomes das variáveis (ex.: 'name' para 'nome').
        name = request.form.get('name')
        email = request.form.get('email')
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')

        if not email or not password or not confirm_password:
            flash("Por favor, preencha todos os campos.", "danger")
            return redirect(url_for('register'))
        
        if password != confirm_password:
            flash("As senhas não conferem.", "danger")
            return redirect(url_for('register'))
        
        existing_user = User.query.filter_by(email=email).first()
        if existing_user:
            flash("Email já cadastrado.", "danger")
            return redirect(url_for('register'))
        
        hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
        new_user = User(email=email, password_hash=hashed_password, name=name)
        db.session.add(new_user)
        db.session.commit()
        flash("Cadastro realizado com sucesso. Faça login.", "success")
        return redirect(url_for('index'))
    return render_template('register.html')

# Rota: Recuperação de senha (simulada)
@app.route('/forgot-password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        email = request.form.get('email')
        user = User.query.filter_by(email=email).first()
        if user:
            # Aqui você integraria com um sistema de envio de email.
            flash("Instruções para redefinir sua senha foram enviadas para seu e-mail.", "info")
        else:
            flash("Email não encontrado.", "danger")
        return redirect(url_for('forgot_password'))
    return render_template('forgot_password.html')

# Rota: Login com Google OAuth
@app.route('/login/google')
def login_google():
    redirect_uri = url_for('authorize', _external=True)
    return google.authorize_redirect(redirect_uri)

@app.route('/authorize')
def authorize():
    token = google.authorize_access_token()
    resp = google.get('userinfo')
    user_info = resp.json()
    email = user_info.get('email')
    google_id = user_info.get('id')
    name = user_info.get('name')

    user = User.query.filter_by(email=email).first()
    if not user:
        user = User(email=email, google_id=google_id, name=name)
        db.session.add(user)
        db.session.commit()
    login_user(user)
    return redirect(url_for('dashboard'))

# Rota: Dashboard – página inicial após login com uma aba de Perfil
@app.route('/dashboard')
@login_required
def dashboard():
    return render_template('home.html', user=current_user)

# Rota: Atualização do perfil (nome e foto)
@app.route('/update_profile', methods=['POST'])
@login_required
def update_profile():
    name = request.form.get('name')
    if 'profile_pic' in request.files:
        file = request.files['profile_pic']
        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            file.save(file_path)
            current_user.profile_pic = 'uploads/' + filename
    if name:
        current_user.name = name
    db.session.commit()
    flash("Perfil atualizado com sucesso.", "success")
    return redirect(url_for('dashboard'))

# Rota: Logout
@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))

if __name__ == '__main__':
    app.run(debug=True)
