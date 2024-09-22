from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager
from flask_bcrypt import Bcrypt
import logging
import sys

# Instância do banco de dados
db = SQLAlchemy()

# Gerenciamento de login
login_manager = LoginManager()
login_manager.login_view = 'login'
login_manager.login_message_category = 'danger'

# Criptografia de senha
bcrypt = Bcrypt()

def create_app():
    # Configuração da aplicação
    app = Flask(__name__)
    app.config['SECRET_KEY'] = '45cf93c4d41348cd9980674ade9a7356'
    app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///site.db'
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False  # Para evitar o aviso de depreciação

    # Inicializar extensões
    db.init_app(app)
    login_manager.init_app(app)
    bcrypt.init_app(app)

    # Configuração de Logging
    syslog_handler = logging.StreamHandler(sys.stdout)
    syslog_handler.setLevel(logging.INFO)
    formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    syslog_handler.setFormatter(formatter)

    app.logger.addHandler(syslog_handler)
    app.logger.setLevel(logging.INFO)

    # Exemplo de log quando a aplicação é iniciada
    @app.before_first_request
    def before_first_request():
        app.logger.info('Aplicação iniciada e pronta para aceitar conexões.')

    # Log de autenticação
    @login_manager.user_loader
    def load_user(user_id):
        from taskmanager.models import User
        user = User.query.get(int(user_id))
        if user:
            app.logger.info(f'Usuário {user.username} autenticado com sucesso.')
        else:
            app.logger.warning(f'Tentativa de autenticação falhou para o ID {user_id}.')
        return user

    # Importar as rotas e registrá-las
    from taskmanager.routes import register_routes
    register_routes(app)

    return app
