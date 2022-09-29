from telnetlib import AO
from flask import Flask
from dotenv import load_dotenv
import os

from flask_login import LoginManager
from src.model import db, login_manager
from src.route.auth_route import auth, mail
from flask_mail import Mail
from flask_jwt_extended import JWTManager

load_dotenv()

app = Flask(__name__)

app.register_blueprint(auth)


app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('SQLALCHEMY_DATABASE_URI')
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY')
app.config['JWT_SECRET_KEY'] = os.getenv('JWT_SECRET_KEY')
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = os.getenv('EMAIL_USER')
app.config['MAIL_PASSWORD'] = os.getenv('EMAIL_PASS')




jwt = JWTManager(app)
db.app=app
db.init_app(app)
login_manager.init_app(app)
app.config
mail.app = app
mail.init_app(app)

from src.route import auth_route
from src.route import post_route