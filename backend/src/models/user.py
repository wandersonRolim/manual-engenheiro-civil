from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, timedelta
import jwt

db = SQLAlchemy()

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    whatsapp = db.Column(db.String(20), nullable=False)
    is_admin = db.Column(db.Boolean, default=False)
    is_active = db.Column(db.Boolean, default=True)
    access_expires_at = db.Column(db.DateTime, nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    last_login = db.Column(db.DateTime, nullable=True)

    def __repr__(self):
        return f'<User {self.email}>'

    def set_password(self, password):
        """Define a senha do usuário com hash"""
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        """Verifica se a senha está correta"""
        return check_password_hash(self.password_hash, password)

    def has_valid_access(self):
        """Verifica se o usuário tem acesso válido"""
        if not self.is_active:
            return False
        if self.access_expires_at and self.access_expires_at < datetime.utcnow():
            return False
        return True

    def extend_access(self, months):
        """Estende o acesso do usuário por X meses"""
        if self.access_expires_at and self.access_expires_at > datetime.utcnow():
            # Se ainda tem acesso válido, estende a partir da data atual de expiração
            self.access_expires_at = self.access_expires_at + timedelta(days=30 * months)
        else:
            # Se não tem acesso ou expirou, estende a partir de agora
            self.access_expires_at = datetime.utcnow() + timedelta(days=30 * months)

    def revoke_access(self):
        """Remove o acesso do usuário"""
        self.is_active = False

    def restore_access(self):
        """Restaura o acesso do usuário"""
        self.is_active = True

    def generate_token(self, secret_key):
        """Gera um token JWT para o usuário"""
        payload = {
            'user_id': self.id,
            'email': self.email,
            'is_admin': self.is_admin,
            'exp': datetime.utcnow() + timedelta(hours=24)
        }
        return jwt.encode(payload, secret_key, algorithm='HS256')

    def to_dict(self):
        return {
            'id': self.id,
            'email': self.email,
            'whatsapp': self.whatsapp,
            'is_admin': self.is_admin,
            'is_active': self.is_active,
            'access_expires_at': self.access_expires_at.isoformat() if self.access_expires_at else None,
            'created_at': self.created_at.isoformat(),
            'last_login': self.last_login.isoformat() if self.last_login else None,
            'has_valid_access': self.has_valid_access()
        }
