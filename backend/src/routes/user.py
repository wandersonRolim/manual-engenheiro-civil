from flask import Blueprint, jsonify, request, current_app
from src.models.user import User, db
from datetime import datetime
import jwt
from functools import wraps
import re

user_bp = Blueprint('user', __name__)

def token_required(f):
    """Decorator para verificar se o token JWT é válido"""
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.headers.get('Authorization')
        if not token:
            return jsonify({'message': 'Token é obrigatório'}), 401
        
        try:
            if token.startswith('Bearer '):
                token = token[7:]
            data = jwt.decode(token, current_app.config['SECRET_KEY'], algorithms=['HS256'])
            current_user = User.query.get(data['user_id'])
            if not current_user or not current_user.has_valid_access():
                return jsonify({'message': 'Token inválido ou acesso expirado'}), 401
        except jwt.ExpiredSignatureError:
            return jsonify({'message': 'Token expirado'}), 401
        except jwt.InvalidTokenError:
            return jsonify({'message': 'Token inválido'}), 401
        
        return f(current_user, *args, **kwargs)
    return decorated

def admin_required(f):
    """Decorator para verificar se o usuário é admin"""
    @wraps(f)
    def decorated(current_user, *args, **kwargs):
        if not current_user.is_admin:
            return jsonify({'message': 'Acesso negado. Apenas administradores.'}), 403
        return f(current_user, *args, **kwargs)
    return decorated

def validate_email(email):
    """Valida formato do email"""
    pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    return re.match(pattern, email) is not None

def validate_whatsapp(whatsapp):
    """Valida formato do WhatsApp (apenas números)"""
    pattern = r'^\d{10,15}$'
    return re.match(pattern, whatsapp.replace(' ', '').replace('-', '').replace('(', '').replace(')', '')) is not None

@user_bp.route('/register', methods=['POST'])
def register():
    """Registro de novo usuário"""
    data = request.json
    
    # Validações
    if not data.get('email') or not data.get('password') or not data.get('whatsapp'):
        return jsonify({'message': 'Email, senha e WhatsApp são obrigatórios'}), 400
    
    if not validate_email(data['email']):
        return jsonify({'message': 'Email inválido'}), 400
    
    if len(data['password']) < 6:
        return jsonify({'message': 'Senha deve ter pelo menos 6 caracteres'}), 400
    
    whatsapp_clean = data['whatsapp'].replace(' ', '').replace('-', '').replace('(', '').replace(')', '')
    if not validate_whatsapp(whatsapp_clean):
        return jsonify({'message': 'WhatsApp inválido'}), 400
    
    # Verificar se email já existe
    if User.query.filter_by(email=data['email']).first():
        return jsonify({'message': 'Email já cadastrado'}), 400
    
    # Criar usuário
    user = User(
        email=data['email'],
        whatsapp=whatsapp_clean
    )
    user.set_password(data['password'])
    
    # Primeiro usuário é admin
    if User.query.count() == 0:
        user.is_admin = True
        user.extend_access(12)  # Admin tem 12 meses de acesso
    
    db.session.add(user)
    db.session.commit()
    
    return jsonify({
        'message': 'Usuário criado com sucesso',
        'user': user.to_dict()
    }), 201

@user_bp.route('/login', methods=['POST'])
def login():
    """Login do usuário"""
    data = request.json
    
    if not data.get('email') or not data.get('password'):
        return jsonify({'message': 'Email e senha são obrigatórios'}), 400
    
    user = User.query.filter_by(email=data['email']).first()
    
    if not user or not user.check_password(data['password']):
        return jsonify({'message': 'Email ou senha incorretos'}), 401
    
    if not user.has_valid_access():
        return jsonify({'message': 'Acesso expirado ou bloqueado. Entre em contato com o administrador.'}), 403
    
    # Atualizar último login
    user.last_login = datetime.utcnow()
    db.session.commit()
    
    # Gerar token
    token = user.generate_token(current_app.config['SECRET_KEY'])
    
    return jsonify({
        'message': 'Login realizado com sucesso',
        'token': token,
        'user': user.to_dict()
    })

@user_bp.route('/me', methods=['GET'])
@token_required
def get_current_user(current_user):
    """Obter dados do usuário atual"""
    return jsonify(current_user.to_dict())

@user_bp.route('/users', methods=['GET'])
@token_required
@admin_required
def get_users(current_user):
    """Listar todos os usuários (apenas admin)"""
    users = User.query.all()
    return jsonify([user.to_dict() for user in users])

@user_bp.route('/users/<int:user_id>/extend-access', methods=['POST'])
@token_required
@admin_required
def extend_user_access(current_user, user_id):
    """Estender acesso do usuário (apenas admin)"""
    user = User.query.get_or_404(user_id)
    data = request.json
    
    months = data.get('months', 1)
    if not isinstance(months, int) or months < 1 or months > 24:
        return jsonify({'message': 'Meses deve ser um número entre 1 e 24'}), 400
    
    user.extend_access(months)
    user.restore_access()  # Garantir que está ativo
    db.session.commit()
    
    return jsonify({
        'message': f'Acesso estendido por {months} meses',
        'user': user.to_dict()
    })

@user_bp.route('/users/<int:user_id>/revoke-access', methods=['POST'])
@token_required
@admin_required
def revoke_user_access(current_user, user_id):
    """Revogar acesso do usuário (apenas admin)"""
    user = User.query.get_or_404(user_id)
    
    if user.is_admin:
        return jsonify({'message': 'Não é possível revogar acesso de administrador'}), 400
    
    user.revoke_access()
    db.session.commit()
    
    return jsonify({
        'message': 'Acesso revogado',
        'user': user.to_dict()
    })

@user_bp.route('/users/<int:user_id>/restore-access', methods=['POST'])
@token_required
@admin_required
def restore_user_access(current_user, user_id):
    """Restaurar acesso do usuário (apenas admin)"""
    user = User.query.get_or_404(user_id)
    
    user.restore_access()
    db.session.commit()
    
    return jsonify({
        'message': 'Acesso restaurado',
        'user': user.to_dict()
    })

@user_bp.route('/users/<int:user_id>', methods=['DELETE'])
@token_required
@admin_required
def delete_user(current_user, user_id):
    """Deletar usuário (apenas admin)"""
    user = User.query.get_or_404(user_id)
    
    if user.is_admin:
        return jsonify({'message': 'Não é possível deletar administrador'}), 400
    
    db.session.delete(user)
    db.session.commit()
    
    return jsonify({'message': 'Usuário deletado com sucesso'})

@user_bp.route('/stats', methods=['GET'])
@token_required
@admin_required
def get_stats(current_user):
    """Estatísticas do sistema (apenas admin)"""
    total_users = User.query.count()
    active_users = User.query.filter_by(is_active=True).count()
    expired_users = User.query.filter(
        User.access_expires_at < datetime.utcnow(),
        User.is_active == True
    ).count()
    
    return jsonify({
        'total_users': total_users,
        'active_users': active_users,
        'expired_users': expired_users,
        'admin_users': User.query.filter_by(is_admin=True).count()
    })
