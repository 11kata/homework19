from flask import request
from flask_restx import Resource, Namespace

from dao.model.user import UserSchema
from implemented import user_service
from service.auth import generate_token, approve_token

auth_ns = Namespace('auth')


@auth_ns.route('/')
class AuthView(Resource):
    def post(self):
        data = request.json
        username = data.get('username')
        password = data.get('password')

        if not username or not password:
            return 'Нет пароля или логина', 400

        user = user_service.get_by_username(username=username)
        return generate_token(username=username,
                              password=password,
                              password_hash=user.password,
                              
                              is_refresh=False), 201

    def put(self):
        data = request.json
        if not data.get('refresh_token'):
            return '', 400
        return approve_token(data.get('refresh_token'), user_service=user_service), 200
