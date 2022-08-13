from dao.user import UserDAO
from service.auth import generate_password_hash


class UserService:
    def __init__(self, dao: UserDAO):
        self.dao = dao

    def get_one(self, rid):
        return self.dao.get_one(rid)

    def get_all(self):
        return self.dao.get_all()

    def get_by_username(self, username):
        return self.dao.get_by_username(username)

    def create(self, data):
        data['password'] = generate_password_hash(password=data['password'])
        return self.dao.create(data)

    def update(self, data):
        self.dao.update(data)
        return self.dao

    def delete(self, rid):
        self.dao.delete(rid)
