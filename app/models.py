import time
from datetime import datetime

from werkzeug.security import generate_password_hash

from app import db


class User(db.Model):
    """
    用户
    """
    __tablename__ = "user"
    # __table_args__ = {'extend_existing': True}
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(10))
    pwd = db.Column(db.String(255))
    email = db.Column(db.String(50), unique=True)
    phone = db.Column(db.String(11), unique=True)
    info = db.Column(db.Text)
    face = db.Column(db.String(255), unique=True)
    addtime = db.Column(db.DateTime, index=True, default=datetime.now)
    uuid = db.Column(db.String(255), unique=True)
    userlogs = db.relationship("UserLog", backref="user")
    comments = db.relationship("Comment", backref="user")
    moviecols = db.relationship("MovieCol", backref="user")

    def __repr__(self):
        return self.name

    def check_pwd(self, pwd):
        from werkzeug.security import check_password_hash
        return check_password_hash(self.pwd, pwd)


class UserLog(db.Model):
    """
    用户登录日志
    """
    __tablename__ = "userlog"
    # __table_args__ = {'extend_existing': True}
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"))
    id = db.Column(db.Integer, primary_key=True)
    ip = db.Column(db.String(100))
    addtime = db.Column(db.DateTime, index=True, default=datetime.now)

    def __repr__(self):
        return self.id


class Tag(db.Model):
    """
    标签
    """
    __tablename__ = "tag"
    # __table_args__ = {'extend_existing': True}
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(16), unique=True)
    addtime = db.Column(db.DateTime, index=True, default=datetime.now)
    movies = db.relationship('Movie', backref="tag")

    def __repr__(self):
        return self.name


class Movie(db.Model):
    """
    电影
    """
    __tablename__ = "movie"
    # __table_args__ = {'extend_existing': True}
    tag_id = db.Column(db.Integer, db.ForeignKey('tag.id'))
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(255), unique=True)
    url = db.Column(db.String(255), unique=True)
    info = db.Column(db.Text)
    logo = db.Column(db.String(255), unique=True)
    star = db.Column(db.SmallInteger)
    playnum = db.Column(db.BigInteger, default=0)
    commentnum = db.Column(db.BigInteger, default=0)
    area = db.Column(db.String(255))
    release_time = db.Column(db.Date)
    length = db.Column(db.String(100))
    addtime = db.Column(db.DateTime, index=True, default=datetime.now)
    comments = db.relationship("Comment", backref="movie")
    moviecols = db.relationship("MovieCol", backref="movie")

    def __repr__(self):
        return self.title


class Prevue(db.Model):
    """
    预告
    """
    __tablename__ = "prevue"
    # __table_args__ = {'extend_existing': True}
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(255), unique=True)
    logo = db.Column(db.String(255), unique=True)
    addtime = db.Column(db.DateTime, index=True, default=datetime.now)

    def __repr__(self):
        return self.title


class Comment(db.Model):
    """
    评论
    """
    __tablename__ = "comment"
    # __table_args__ = {'extend_existing': True}
    movie_id = db.Column(db.Integer, db.ForeignKey("movie.id"))
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"))
    id = db.Column(db.Integer, primary_key=True)
    content = db.Column(db.Text)
    addtime = db.Column(db.DateTime, index=True, default=datetime.now)

    def __repr__(self):
        self.id


class MovieCol(db.Model):
    """
    收藏
    """
    __tablename__ = "moviecol"
    # __table_args__ = {'extend_existing': True}
    movie_id = db.Column(db.Integer, db.ForeignKey("movie.id"))
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"))
    id = db.Column(db.Integer, primary_key=True)
    addtime = db.Column(db.DateTime, index=True, default=datetime.now)

    def __repr__(self):
        self.id


class Auth(db.Model):
    """
    权限
    """
    __tablename__ = "auth"
    # __table_args__ = {'extend_existing': True}
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), unique=True)
    url = db.Column(db.String(255), unique=True)
    addtime = db.Column(db.DateTime, index=True, default=datetime.now)

    def __repr__(self):
        return self.name


class Role(db.Model):
    """
    角色
    """
    __tablename__ = "role"
    # __table_args__ = {'extend_existing': True}
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), unique=True)
    auths = db.Column(db.String(1024))
    addtime = db.Column(db.DateTime, index=True, default=datetime.now)
    admins = db.relationship("Admin", backref="role")

    def __repr__(self):
        return self.name


class Admin(db.Model):
    """
    管理员
    """
    __tablename__ = "admin"
    # __table_args__ = {'extend_existing': True}
    role_id = db.Column(db.Integer, db.ForeignKey("role.id"))
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(16), unique=True)
    pwd = db.Column(db.String(100))
    is_super = db.Column(db.SmallInteger)
    addtime = db.Column(db.DateTime, index=True, default=datetime.now)
    adminlogs = db.relationship("AdminLog", backref="admin")
    operatelogs = db.relationship("OperateLog", backref="admin")

    def __repr__(self):
        return self.name

    def check_pwd(self, pwd):
        from werkzeug.security import check_password_hash
        return check_password_hash(self.pwd, pwd)


class AdminLog(db.Model):
    """
    管理员登录日志
    """
    __tablename__ = "adminlog"
    # __table_args__ = {'extend_existing': True}
    admin_id = db.Column(db.Integer, db.ForeignKey("admin.id"))
    id = db.Column(db.Integer, primary_key=True)
    ip = db.Column(db.String(100))
    addtime = db.Column(db.DateTime, index=True, default=datetime.now)

    def __repr__(self):
        return self.id


class OperateLog(db.Model):
    """
    操作日志
    """
    __tablename__ = "operatelog"
    # __table_args__ = {'extend_existing': True}
    admin_id = db.Column(db.Integer, db.ForeignKey("admin.id"))
    id = db.Column(db.Integer, primary_key=True)
    ip = db.Column(db.String(100))
    reason = db.Column(db.String(500))
    addtime = db.Column(db.DateTime, index=True, default=datetime.now)

    def __repr__(self):
        return self.id


def create_tables():
    # db.drop_all()
    # db.create_all()
    # role = Role(name="superuser")
    # db.session.add(role)
    # db.session.commit()
    #
    # admin = Admin(role_id=role.id, name="admin", pwd=generate_password_hash("admin123"), is_super=1)
    # db.session.add(admin)
    # db.session.commit()

    # user1 = User(name="羊", pwd=generate_password_hash("1234"), email="1@qq.com", phone="18844631601", info="123123", face="1.png", uuid="12311")
    # user2 = User(name="候", pwd=generate_password_hash("1234"), email="2@qq.com", phone="18844631602", info="123123", face="2.jpg", uuid="12312")
    # user3 = User(name="鸡", pwd=generate_password_hash("1234"), email="3@qq.com", phone="18844631603", info="123123", face="3.png", uuid="12313")
    # user4 = User(name="狗", pwd=generate_password_hash("1234"), email="4@qq.com", phone="18844631604", info="123123", face="4.png", uuid="12314")
    #
    # db.session.add_all([user1, user2, user3, user4])
    # db.session.commit()

    # comment1 = Comment(movie_id=1, user_id=2, content="好看")
    # comment2 = Comment(movie_id=2, user_id=3, content="好棒")
    # comment3 = Comment(movie_id=1, user_id=4, content="很ok")
    # comment4 = Comment(movie_id=2, user_id=2, content="满意")
    #
    # moviecol1 = MovieCol(movie_id=1, user_id=2)
    # moviecol2 = MovieCol(movie_id=2, user_id=3)
    # moviecol3 = MovieCol(movie_id=2, user_id=4)
    # moviecol4 = MovieCol(movie_id=1, user_id=3)
    #
    # db.session.add_all([comment1, comment2, comment3, comment4, moviecol1, moviecol2, moviecol3, moviecol4])
    # db.session.commit()

    userlog1 = UserLog(user_id=1, ip="127.0.0.1")
    userlog2 = UserLog(user_id=2, ip="127.0.0.1")
    userlog3 = UserLog(user_id=3, ip="127.0.0.1")
    userlog4 = UserLog(user_id=4, ip="127.0.0.1")
    db.session.add_all([userlog1, userlog2, userlog3, userlog4])
    db.session.commit()

# create_tables()
