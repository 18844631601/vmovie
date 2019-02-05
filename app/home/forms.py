from flask import session
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, FileField, TextAreaField
from wtforms.fields.html5 import EmailField
from wtforms.validators import DataRequired, EqualTo, Regexp, Email, ValidationError

from app.models import User


class RegisterForm(FlaskForm):
    name = StringField(label="昵称", validators=[DataRequired("请输入昵称")], description="昵称",
                       render_kw={"class": "form-control input-lg", "placeholder": "昵称", "autofocus": "autofocus"})
    pwd = PasswordField(label="密码", validators=[DataRequired("请输入密码")], description="密码",
                        render_kw={"class": "form-control input-lg", "placeholder": "密码"})
    pwd2 = PasswordField(label="确认密码", validators=[DataRequired("请输入确认密码"), EqualTo("pwd", message="密码不一致")],
                         description="确认密码",
                         render_kw={"class": "form-control input-lg", "placeholder": "确认密码"})
    email = EmailField(label="邮箱", validators=[DataRequired("请输入邮箱"), Email("邮箱格式不正确")], description="邮箱",
                       render_kw={"class": "form-control input-lg", "placeholder": "邮箱", "autofocus": "autofocus"})
    phone = StringField(label="手机号码",
                        validators=[DataRequired("请输入手机号码"), Regexp(r"^1[34578]\d{9}$", message="手机号码格式不正确")],
                        description="手机号码",
                        render_kw={"class": "form-control input-lg", "placeholder": "手机号码", "autofocus": "autofocus"})
    submit = SubmitField(label="注册", render_kw={"class": "btn btn-lg btn-success btn-block"})

    def validate_name(self, field):
        name = field.data
        user_count = User.query.filter_by(name=name).count()
        if user_count == 1:
            raise ValidationError("昵称已存在")

    def validate_email(self, field):
        email = field.data
        user_count = User.query.filter_by(email=email).count()
        if user_count == 1:
            raise ValidationError("邮箱已存在")

    def validate_phone(self, field):
        phone = field.data
        user_count = User.query.filter_by(phone=phone).count()
        if user_count == 1:
            raise ValidationError("手机号码已存在")


class LoginForm(FlaskForm):
    contact = StringField(label="用户名/邮箱/手机号码", validators=[DataRequired("请输入用户名/邮箱/手机号码")], description="用户名/邮箱/手机号码",
                          render_kw={"class": "form-control input-lg", "placeholder": "用户名/邮箱/手机号码",
                                     "autofocus": "autofocus"})
    pwd = PasswordField(label="密码", validators=[DataRequired("请输入密码")], description="密码",
                        render_kw={"class": "form-control input-lg", "placeholder": "密码"})
    submit = SubmitField(label="登录", render_kw={"class": "btn btn-lg btn-success btn-block"})


class UserForm(FlaskForm):
    name = StringField(label="昵称", validators=[DataRequired("请输入昵称")], description="昵称",
                       render_kw={"class": "form-control", "placeholder": "昵称", "autofocus": "autofocus"})
    email = EmailField(label="邮箱", validators=[DataRequired("请输入邮箱"), Email("邮箱格式不正确")], description="邮箱",
                       render_kw={"class": "form-control", "placeholder": "邮箱", "autofocus": "autofocus"})
    phone = StringField(label="手机号码",
                        validators=[DataRequired("请输入手机号码"), Regexp(r"^1[34578]\d{9}$", message="手机号码格式不正确")],
                        description="手机号码",
                        render_kw={"class": "form-control", "placeholder": "手机号码", "autofocus": "autofocus"})
    face = FileField(label="头像", description="头像")
    info = TextAreaField(label="个人简介", description="个人简介",
                         render_kw={"class": "form-control", "placeholder": "介绍一下自己吧", "rows": "10"})
    submit = SubmitField(label="保存修改", render_kw={"class": "btn btn-lg btn-success"})

    def validate_name(self, field):
        name = field.data
        user_count = User.query.filter_by(name=name).count()
        if name != session["user"] and user_count == 1:
            raise ValidationError("昵称已存在")

    def validate_email(self, field):
        email = field.data
        user = User.query.get(session["user_id"])
        user_count = User.query.filter_by(email=email).count()
        if email != user.email and user_count == 1:
            raise ValidationError("邮箱已存在")

    def validate_phone(self, field):
        phone = field.data
        user = User.query.get(session["user_id"])
        user_count = User.query.filter_by(phone=phone).count()
        if phone != user.phone and user_count == 1:
            raise ValidationError("手机号码已存在")


class PwdForm(FlaskForm):
    old_pwd = StringField("旧密码", validators=[DataRequired("请输入旧密码")], description="旧密码",
                          render_kw={"class": "form-control", "placeholder": "请输入旧密码！"})
    new_pwd = StringField("新密码", validators=[DataRequired("请输入新密码")], description="新密码",
                          render_kw={"class": "form-control", "placeholder": "请输入新密码！"})
    submit = SubmitField(label="提交", render_kw={"class": "btn btn-primary"})

    # 校验什么，对应参数field就是什么，field.data可取出该数据
    def validate_old_pwd(self, field):
        pwd = field.data
        user = User.query.filter_by(id=session["user_id"]).first()
        if not user.check_pwd(pwd):
            raise ValidationError("旧密码错误")


class CommentForm(FlaskForm):
    content = TextAreaField("内容", validators=[DataRequired("请输入评论内容")], description="内容",
                            render_kw={"placeholder": "留下你的观后感吧！", "id": "input_content"})
    submit = SubmitField(label="提交评论", render_kw={"class": "btn btn-success", "id": "btn-sub"})
