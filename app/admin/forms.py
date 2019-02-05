from flask import session
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, FileField, TextAreaField, SelectField, DateField, \
    SelectMultipleField, IntegerField
from wtforms.validators import DataRequired, ValidationError, EqualTo

from app.models import Admin


class LoginForm(FlaskForm):
    """
    管理员登录表单
    """
    account = StringField(label="账号：", validators=[DataRequired("请输入账号")], description="账号",
                          render_kw={"class": "form-control", "placeholder": "账号"})
    pwd = PasswordField(label="密码：", validators=[DataRequired("请输入密码")], description="密码",
                        render_kw={"class": "form-control", "placeholder": "密码"})
    submit = SubmitField(label="登录", render_kw={"class": "btn btn-primary btn-block btn-flat"})

    # 于views中post的方法之前执行
    def validate_account(self, field):
        account = field.data
        admin_num = Admin.query.filter_by(name=account).count()
        if admin_num == 0:
            raise ValidationError("账号不存在")


class TagForm(FlaskForm):
    """
    标签提交表单
    """
    name = StringField("标签名称", validators=[DataRequired("请输入标签名称")], description="标签",
                       render_kw={"class": "form-control", "id": "input_name", "placeholder": "请输入标签名称！"})
    submit = SubmitField(label="提交", render_kw={"class": "btn btn-primary"})


class MovieForm(FlaskForm):
    """
    电影表单
    """
    title = StringField("片名", validators=[DataRequired("请输入片名")], description="片名",
                        render_kw={"class": "form-control", "placeholder": "请输入片名！"})
    url = FileField("文件", validators=[DataRequired("请输入文件")], description="文件")
    info = TextAreaField("简介", validators=[DataRequired("请输入简介")], description="简介",
                         render_kw={"class": "form-control", "placeholder": "请输入简介！", "rows": 10})
    logo = FileField("封面", validators=[DataRequired("请输入封面")], description="封面")
    star = SelectField("星级", validators=[DataRequired("请输入星级")], description="星级", coerce=int,
                       choices=[(1, '1星'), (2, '2星'), (3, '3星'), (4, '4星'), (5, '5星')],
                       render_kw={"class": "form-control"})
    tag_id = SelectField("标签", validators=[DataRequired("请输入标签")], description="标签", coerce=int,
                         render_kw={"class": "form-control"})
    area = StringField("地区", validators=[DataRequired("请输入地区")], description="地区",
                       render_kw={"class": "form-control", "placeholder": "请输入地区！"})
    length = StringField("片长", validators=[DataRequired("请输入片长")], description="片长",
                         render_kw={"class": "form-control", "placeholder": "请输入片长！"})
    release_time = StringField("上映时间", validators=[DataRequired("请输入上映时间")], description="上映时间",
                               render_kw={"class": "form-control", "placeholder": "请输入上映时间！",
                                          "id": "input_release_time"})
    submit = SubmitField(label="提交", render_kw={"class": "btn btn-primary"})


class PrevueForm(FlaskForm):
    title = StringField("预告标题", validators=[DataRequired("请输入预告标题")], description="预告标题",
                        render_kw={"class": "form-control", "placeholder": "请输入预告标题！"})
    logo = FileField("预告封面", validators=[DataRequired("请输入预告封面")], description="预告封面",
                     render_kw={"class": "form-control", "placeholder": "请输入预告标题！"})
    submit = SubmitField(label="提交", render_kw={"class": "btn btn-primary"})


class PwdForm(FlaskForm):
    old_pwd = StringField("旧密码", validators=[DataRequired("请输入旧密码")], description="旧密码",
                          render_kw={"class": "form-control", "placeholder": "请输入旧密码！"})
    new_pwd = StringField("新密码", validators=[DataRequired("请输入新密码")], description="新密码",
                          render_kw={"class": "form-control", "placeholder": "请输入新密码！"})
    submit = SubmitField(label="提交", render_kw={"class": "btn btn-primary"})

    # 校验什么，对应参数field就是什么，field.data可取出该数据
    def validate_old_pwd(self, field):
        pwd = field.data
        name = session["admin"]
        admin = Admin.query.filter_by(name=name).first()
        if not admin.check_pwd(pwd):
            raise ValidationError("旧密码错误")


class AuthForm(FlaskForm):
    name = StringField("权限名称", validators=[DataRequired("请输入权限名称")], description="权限名称",
                       render_kw={"class": "form-control", "placeholder": "请输入权限名称！"})
    url = StringField("权限地址", validators=[DataRequired("请输入权限地址")], description="权限地址",
                      render_kw={"class": "form-control", "placeholder": "请输入权限地址！"})
    submit = SubmitField(label="提交", render_kw={"class": "btn btn-primary"})


class RoleForm(FlaskForm):
    name = StringField("角色名称", validators=[DataRequired("请输入角色名称")], description="角色名称",
                       render_kw={"class": "form-control", "placeholder": "请输入角色名称！"})
    auths = SelectMultipleField("操作权限", validators=[DataRequired("请选择操作权限")], description="操作权限", coerce=int,
                                render_kw={"class": "form-control"})
    submit = SubmitField(label="提交", render_kw={"class": "btn btn-primary"})


class AdminForm(FlaskForm):
    name = StringField(label="管理员名称", validators=[DataRequired("请输入管理员名称")], description="管理员名称",
                       render_kw={"class": "form-control", "placeholder": "请输入管理员名称"})
    pwd = PasswordField(label="管理员密码", validators=[DataRequired("请输入管理员密码")], description="管理员密码",
                        render_kw={"class": "form-control", "placeholder": "请输入管理员密码"})
    pwd2 = PasswordField(label="管理员重复密码", validators=[DataRequired("请重复输入管理员密码"), EqualTo("pwd", message="密码不一致")],
                         description="管理员重复密码",
                         render_kw={"class": "form-control", "placeholder": "请重复输入管理员密码"})
    role_id = SelectField(label="所属角色", validators=[DataRequired("请输入所属角色")], description="所属角色",coerce=int,
                          render_kw={"class": "form-control"})
    submit = SubmitField(label="登录", render_kw={"class": "btn btn-primary btn-block btn-flat"})
