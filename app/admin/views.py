import os
import uuid
from datetime import datetime
from functools import wraps

from flask import render_template, url_for, redirect, flash, session, request, abort
from werkzeug.security import generate_password_hash
from werkzeug.utils import secure_filename

from app import db, app
from app.admin.forms import LoginForm, TagForm, MovieForm, PrevueForm, PwdForm, AuthForm, RoleForm, AdminForm
from app.models import Admin, Tag, Movie, Prevue, User, Comment, MovieCol, OperateLog, AdminLog, UserLog, Auth, Role
from . import admin


@admin.context_processor
def tpl_extra():
    """
    上下文处理器:dict()封装变量返回出去，使得变量全局可用
    :return:
    """
    data = dict(
        online_time=datetime.now().strftime("%Y-%m-%d")
    )
    return data


def admin_login_req(f):
    """
    登录装饰器
    :param f:
    :return:
    """

    @wraps(f)
    def decorated_function(*args, **kwargs):
        if session.get("admin") is None:
            return redirect(url_for("admin.login", next=request.url))
        return f(*args, **kwargs)

    return decorated_function


def admin_auth(f):
    """
    管理员访问权限控制装饰器
    :param f:
    :return:
    """

    @wraps(f)
    def decorated_function(*args, **kwargs):
        admin = Admin.query.join(
            Role
        ).filter(
            Role.id == Admin.role_id
        ).first()
        auths = admin.role.auths
        auths = list(map(lambda v: int(v), auths.split(",")))
        auth_list = Auth.query.all()
        urls = ["/admin"+val.url for v in auths for val in auth_list if v == val.id]
        rule = request.url_rule
        # if str(rule) not in urls:
        #     abort(404)
        return f(*args, **kwargs)

    return decorated_function


@admin.route("/")
@admin_login_req
@admin_auth
def index():
    return render_template("admin/index.html")


@admin.route("/login/", methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if request.method == "GET":
        form.account.flags.required = False
        form.pwd.flags.required = False
    if form.validate_on_submit():
        data = form.data
        admin = Admin.query.filter_by(name=data["account"]).first()
        if not admin.check_pwd(data["pwd"]):
            flash("账号或者密码错误", "error")
            return redirect(url_for("admin.login"))
        session["admin"] = data["account"]
        session["admin_id"] = admin.id
        adminlog = AdminLog(
            admin_id=admin.id,
            ip=request.remote_addr
        )
        db.session.add(adminlog)
        db.session.commit()
        return redirect(request.args.get("next") or url_for("admin.index"))
    return render_template("admin/login.html", form=form)


@admin.route("/logout/")
@admin_login_req
def logout():
    session.pop("admin", None)
    session.pop("admin_id", None)
    return redirect(url_for("admin.login"))


@admin.route("/pwd/", methods=['GET', 'POST'])
@admin_login_req
def pwd():
    form = PwdForm()
    if request.method == "GET":
        form.old_pwd.flags.required = False
        form.new_pwd.flags.required = False
    if form.validate_on_submit():
        data = form.data
        try:
            admin = Admin.query.filter_by(name=session['admin']).first()
            admin.pwd = generate_password_hash(data['new_pwd'])
            db.session.add(admin)
            db.session.commit()
            flash("密码修改成功，请重新登录", category="ok")
            return redirect(url_for("admin.logout"))
        except Exception as e:
            print(e)
            flash("密码修改失败", category="error")
            db.session.rollback()
    return render_template("admin/pwd.html", form=form)


@admin.route("/tag/add/", methods=['GET', 'POST'])
@admin_login_req
@admin_auth
def tag_add():
    form = TagForm()
    if request.method == "GET":
        form.name.flags.required = False
    if form.validate_on_submit():
        data = form.data
        tag_count = Tag.query.filter_by(name=data["name"]).count()
        if tag_count == 1:
            flash("标签已存在", category="error")
        else:
            operatelog = OperateLog(
                admin_id=session["admin_id"],
                ip=request.remote_addr,
                reason="添加标签：{}".format(data["name"])
            )
            try:
                db.session.add(Tag(name=data["name"]))
                db.session.add(operatelog)
                db.session.commit()
                flash("标签添加成功", category="ok")
            except Exception as e:
                print(e)
                flash("标签添加失败", category="error")
                db.session.rollback()
    return render_template("admin/tag_add.html", form=form)


@admin.route("/tag/edit/<int:id>/", methods=['GET', 'POST'])
@admin_login_req
@admin_auth
def tag_edit(id=None):
    form = TagForm()
    if request.method == "GET":
        form.name.flags.required = False
    tag = Tag.query.get_or_404(id)
    if form.validate_on_submit():
        data = form.data
        tag_count = Tag.query.filter_by(name=data["name"]).count()
        if tag.name != data["name"] and tag_count == 1:
            flash("标签已存在", category="error")
        else:
            try:
                tag.name = data["name"]
                db.session.add(tag)
                db.session.commit()
                flash("标签修改成功", category="ok")
            except Exception as e:
                print(e)
                flash("标签修改失败", category="error")
                db.session.rollback()
    return render_template("admin/tag_edit.html", form=form, tag=tag)


@admin.route("/tag/delete/<int:id>/", methods=['GET'])
@admin_login_req
@admin_auth
def tag_delete(id=None):
    try:
        tag = Tag.query.filter_by(id=id).first_or_404()
        db.session.delete(tag)
        db.session.commit()
        flash("标签删除成功", "ok")
    except Exception as e:
        print(e)
        flash("标签删除失败", "error")
        db.session.rollback()
    return redirect(url_for("admin.tag_list"))


@admin.route("/tag/list/<int:page>/", methods=['GET'])
@admin.route("/tag/list/", methods=['GET'])
@admin_login_req
@admin_auth
def tag_list(page=1):
    page_data = Tag.query.order_by(Tag.addtime.desc()).paginate(page=page, per_page=10)  # Tag.addtime.desc()
    return render_template("admin/tag_list.html", page_data=page_data)


def change_filename(filename):
    fileinfo = os.path.splitext(filename)
    filename = datetime.now().strftime("%Y%m%d%H%M%S") + uuid.uuid4().hex + fileinfo[-1]
    return filename


@admin.route("/movie/add/", methods=["GET", "POST"])
@admin_login_req
@admin_auth
def movie_add():
    form = MovieForm()
    form.tag_id.choices = [(v.id, v.name) for v in Tag.query.all()]
    if request.method == "GET":
        form.title.flags.required = False
        form.url.flags.required = False
        form.info.flags.required = False
        form.logo.flags.required = False
        form.star.flags.required = False
        form.tag_id.flags.required = False
        form.area.flags.required = False
        form.length.flags.required = False
        form.release_time.flags.required = False
    if form.validate_on_submit():
        data = form.data
        movie_count = Movie.query.filter_by(title=data["title"]).count()
        if movie_count == 1:
            flash("电影已存在", category="error")
        else:
            file_url = secure_filename(form.url.data.filename)
            file_logo = secure_filename(form.logo.data.filename)
            if not os.path.exists(app.config["UP_DIR"]):
                os.makedirs(app.config["UP_DIR"])
                os.chmod(app.config["UP_DIR"], "rw")
            url = change_filename(file_url)
            logo = change_filename(file_logo)
            form.url.data.save(app.config["UP_DIR"] + url)
            form.logo.data.save(app.config["UP_DIR"] + logo)
            movie = Movie(
                tag_id=int(data["tag_id"]),
                title=data["title"],
                url=url,
                info=data["info"],
                logo=logo,
                star=int(data["star"]),
                area=data["area"],
                release_time=data["release_time"],
                length=data["length"]
            )
            try:
                db.session.add(movie)
                db.session.commit()
                flash("电影添加成功", "ok")
            except Exception as e:
                print(e)
                flash("电影添加失败", "error")
                db.session.rollback()
    return render_template("admin/movie_add.html", form=form)


@admin.route("/movie/list/<int:page>/", methods=["GET"])
@admin.route("/movie/list/", methods=["GET"])
@admin_login_req
@admin_auth
def movie_list(page=1):
    page_data = Movie.query.join(
        Tag
    ).filter(
        Tag.id == Movie.tag_id
    ).order_by(
        Movie.addtime.desc()
    ).paginate(
        page=page,
        per_page=10
    )
    return render_template("admin/movie_list.html", page_data=page_data)


@admin.route("/movie/delete/<int:id>/", methods=['GET'])
@admin_login_req
@admin_auth
def movie_delete(id=None):
    try:
        movie = Movie.query.get_or_404(id)  # 报错会被捕捉
        db.session.delete(movie)
        db.session.commit()
        flash("电影删除成功", "ok")
    except Exception as e:
        print(e)
        flash("电影删除失败", "error")
        db.session.rollback()
    return redirect(url_for("admin.movie_list"))


@admin.route("/movie/edit/<int:id>/", methods=['GET', 'POST'])
@admin_login_req
@admin_auth
def movie_edit(id=None):
    form = MovieForm()
    form.tag_id.choices = [(v.id, v.name) for v in Tag.query.all()]
    movie = Movie.query.get_or_404(id)
    if request.method == "GET":
        form.title.flags.required = False
        form.url.flags.required = False
        form.info.flags.required = False
        form.logo.flags.required = False
        form.star.flags.required = False
        form.tag_id.flags.required = False
        form.area.flags.required = False
        form.length.flags.required = False
        form.info.data = movie.info
        form.tag_id.data = movie.tag_id
        form.star.data = movie.star
    form.url.validators = []
    form.logo.validators = []
    if form.validate_on_submit():
        data = form.data
        movie_count = Movie.query.filter_by(title=data["title"]).count()  # title是唯一unique
        if movie.title != data["title"] and movie_count == 1:
            flash("电影已存在", category="error")
        else:
            if not os.path.exists(app.config["UP_DIR"]):
                os.makedirs(app.config["UP_DIR"])
                os.chmod(app.config["UP_DIR"], "rw")
            if form.url.data != '':
                file_url = secure_filename(form.url.data.filename)
                movie.url = change_filename(file_url)
                form.url.data.save(app.config["UP_DIR"] + movie.url)
            if form.logo.data != '':
                file_logo = secure_filename(form.logo.data.filename)
                movie.logo = change_filename(file_logo)
                form.logo.data.save(app.config["UP_DIR"] + movie.logo)
            try:
                movie.title = data["title"]
                movie.info = data['info']
                movie.tag_id = data["tag_id"]
                movie.star = data["star"]
                movie.area = data["area"]
                movie.length = data["length"]
                movie.release_time = data["release_time"]
                db.session.add(movie)
                db.session.commit()
                flash("电影修改成功", category="ok")
            except Exception as e:
                print(e)
                flash("电影修改失败", category="error")
                db.session.rollback()
    return render_template("admin/movie_edit.html", form=form, movie=movie)


@admin.route("/prevue/add/", methods=['GET', 'POST'])
@admin_login_req
@admin_auth
def prevue_add():
    form = PrevueForm()
    if request.method == "GET":
        form.title.flags.required = False
        form.logo.flags.required = False
    if form.validate_on_submit():
        data = form.data
        prevue_count = Prevue.query.filter_by(title=data["title"]).count()
        if prevue_count == 1:
            flash("预告已存在", "error")
        else:
            if not os.path.exists(app.config["UP_DIR"]):
                os.makedirs(app.config["UP_DIR"])
                os.chmod(app.config["UP_DIR"], "rw")
            file_logo = secure_filename(form.logo.data.filename)
            logo = change_filename(file_logo)
            form.logo.data.save(app.config["UP_DIR"] + logo)
            prevue = Prevue(
                title=data["title"],
                logo=logo
            )
            try:
                db.session.add(prevue)
                db.session.commit()
                flash("预告添加成功", "ok")
            except Exception as e:
                print(e)
                flash("预告添加失败", "error")
                db.session.rollback()
    return render_template("admin/prevue_add.html", form=form)


@admin.route("/prevue/list/<int:page>/", methods=['GET'])
@admin.route("/prevue/list/", methods=['GET'])
@admin_login_req
@admin_auth
def prevue_list(page=1):
    page_data = Prevue.query.order_by(Prevue.addtime.desc()).paginate(page=page, per_page=10)
    return render_template("admin/prevue_list.html", page_data=page_data)


@admin.route("/prevue/delete/<int:id>/", methods=['GET'])
@admin_login_req
@admin_auth
def prevue_delete(id=None):
    try:
        prevue = Prevue.query.get_or_404(id)  # 报错会被捕捉
        db.session.delete(prevue)
        db.session.commit()
        flash("预告删除成功", "ok")
    except Exception as e:
        print(e)
        flash("预告删除失败", "error")
        db.session.rollback()
    return redirect(url_for("admin.prevue_list"))


@admin.route("/prevue/edit/<int:id>/", methods=['GET', 'POST'])
@admin_login_req
@admin_auth
def prevue_edit(id=None):
    form = PrevueForm()
    prevue = Prevue.query.get_or_404(id)
    if request.method == "GET":
        form.title.flags.required = False
        form.logo.flags.required = False
        form.title.data = prevue.title
    form.logo.validators = []
    if form.validate_on_submit():
        data = form.data
        prevue_count = Prevue.query.filter_by(title=data["title"]).count()  # title是唯一unique
        if prevue.title != data["title"] and prevue_count == 1:
            flash("预告已存在", category="error")
        else:
            if not os.path.exists(app.config["UP_DIR"]):
                os.makedirs(app.config["UP_DIR"])
                os.chmod(app.config["UP_DIR"], "rw")
            if form.logo.data != '':
                file_logo = secure_filename(form.logo.data.filename)
                prevue.logo = change_filename(file_logo)
                form.logo.data.save(app.config["UP_DIR"] + prevue.logo)
            try:
                prevue.title = data["title"]
                db.session.add(prevue)
                db.session.commit()
                flash("预告修改成功", category="ok")
            except Exception as e:
                print(e)
                flash("预告修改失败", category="error")
                db.session.rollback()
    return render_template("admin/prevue_edit.html", form=form, prevue=prevue)


@admin.route("/user/list/<int:page>/", methods=['GET'])
@admin.route("/user/list/", methods=['GET'])
@admin_login_req
@admin_auth
def user_list(page=1):
    page_data = User.query.order_by(User.addtime.desc()).paginate(page=page, per_page=10)
    return render_template("admin/user_list.html", page_data=page_data)


@admin.route("/user/view/<int:id>/", methods=['GET'])
@admin_login_req
@admin_auth
def user_view(id=None):
    user = User.query.get_or_404(id)
    return render_template("admin/user_view.html", user=user)


@admin.route("/user/delete/<int:id>/", methods=['GET'])
@admin_login_req
@admin_auth
def user_delete(id=None):
    try:
        user = User.query.get_or_404(id)  # 报错会被捕捉
        db.session.delete(user)
        db.session.commit()
        flash("会员删除成功", "ok")
    except Exception as e:
        print(e)
        flash("会员删除失败", "error")
        db.session.rollback()
    return redirect(url_for("admin.user_list"))


@admin.route("/comment/list/<int:page>/", methods=['GET'])
@admin.route("/comment/list/", methods=['GET'])
@admin_login_req
@admin_auth
def comment_list(page=1):
    page_data = Comment.query.join(
        Movie
    ).join(
        User
    ).filter(
        Movie.id == Comment.movie_id,
        User.id == Comment.user_id
    ).order_by(
        Comment.addtime.desc()
    ).paginate(
        page=page,
        per_page=10
    )
    return render_template("admin/comment_list.html", page_data=page_data)


@admin.route("/comment/delete/<int:id>/", methods=['GET'])
@admin_login_req
@admin_auth
def comment_delete(id=None):
    try:
        comment = Comment.query.get_or_404(id)  # 报错会被捕捉
        db.session.delete(comment)
        db.session.commit()
        flash("评论删除成功", "ok")
    except Exception as e:
        print(e)
        flash("评论删除失败", "error")
        db.session.rollback()
    return redirect(url_for("admin.comment_list"))


@admin.route("/moviecol/list/<int:page>/", methods=['GET'])
@admin.route("/moviecol/list/", methods=['GET'])
@admin_login_req
@admin_auth
def moviecol_list(page=1):
    page_data = MovieCol.query.join(
        Movie
    ).join(
        User
    ).filter(
        Movie.id == MovieCol.movie_id,
        User.id == MovieCol.user_id
    ).order_by(
        MovieCol.addtime.desc()
    ).paginate(
        page=page,
        per_page=10
    )
    return render_template("admin/moviecol_list.html", page_data=page_data)


@admin.route("/moviecol/delete/<int:id>/", methods=['GET'])
@admin_login_req
@admin_auth
def moviecol_delete(id=None):
    try:
        moviecol = MovieCol.query.get_or_404(id)  # 报错会被捕捉
        db.session.delete(moviecol)
        db.session.commit()
        flash("收藏删除成功", "ok")
    except Exception as e:
        print(e)
        flash("收藏删除失败", "error")
        db.session.rollback()
    return redirect(url_for("admin.moviecol_list"))


@admin.route("/operatelog/list/<int:page>/", methods=["GET"])
@admin.route("/operatelog/list/", methods=["GET"])
@admin_login_req
@admin_auth
def operatelog_list(page=1):
    page_data = OperateLog.query.join(
        Admin
    ).filter(
        Admin.id == OperateLog.admin_id
    ).order_by(
        OperateLog.addtime.desc()
    ).paginate(
        page=page, per_page=10
    )
    return render_template("admin/operatelog_list.html", page_data=page_data)


@admin.route("/adminloginlog/list/<int:page>/", methods=["GET"])
@admin.route("/adminloginlog/list/", methods=["GET"])
@admin_login_req
@admin_auth
def adminloginlog_list(page=1):
    page_data = AdminLog.query.join(
        Admin
    ).filter(
        Admin.id == AdminLog.admin_id
    ).order_by(
        AdminLog.addtime.desc()
    ).paginate(
        page=page, per_page=10
    )
    return render_template("admin/adminloginlog_list.html", page_data=page_data)


@admin.route("/userloginlog/list/<int:page>/", methods=["GET"])
@admin.route("/userloginlog/list/", methods=["GET"])
@admin_login_req
@admin_auth
def userloginlog_list(page=1):
    page_data = UserLog.query.join(
        User
    ).filter(
        User.id == UserLog.user_id
    ).order_by(
        UserLog.addtime.desc()
    ).paginate(
        page=page, per_page=10
    )
    return render_template("admin/userloginlog_list.html", page_data=page_data)


@admin.route("/auth/add/", methods=["GET", "POST"])
@admin_login_req
@admin_auth
def auth_add():
    form = AuthForm()
    if request.method == "GET":
        form.name.flags.required = False
        form.url.flags.required = False
    if form.validate_on_submit():
        data = form.data
        auth_count = Auth.query.filter_by(name=data["name"]).count()
        if auth_count == 1:
            flash("权限已存在", category="error")
        else:
            auth = Auth(
                name=data["name"],
                url=data["url"]
            )
            operatelog = OperateLog(
                admin_id=session["admin_id"],
                ip=request.remote_addr,
                reason="添加权限：{}".format(data["name"])
            )
            try:
                db.session.add(auth)
                db.session.add(operatelog)
                db.session.commit()
                flash("权限添加成功", category="ok")
            except Exception as e:
                print(e)
                flash("权限添加失败", category="error")
                db.session.rollback()
    return render_template("admin/auth_add.html", form=form)


@admin.route("/auth/list/<int:page>", methods=['GET'])
@admin.route("/auth/list/", methods=['GET'])
@admin_login_req
@admin_auth
def auth_list(page=1):
    page_data = Auth.query.order_by(Auth.addtime.desc()).paginate(page=page, per_page=10)
    return render_template("admin/auth_list.html", page_data=page_data)


@admin.route("/auth/edit/<int:id>/", methods=['GET', 'POST'])
@admin_login_req
@admin_auth
def auth_edit(id=None):
    form = AuthForm()
    if request.method == "GET":
        form.name.flags.required = False
        form.url.flags.required = False
    auth = Auth.query.get_or_404(id)
    if form.validate_on_submit():
        data = form.data
        auth_count = Auth.query.filter_by(name=data["name"]).count()
        if auth.name != data["name"] and auth_count == 1:
            flash("权限已存在", category="error")
        else:
            auth.name = data["name"]
            auth.url = data["url"]
            operatelog = OperateLog(
                admin_id=session["admin_id"],
                ip=request.remote_addr,
                reason="修改权限：{}".format(data["name"])
            )
            try:
                db.session.add(auth)
                db.session.add(operatelog)
                db.session.commit()
                flash("权限修改成功", category="ok")
            except Exception as e:
                print(e)
                flash("权限修改失败", category="error")
                db.session.rollback()
    return render_template("admin/auth_edit.html", form=form, auth=auth)


@admin.route("/auth/delete/<int:id>/", methods=['GET'])
@admin_login_req
@admin_auth
def auth_delete(id=None):
    try:
        auth = Auth.query.filter_by(id=id).first_or_404()
        db.session.delete(auth)
        auth = Auth.query.get_or_404(id)
        operatelog = OperateLog(
            admin_id=session["admin_id"],
            ip=request.remote_addr,
            reason="删除权限：{}".format(auth.name)
        )
        db.session.add(operatelog)
        db.session.commit()
        flash("权限删除成功", "ok")
    except Exception as e:
        print(e)
        flash("权限删除失败", "error")
        db.session.rollback()
    return redirect(url_for("admin.auth_list"))


@admin.route("/role/add/", methods=["GET", "POST"])
@admin_login_req
@admin_auth
def role_add():
    form = RoleForm()
    if request.method == "GET":
        form.name.flags.required = False
        form.auths.flags.required = False
    form.auths.choices = [(v.id, v.name) for v in Auth.query.all()]
    if form.validate_on_submit():
        data = form.data
        role_count = Role.query.filter_by(name=data["name"]).count()
        if role_count == 1:
            flash("角色已存在", category="error")
        else:
            role = Role(
                name=data["name"],
                # 这种拼接只能是字符串
                auths=",".join(map(lambda v: str(v), data["auths"]))
            )
            operatelog = OperateLog(
                admin_id=session["admin_id"],
                ip=request.remote_addr,
                reason="添加角色：{}".format(data["name"])
            )
            try:
                db.session.add(role)
                db.session.add(operatelog)
                db.session.commit()
                flash("角色添加成功", category="ok")
            except Exception as e:
                print(e)
                flash("角色添加失败", category="error")
                db.session.rollback()
    return render_template("admin/role_add.html", form=form)


@admin.route("/role/list/<int:page>", methods=['GET'])
@admin.route("/role/list/", methods=['GET'])
@admin_login_req
@admin_auth
def role_list(page=1):
    page_data = Role.query.order_by(Role.addtime.desc()).paginate(page=page, per_page=10)
    return render_template("admin/role_list.html", page_data=page_data)


@admin.route("/role/edit/<int:id>/", methods=['GET', 'POST'])
@admin_login_req
@admin_auth
def role_edit(id=None):
    form = RoleForm()
    role = Role.query.get_or_404(id)
    form.auths.choices = [(v.id, v.name) for v in Auth.query.all()]
    if request.method == "GET":
        form.name.flags.required = False
        form.auths.flags.required = False
        form.auths.data = list(map(lambda v: int(v), role.auths.split(",")))
    if form.validate_on_submit():
        data = form.data
        role_count = Role.query.filter_by(name=data["name"]).count()
        if role.name != data["name"] and role_count == 1:
            flash("角色已存在", category="error")
        else:
            role.name = data["name"]
            role.auths = ",".join(map(lambda v: str(v), data["auths"]))
            operatelog = OperateLog(
                admin_id=session["admin_id"],
                ip=request.remote_addr,
                reason="修改角色：{}".format(role.name)
            )
            try:
                db.session.add(operatelog)
                db.session.add(role)
                db.session.commit()
                flash("角色修改成功", category="ok")
            except Exception as e:
                print(e)
                flash("角色修改失败", category="error")
                db.session.rollback()
    return render_template("admin/role_edit.html", form=form, role=role)


@admin.route("/role/delete/<int:id>/", methods=['GET'])
@admin_login_req
@admin_auth
def role_delete(id=None):
    try:
        role = Role.query.filter_by(id=id).first_or_404()
        operatelog = OperateLog(
            admin_id=session["admin_id"],
            ip=request.remote_addr,
            reason="删除角色：{}".format(role.name)
        )
        db.session.add(operatelog)
        db.session.delete(role)
        db.session.commit()
        flash("角色删除成功", "ok")
    except Exception as e:
        print(e)
        flash("角色删除失败", "error")
        db.session.rollback()
    return redirect(url_for("admin.role_list"))


@admin.route("/admin/add/", methods=['GET', 'POST'])
@admin_login_req
@admin_auth
def admin_add():
    form = AdminForm()
    form.role_id.choices = [(v.id, v.name) for v in Role.query.all()]
    if request.method == "GET":
        form.name.flags.required = False
        form.pwd.flags.required = False
        form.pwd2.flags.required = False
        form.role_id.flags.required = False
    if form.validate_on_submit():
        data = form.data
        admin_count = Admin.query.filter_by(name=data["name"]).count()
        if admin_count == 1:
            flash("管理员账户已存在", "error")
        else:
            admin = Admin(
                name=data["name"],
                pwd=generate_password_hash(data["pwd"]),
                role_id=data["role_id"],
                is_super=1
            )
            operatelog = OperateLog(
                admin_id=session["admin_id"],
                ip=request.remote_addr,
                reason="添加管理员：{}".format(data["name"])
            )
            try:
                db.session.add(admin)
                db.session.add(operatelog)
                db.session.commit()
                flash("管理员添加成功", "ok")
            except Exception as e:
                print(e)
                flash("管理员添加失败", "error")
                db.session.rollback()
    return render_template("admin/admin_add.html", form=form)


@admin.route("/admin/list/<int:page>/", methods=['GET'])
@admin.route("/admin/list/", methods=['GET'])
@admin_login_req
@admin_auth
def admin_list(page=1):
    page_data = Admin.query.join(
        Role
    ).filter(
        Role.id == Admin.role_id
    ).order_by(
        Admin.addtime.desc()
    ).paginate(
        page=page,
        per_page=10
    )
    return render_template("admin/admin_list.html", page_data=page_data)
