import json
import os
import re
import uuid
from datetime import datetime
from functools import wraps

from flask import render_template, redirect, url_for, request, flash, session, Response
from sqlalchemy import extract
from werkzeug.security import generate_password_hash
from werkzeug.utils import secure_filename

from app import db, app, rd
from app.admin.views import change_filename
from app.home.forms import RegisterForm, LoginForm, UserForm, PwdForm, CommentForm
from app.models import User, UserLog, Prevue, Tag, Movie, Comment, MovieCol
from . import home


def user_login_req(f):
    """
    登录装饰器
    :param f:
    :return:
    """

    @wraps(f)
    def decorated_function(*args, **kwargs):
        if session.get("user") is None:
            return redirect(url_for("home.login", next=request.url))
        return f(*args, **kwargs)

    return decorated_function


@home.route("/login/", methods=["GET", "POST"])
def login():
    form = LoginForm()
    if request.method == "GET":
        form.contact.flags.required = False
        form.pwd.flags.required = False
    if form.validate_on_submit():
        data = form.data
        user = User()
        if re.match(r"^1[34578]\d{9}$", data["contact"]):
            user = User.query.filter_by(
                phone=data["contact"]
            ).first()
        elif re.match(r"^[0-9a-zA-Z_]{0,19}@[0-9a-zA-Z]{1,13}\.[com,cn,net]{1,3}$", data["contact"]):
            user = User.query.filter_by(
                email=data["contact"]
            ).first()
        else:
            user = User.query.filter_by(
                name=data["contact"]
            ).first()
        if user is not None and user.check_pwd(data["pwd"]):
            userlog = UserLog(
                user_id=user.id,
                ip=request.remote_addr
            )
            try:
                db.session.add(userlog)
                db.session.commit()
                session["user"] = user.name
                session["user_id"] = user.id
                return redirect(request.args.get("next") or url_for("home.user"))
            except Exception as e:
                print(e)
                flash("用户登录日志录入错误请联系管理员", "error")
                db.session.rollback()
        else:
            flash("账号或者密码错误", "error")
    return render_template("home/login.html", form=form)


@home.route("/logout/", methods=["GET"])
def logout():
    session.pop("user", None)
    session.pop("user_id", None)
    return redirect(url_for("home.login"))


@home.route("/register/", methods=["GET", "POST"])
def register():
    form = RegisterForm()
    if request.method == "GET":
        form.name.flags.required = False
        form.pwd.flags.required = False
        form.pwd2.flags.required = False
        form.email.flags.required = False
        form.phone.flags.required = False
    if form.validate_on_submit():
        data = form.data
        user = User(
            name=data["name"],
            pwd=generate_password_hash(data["pwd"]),
            email=data["email"],
            phone=data["phone"],
            uuid=uuid.uuid4().hex
        )
        try:
            db.session.add(user)
            db.session.commit()
            session["user"] = user.name
            session["user_id"] = user.id
            return redirect(url_for('home.user'))
        except Exception as e:
            print(e)
            flash("注册失败", "error")
            db.session.rollback()
    return render_template("home/register.html", form=form)


@home.route("/user/", methods=["GET", "POST"])
@user_login_req
def user():
    form = UserForm()
    user = User.query.filter_by(
        id=session["user_id"]
    ).first()
    if request.method == "GET":
        form.name.flags.required = False
        form.email.flags.required = False
        form.phone.flags.required = False
        form.info.data = user.info
    if form.validate_on_submit():
        data = form.data
        user.name = data["name"]
        user.email = data["email"]
        user.phone = data["phone"]
        user.info = data["info"]
        if not os.path.exists(app.config["FACE_DIR"]):
            os.makedirs(app.config["FACE_DIR"])
            os.chmod(app.config["FACE_DIR"])
        if form.face.data != "":
            file_face = secure_filename(form.face.data.filename)
            user.face = change_filename(file_face)
            form.face.data.save(app.config["FACE_DIR"] + user.face)
        try:
            db.session.add(user)
            db.session.commit()
            flash("信息修改成功", "ok")
        except Exception as e:
            print(e)
            flash("信息修改失败", "error")
            db.session.rollback()
    return render_template("home/user.html", form=form, user=user)


@home.route("/pwd/", methods=['GET', 'POST'])
@user_login_req
def pwd():
    form = PwdForm()
    if request.method == "GET":
        form.old_pwd.flags.required = False
        form.new_pwd.flags.required = False
    if form.validate_on_submit():
        data = form.data
        try:
            user = User.query.filter_by(id=session['user_id']).first()
            user.pwd = generate_password_hash(data['new_pwd'])
            db.session.add(user)
            db.session.commit()
            flash("密码修改成功，请重新登录", category="ok")
            return redirect(url_for("home.logout"))
        except Exception as e:
            print(e)
            flash("密码修改失败", category="error")
            db.session.rollback()
    return render_template("home/pwd.html", form=form)


@home.route("/comments/", methods=["GET"])
@home.route("/comments/<int:page>/", methods=["GET"])
@user_login_req
def comments(page=1):
    page_data = Comment.query.join(
        User
    ).join(
        Movie
    ).filter(
        Movie.id == Comment.movie_id,
        User.id == session["user_id"]
    ).order_by(
        Comment.addtime.desc()
    ).paginate(
        page=page,
        per_page=10
    )
    return render_template("home/comments.html", page_data=page_data)


@home.route("/userlog/<int:page>/", methods=["GET"])
@home.route("/userlog/", methods=["GET"])
@user_login_req
def userlog(page=1):
    page_data = UserLog.query.filter_by(
        user_id=session["user_id"]
    ).order_by(
        UserLog.addtime.desc()
    ).paginate(
        page=page,
        per_page=10
    )
    return render_template("home/userlog.html", page_data=page_data)


@home.route("/moviecol/<int:page>/", methods=["GET"])
@home.route("/moviecol/", methods=["GET"])
@user_login_req
def moviecol(page=1):
    page_data = MovieCol.query.join(
        Movie
    ).join(
        User
    ).filter(
        MovieCol.user_id == session["user_id"],
        User.id == MovieCol.user_id,
        Movie.id == MovieCol.movie_id
    ).order_by(
        MovieCol.addtime.desc()
    ).paginate(
        page=page,
        per_page=10
    )
    return render_template("home/moviecol.html", page_data=page_data)


@home.route("/moviecol/add/", methods=["GET"])
@user_login_req
def moviecol_add():
    mid = request.args.get("movie_id", "")
    moviecols = MovieCol.query.filter(
        MovieCol.movie_id == mid,
        MovieCol.user_id == session["user_id"]
    )
    moviecol_count = moviecols.count()
    if moviecol_count:
        try:
            db.session.delete(moviecols.first())
            db.session.commit()
            data = dict(res=True, message="取消收藏")
        except Exception as e:
            print(e)
            db.session.rollback()
            data = dict(res=False, message="取消收藏失败")
    else:
        new_moviecol = MovieCol(
            user_id=session["user_id"],
            movie_id=mid
        )
        try:
            db.session.add(new_moviecol)
            db.session.commit()
            data = dict(res=True, message="收藏成功")
        except Exception as e:
            print(e)
            data = dict(res=False, message="收藏失败")
            db.session.rollback()
    return json.dumps(data)


@home.route("/<int:page>/", methods=["GET"])
@home.route("/", methods=["GET"])
def index(page=1):
    tags = Tag.query.order_by(Tag.addtime.asc())
    times = [2019, 2018, 2017, 2016, 2015]
    page_data = Movie.query
    tag = int(request.args.get("tag", 0))
    if tag != 0:
        page_data = page_data.filter_by(tag_id=int(tag))
    star = int(request.args.get("star", 0))
    if star != 0:
        page_data = page_data.filter_by(star=int(star))
    time = int(request.args.get("time", 0))
    if time != 0:
        if time == times[-1]:
            page_data = page_data.filter(extract('year', Movie.release_time) <= time)
        else:
            page_data = page_data.filter(extract('year', Movie.release_time) == time)
    playnum = int(request.args.get("playnum", 1))
    page_data = page_data.order_by(Movie.playnum.desc()) if playnum == 1 else page_data.order_by(Movie.playnum.asc())
    commentnum = int(request.args.get("commentnum", 1))
    page_data = page_data.order_by(Movie.commentnum.desc()) if int(commentnum) == 1 else page_data.order_by(
        Movie.commentnum.asc())
    page_data = page_data.paginate(page=page, per_page=10)
    p = dict(
        tag=tag,
        star=star,
        time=time,
        playnum=playnum,
        commentnum=commentnum
    )
    return render_template("home/index.html", tags=tags, times=times, p=p, page_data=page_data)


@home.route("/animation/")
def animation():
    data = Prevue.query.order_by(
        Prevue.addtime.desc()
    )
    return render_template("home/animation.html", data=data)


@home.route("/search/<int:page>/", methods=["GET"])
@home.route("/search/", methods=["GET"])
def search(page=1):
    key = request.args.get("key", "")
    page_data = Movie.query.filter(
        # Movie.title.like("%"+key+"%")
        # Movie.title.ilike("%"+key+"%")
        Movie.title.contains(key)
    ).order_by(
        Movie.addtime.desc()
    )
    count = page_data.count()
    page_data = page_data.paginate(
        page=page,
        per_page=10
    )
    page_data.key = key
    return render_template("home/search.html", page_data=page_data, key=key, count=count)


@home.route("/play/<int:id>/<int:page>/", methods=["GET", "POST"])
@home.route("/play/<int:id>/", methods=["GET", "POST"])
def play(id=None, page=1):
    movie = Movie.query.join(
        Tag
    ).filter(
        Movie.id == id,
        Tag.id == Movie.tag_id
    ).first_or_404()
    movie.playnum += 1
    form = CommentForm()
    if request.method == "GET":
        form.content.flags.required = False
    if form.validate_on_submit():
        if session.get("user") is None:
            flash("要登录才可以评论", "error")
        else:
            data = form.data
            comment = Comment(
                content=data["content"].replace("'", ""),
                user_id=session["user_id"],
                movie_id=id
            )
            try:
                db.session.add(comment)
                db.session.commit()
                flash("评论成功", "ok")
                movie.commentnum += 1
            except Exception as e:
                print(e)
                flash("评论失败", "error")
                db.session.rollback()
    try:
        db.session.add(movie)
        db.session.commit()
    except Exception as e:
        print(e)
        flash("电影信息修改出错，请联系管理员处理", "movie_error")
        db.session.rollback()
    page_data = Comment.query.join(
        Movie
    ).join(
        User
    ).filter(
        movie.id == Movie.id,
        Comment.user_id == User.id
    ).order_by(
        Comment.addtime.desc()
    ).paginate(
        page=page,
        per_page=10
    )
    return render_template("home/play.html", movie=movie, form=form, page_data=page_data)


@home.route("/video/<int:id>/<int:page>/", methods=["GET", "POST"])
@home.route("/video/<int:id>/", methods=["GET", "POST"])
def video(id=None, page=1):
    movie = Movie.query.join(
        Tag
    ).filter(
        Movie.id == id,
        Tag.id == Movie.tag_id
    ).first_or_404()
    movie.playnum += 1
    form = CommentForm()
    if request.method == "GET":
        form.content.flags.required = False
    if form.validate_on_submit():
        if session.get("user") is None:
            flash("要登录才可以评论", "error")
        else:
            data = form.data
            comment = Comment(
                content=data["content"].replace("'", ""),
                user_id=session["user_id"],
                movie_id=id
            )
            try:
                db.session.add(comment)
                db.session.commit()
                flash("评论成功", "ok")
                movie.commentnum += 1
            except Exception as e:
                print(e)
                flash("评论失败", "error")
                db.session.rollback()
    try:
        db.session.add(movie)
        db.session.commit()
    except Exception as e:
        print(e)
        flash("电影信息修改出错，请联系管理员处理", "movie_error")
        db.session.rollback()
    page_data = Comment.query.join(
        Movie
    ).join(
        User
    ).filter(
        movie.id == Movie.id,
        Comment.user_id == User.id
    ).order_by(
        Comment.addtime.desc()
    ).paginate(
        page=page,
        per_page=10
    )
    return render_template("home/video.html", movie=movie, form=form, page_data=page_data)


@home.route("/tm/v3/", methods=["GET", "POST"])
def tm():
    if request.method == "GET":
        # 获取弹幕消息队列
        id = request.args.get("id")
        global key
        key = "movie"+str(id)
        if rd.llen(key):
            msgs = rd.lrange(key, 0, 2999)
            res = {
                "code": 0,
                "data": [eval(v.decode("utf8")) for v in msgs]
            }
        else:
            res = {
                "code": 0,
                "data": []
            }
        resp = json.dumps(res)
    if request.method == "POST":
        # 添加弹幕
        data = json.loads(request.get_data())
        msg = [data["time"], data["type"], data["color"], data["author"], data["text"], request.remote_addr, datetime.now().strftime("%Y%m%d%H%M%S")+uuid.uuid4().hex]
        res = {
            "code": 0,
            "data": msg
        }
        resp = json.dumps(res)
        rd.lpush(key, json.dumps(msg))
    return Response(resp, mimetype="application/json")