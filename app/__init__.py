import os

from flask import Flask, render_template
from flask_redis import FlaskRedis

from flask_sqlalchemy import SQLAlchemy


app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql://admin:123456@47.107.149.142:3306/vmovie'
# app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql://root:1234@127.0.0.1:3306/vmovie'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.secret_key = "4b17eb9e1b9b43e7986c713590c4d48f"
app.config["REDIS_URL"] = "redis://0.0.0.0:6379/"
# app.config["REDIS_URL"] = "redis://127.0.0.1:6379/"
app.config["UP_DIR"] = os.path.join(os.path.abspath(os.path.dirname(__file__)), "static/uploads/")
app.config["FACE_DIR"] = os.path.join(os.path.abspath(os.path.dirname(__file__)), "static/uploads/users/")
app.debug = False
db = SQLAlchemy(app)
rd = FlaskRedis(app=app)

from app.admin import admin as admin_blueprint
from app.home import home as home_blueprint

app.register_blueprint(home_blueprint)
app.register_blueprint(admin_blueprint, url_prefix="/admin")


@app.errorhandler(404)
def page_not_found(error):
    return render_template("home/404.html"), 404
