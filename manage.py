from flask_script import Manager

from app import app

# Mangeger可指定端口和地址
manage = Manager(app)

if __name__ == '__main__':
    app.run()