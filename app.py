#!/usr/bin/env python
import os
from flask import Flask, abort, request, jsonify, g, url_for, render_template, redirect, send_from_directory
from flask_login import UserMixin
import flask.ext.login as auth
from flask.ext.sqlalchemy import SQLAlchemy
from sqlalchemy.orm import relationship

from werkzeug.utils import secure_filename
from passlib.apps import custom_app_context as pwd_context
from flask_wtf import Form
from wtforms import StringField, PasswordField, validators



# initialization
app = Flask(__name__)
app.config['SECRET_KEY'] = 'the quick brown fox jumps over the lazy dog'
WTF_CSRF_SECRET_KEY = 'a random string'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///db.sqlite'
app.config['SQLALCHEMY_COMMIT_ON_TEARDOWN'] = True

# extensions
db = SQLAlchemy(app)
login_manager = auth.LoginManager()
login_manager.init_app(app)



#
# Auth code etc.
#
class User(db.Model, UserMixin):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(32), index=True)
    password_hash = db.Column(db.String(64))
    authenticated = db.Column(db.Boolean, default=False)
    comments = relationship("Comment", back_populates="user")

    def get_id(self):
        return self.id

    def is_authenticated(self):
        return self.authenticated

    def is_anonymous(self):
        return False

    def is_active(self):
        return True

    def hash_password(self, password):
        self.password_hash = pwd_context.encrypt(password)

    def verify_password(self, password):
        return pwd_context.verify(password, self.password_hash)

    # def generate_auth_token(self, expiration=600):
    #     s = Serializer(app.config['SECRET_KEY'], expires_in=expiration)
    #     return s.dumps({'id': self.id})

    # @staticmethod
    # def verify_auth_token(token):
    #     s = Serializer(app.config['SECRET_KEY'])
    #     try:
    #         data = s.loads(token)
    #     except SignatureExpired:
    #         return None    # valid token, but expired
    #     except BadSignature:
    #         return None    # invalid token
    #     user = User.query.get(data['id'])
    #     return user
    #


# Our code for image upload etc.
#
class UserImage(db.Model):
    __tablename__ = 'userimages'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(32), index=True)
    filename = db.Column(db.String(32))
    comments = relationship("Comment")
    shared = relationship("SharedImage")

class SharedImage(db.Model):
    __tablename__ = 'sharedimages'
    id = db.Column(db.Integer, primary_key=True)
    imageId = db.Column(db.Integer, db.ForeignKey('userimages.id'))
    sharedWithId = db.Column(db.Integer, db.ForeignKey('users.id'))
    image = relationship("UserImage", back_populates="shared")

class Comment(db.Model):
    __tablename__ = 'comments'
    id = db.Column(db.Integer, primary_key=True)
    imageId = db.Column(db.Integer, db.ForeignKey('userimages.id'))
    comment = db.Column(db.String)
    userId = db.Column(db.Integer, db.ForeignKey('users.id'))
    user = relationship("User", back_populates="comments")



class LoginForm(Form):
    username = StringField('Username', [validators.Required()])
    password = PasswordField('Password', [validators.Required()])

    def __init__(self, *args, **kwargs):
        Form.__init__(self, *args, **kwargs)
        self.user = None

    def validate(self):
        rv = Form.validate(self)
        if not rv:
            return False

        user = User.query.filter_by(
            username=self.username.data).first()
        if user is None:
            self.username.errors.append('Unknown username')
            return False

        if not user.verify_password(self.password.data):
            self.password.errors.append('Invalid password')
            return False

        self.user = user
        return True


class RegisterForm(Form):
    username = StringField('Username', [validators.Required()])
    password = PasswordField('Password', [validators.Required()])


@login_manager.user_loader
def user_loader(user_id):
    return User.query.get(user_id)


#
#
# Routings etc.
#
@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegisterForm(request.form)
    if request.method == 'POST' and form.validate():
        user = User(username=form.username.data)
        user.hash_password(form.password.data)
        db.session.add(user)
        db.session.commit()
        return redirect(url_for('login'))
    return render_template('register.html', form=form)


@app.route("/login", methods=["GET", "POST"])
def login():
    form = LoginForm(request.form)
    if form.validate():
        user = User.query.filter_by(username=form.username.data).first()
        auth.login_user(user)
        return redirect(url_for("upload"))
    return render_template("login.html", form=form)


@app.route("/logout", methods=["GET"])
@auth.login_required
def logout():
    user = auth.current_user
    user.authenticated = False
    db.session.add(user)
    db.session.commit()
    auth.logout_user()
    return redirect(url_for('login'))


@app.route('/')
@auth.login_required
def upload():
    own_images = UserImage.query.filter_by(username=auth.current_user.username)
    shared_images = SharedImage.query.filter_by(sharedWithId=auth.current_user.id)
    model = {"own_images": own_images, "shared_images": shared_images}

    return render_template('index.html', model=model)


def create_dir_if_not_exists(path):
    if not os.path.exists(path):
        os.makedirs(path)


@app.route('/upload_image', methods=['POST'])
@auth.login_required
def upload_image():
    pic = request.files["image_upload"]
    filename = secure_filename(pic.filename)
    user_path = os.path.expanduser('~')
    username = auth.current_user.username
    create_dir_if_not_exists("static/images/" + username + "/")
    pic.save("static/images/" + username + "/" + filename)
    user_image = UserImage(username=username, filename=filename)
    db.session.add(user_image)
    db.session.commit()
    return redirect(url_for('image', username=username, filename=filename))


@app.route('/images/<username>/<filename>')
@auth.login_required
def image(username, filename):
    current_user = auth.current_user
    image = UserImage.query.filter_by(username=username, filename=filename).first()

    url = "images/" + username + "/" + filename

    if current_user.username != username:
        isshared = SharedImage.query.filter_by(sharedWithId=current_user.id).first()
        if not isshared:
            return abort(405)
    return render_template('image.html', image=image, filename=url)


if __name__ == '__main__':
    if not os.path.exists('db.sqlite'):
        db.create_all()
    app.debug = True
    app.run()


