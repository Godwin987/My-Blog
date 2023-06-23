from flask import Flask, render_template, redirect, url_for, flash, request, abort
from flask_bootstrap import Bootstrap5
from flask_ckeditor import CKEditor
from datetime import date
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin, login_user, LoginManager, login_required, current_user, logout_user
from forms import CreatePostForm, RegisterForm, LoginForm, CommentForm
from flask_gravatar import Gravatar
from functools import wraps
from sqlalchemy import Table, Column, Integer, ForeignKey
from sqlalchemy.orm import relationship, declarative_base
from flask_migrate import Migrate
import os
from dotenv import load_dotenv

load_dotenv()  # take environment variables from .env.

# Base = declarative_base()

app = Flask(__name__)
app.config['SECRET_KEY'] = os.getenv("SECRET_KEY")
ckeditor = CKEditor(app)
Bootstrap5(app)

##CONNECT TO DB
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv("DATABASE_URL", "sqlite:///blog.db")
# postgresql://blog_data_rxkz_user:cOwXti1ydNSaLI0TEnO0bMIccDYnHlKT@dpg-ci71bsp8g3n3vm4o95r0-a.oregon-postgres.render.com/blog_data_rxkz
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy()
db.init_app(app)
session = db.session

# CONFIGURE APP FOR FLASK_LOGIN
login_manager = LoginManager()
login_manager.init_app(app)

# MIGRATE OBJECT
migrate = Migrate(app, db)


@login_manager.user_loader
def load_user(user_id):
    return session.get(entity=Users, ident=int(user_id))


##CONFIGURE TABLES


# ADMIN_DECORATOR
def admin_only(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        # If user is not actually logged in
        if current_user.is_anonymous:
            print("User is anonymous")
            return abort(403, description="User is anonymous")
        # If id is not 1 then return abort with 403 error
        elif current_user.id != 1:
            print("User is not an admin")
            return abort(403, description="User is not an admin")
        else:
            print("User is an admin")
            # Otherwise, continue with the route function
            return f(*args, **kwargs)

    return decorated_function


# MODELS
class Users(UserMixin, db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(150), unique=False, nullable=False)
    name = db.Column(db.String(150), unique=False, nullable=False)
    posts = db.relationship('BlogPost', backref='user')
    comment = db.relationship('Comment', backref='user')


class BlogPost(db.Model):
    __tablename__ = "blog_posts"
    id = db.Column(db.Integer, primary_key=True)
    author = db.Column(db.String(250), nullable=False)
    title = db.Column(db.String(250), unique=True, nullable=False)
    subtitle = db.Column(db.String(250), nullable=False)
    date = db.Column(db.String(250), nullable=False)
    body = db.Column(db.Text, nullable=False)
    img_url = db.Column(db.String(250), nullable=False)
    user_id = db.Column(db.Integer, ForeignKey('users.id'))
    comment = db.relationship('Comment', backref='blog_posts')


# db.create_all()

class Comment(db.Model):
    __tablename__ = "comments"
    id = db.Column(db.Integer, primary_key=True)
    text = db.Column(db.String(300))
    user_id = db.Column(db.Integer, ForeignKey('users.id'))
    blog_id = db.Column(db.Integer, ForeignKey('blog_posts.id'))


# GRAVATAR SETUP
gravatar = Gravatar(app,
                    size=100,
                    rating='g',
                    default='retro',
                    force_default=False,
                    force_lower=False,
                    use_ssl=False,
                    base_url=None)

with app.app_context():
    # db.create_all()
    @app.route('/')
    def get_all_posts():
        posts = BlogPost.query.all()
        return render_template("index.html", all_posts=posts, user=current_user)


    # REGISTER ROUTE
    @app.route('/register', methods=["GET", "POST"])
    def register():
        form = RegisterForm()
        if form.validate_on_submit():
            user = Users.query.filter_by(email=request.form.get('email')).first()
            if user:
                flash(message='You\'ve already signed up with that email. Login instead', category='error')
                return redirect(url_for('login'))
            else:
                new_user = Users(
                    email=form.email.data,
                    password=generate_password_hash(password=form.password.data),
                    name=form.name.data
                )
                db.session.add(new_user)
                db.session.commit()
                login_user(new_user)
                return redirect(url_for("get_all_posts"))
        return render_template("register.html", form=form, user=current_user)


    # LOGIN ROUTE
    @app.route('/login', methods=["GET", "POST"])
    def login():
        form = LoginForm()
        if form.validate_on_submit():
            user = Users.query.filter_by(email=request.form.get('email')).first()
            if user:
                if check_password_hash(pwhash=user.password, password=request.form.get('password')):
                    login_user(user)
                    return redirect(url_for('get_all_posts', user=current_user))
                else:
                    flash(message='Password is incorrect', category='error')
            else:
                flash(message='Email does\'nt exist. You can signup for a new account', category='error')
        return render_template("login.html", form=form, user=current_user)


    # LOGOUT ROUTE
    @app.route('/logout')
    @login_required
    def logout():
        logout_user()
        return redirect(url_for('get_all_posts'))


    @app.route("/post/<int:post_id>", methods=["GET", "POST"])
    # @login_required
    def show_post(post_id):
        comment_form = CommentForm()
        requested_post = session.get(BlogPost, post_id)
        if comment_form.validate_on_submit():
            if not current_user.is_authenticated:
                flash('Please login or register to comment')
                return redirect(url_for('login'))
            else:
                new_comment = Comment(
                    text=comment_form.comment.data,
                    user=current_user,
                    blog_posts=requested_post
                )
                db.session.add(new_comment)
                db.session.commit()
                return redirect(url_for("get_all_posts"))
        return render_template("post.html", post=requested_post, user=current_user, form=comment_form)


    @app.route("/about")
    def about():
        return render_template("about.html", user=current_user)


    @app.route("/contact")
    def contact():
        return render_template("contact.html", user=current_user)


    @app.route("/new-post", methods=["GET", "POST"])
    @login_required
    # @admin_only
    def add_new_post():
        form = CreatePostForm()
        if form.validate_on_submit():
            new_post = BlogPost(
                title=form.title.data,
                subtitle=form.subtitle.data,
                body=form.body.data,
                img_url=form.img_url.data,
                author=current_user.name,
                date=date.today().strftime("%B %d, %Y")
            )
            db.session.add(new_post)
            db.session.commit()
            return redirect(url_for("get_all_posts"))
        return render_template("make-post.html", form=form, user=current_user)


    # EDIT POSTS
    @app.route("/edit-post/<int:post_id>", methods=["GET", "POST"])
    @login_required
    @admin_only
    def edit_post(post_id):
        post = BlogPost.query.get(post_id)
        edit_form = CreatePostForm(
            title=post.title,
            subtitle=post.subtitle,
            img_url=post.img_url,
            author=post.author,
            body=post.body
        )
        if edit_form.validate_on_submit():
            post.title = edit_form.title.data
            post.subtitle = edit_form.subtitle.data
            post.img_url = edit_form.img_url.data
            post.author = edit_form.author.data
            post.body = edit_form.body.data
            db.session.commit()
            return redirect(url_for("show_post", post_id=post.id))

        return render_template("make-post.html", form=edit_form, user=current_user)


    # DELETE POSTS
    @app.route("/delete/<int:post_id>")
    @login_required
    def delete_post(post_id):
        post_to_delete = BlogPost.query.get(post_id)
        db.session.delete(post_to_delete)
        db.session.commit()
        return redirect(url_for('get_all_posts'))


    if __name__ == "__main__":
        app.run(debug=True)
