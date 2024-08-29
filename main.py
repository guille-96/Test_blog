import flask
from typing import List
from flask import Flask, render_template, request, redirect, url_for, abort
from flask_bootstrap import Bootstrap5
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship
from sqlalchemy import Integer, String, Boolean, Text
import werkzeug
import requests
import smtplib
import os
from flask_ckeditor import CKEditor, CKEditorField
from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField, PasswordField
from wtforms.validators import DataRequired, URL, Email
from datetime import date
from flask_login import LoginManager, login_user, UserMixin, logout_user, current_user
from functools import wraps
from flask_gravatar import Gravatar



app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get("FLASK_KEY")
ckeditor = CKEditor(app)
Bootstrap5(app)

data_endpoint = "https://api.npoint.io/650c81581d282bf58934"
posts = requests.get(data_endpoint).json()

app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get("DB_URI")

db = SQLAlchemy(app)

login_manager = LoginManager()
login_manager.init_app(app)


def admin_only(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated:
            flask.flash('Identify as an admin to do that action')
            return redirect(url_for('login'))

        if current_user.id != 1:
            abort(403)

        return f(*args, **kwargs)

    return decorated_function


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(user_id)


@app.context_processor
def inject_year():
    return {'current_year': date.today().strftime("%Y")}


gravatar = Gravatar(app,
                    size=100,
                    rating='g',
                    default='retro',
                    force_default=False,
                    force_lower=False,
                    use_ssl=False,
                    base_url=None)


class User(db.Model, UserMixin):
    __tablename__ = "users"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    email: Mapped[str] = mapped_column(String(100), unique=True)
    password: Mapped[str] = mapped_column(String(100))
    name: Mapped[str] = mapped_column(String(100))
    posts = relationship("BlogPost", back_populates="author")


class BlogPost(db.Model):
    __tablename__ = "blog_posts"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    author_id: Mapped[int] = mapped_column(Integer, db.ForeignKey("users.id"))
    author = relationship("User", back_populates="posts")
    title: Mapped[str] = mapped_column(String(250), unique=True, nullable=False)
    subtitle: Mapped[str] = mapped_column(String(250), nullable=False)
    date: Mapped[str] = mapped_column(String(250), nullable=False)
    body: Mapped[str] = mapped_column(Text, nullable=False)
    img_url: Mapped[str] = mapped_column(String(250), nullable=False)
    comments = relationship("Comment", back_populates="post", cascade="all, delete-orphan")


class Comment(db.Model):
    __tablename__ = "comments"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    user_id: Mapped[int] = mapped_column(Integer, db.ForeignKey("users.id"))
    post_id: Mapped[int] = mapped_column(Integer, db.ForeignKey("blog_posts.id"))
    user: Mapped['User'] = relationship("User")
    post: Mapped['BlogPost'] = relationship("BlogPost", back_populates="comments")
    body: Mapped[str] = mapped_column(Text, nullable=False)


class CreatePostForm(FlaskForm):
    title = StringField("Blog Post Title", validators=[DataRequired()])
    subtitle = StringField("Subtitle", validators=[DataRequired()])
    author = StringField("Your Name", validators=[DataRequired()])
    img_url = StringField("Blog Image URL", validators=[DataRequired(), URL()])
    body = CKEditorField("Blog Content", validators=[DataRequired()])
    submit = SubmitField("Submit Post")


class RegisterForm(FlaskForm):
    email = StringField("Email", validators=[DataRequired(), Email()])
    password = PasswordField("Password", validators=[DataRequired()])
    name = StringField("Name", validators=[DataRequired()])
    submit = SubmitField("Register")


class CommentForm(FlaskForm):
    comment = CKEditorField("Comment")
    submit = SubmitField("Submit comment")

class LoginForm(FlaskForm):
    email = StringField("Email", validators=[DataRequired(), Email()])
    password = PasswordField("Password", validators=[DataRequired()])
    login = SubmitField("Log in")


@app.route("/")
def home(name=None):
    result = db.session.execute(db.select(BlogPost))
    posts = result.scalars().all()
    return render_template("index.html", posts=posts)


@app.route("/about")
def about(name=None):
    return render_template("about.html")


@app.route("/contact", methods=["GET", "POST"])
def contact():
    if request.method == 'POST':
        my_email = os.environ.get("my_email")
        email_password = os.environ.get("email_password")
        name = request.form["name"]
        email = request.form["email"]
        phone_number = request.form["phone_number"]
        message = request.form["message"]
        data = (f"Name: {name}\n"
                f"Email: {email}\n"
                f"Phone number: {phone_number}\n"
                f"Message: {message}")
        print(data)

        email_message = f"Subject: New Contact Form Submission\n\n{data}"

        with smtplib.SMTP("smtp.gmail.com", 587) as connection:
            connection.starttls()
            connection.login(user=my_email, password=email_password)
            connection.sendmail(from_addr=my_email,
                                to_addrs="guillermovzmn@gmail.com",
                                msg=email_message)
        return render_template("contact.html", sent_message=True)
    if request.method == 'GET':
        return render_template("contact.html")


@app.route("/post/<int:post_id>", methods=["GET", "POST"])
def post(post_id):
    result = db.session.execute(db.select(BlogPost).where(BlogPost.id == post_id))
    post = result.scalar_one_or_none()
    comments = Comment.query.filter_by(post_id=post_id).all()
    comment_form = CommentForm()
    if request.method == "POST":
        new_comment = Comment(
            user_id=current_user.id,
            post_id=post_id,
            body=comment_form.comment.data
        )
        db.session.add(new_comment)
        db.session.commit()
        return redirect(url_for('post', post_id=post_id))
    return render_template("post.html", post=post, form=comment_form, comments = comments)


@app.route("/new-post", methods=['GET', 'POST'])
@admin_only
def new_post(name=None):
    form = CreatePostForm()
    if request.method == 'POST':
        new_post = BlogPost(
            title=form.title.data,
            subtitle=form.subtitle.data,
            author=current_user,
            img_url=form.img_url.data,
            body=form.body.data,
            date=date.today().strftime("%B %d, %Y")
        )
        db.session.add(new_post)
        db.session.commit()
        return redirect('/')
    return render_template("make-post.html", form=form, title="New post")


@app.route("/edit-post/<post_id>", methods=['GET', 'POST'])
@admin_only
def edit_post(post_id):
    result = db.session.execute(db.select(BlogPost).where(BlogPost.id == post_id))
    post = result.scalar_one_or_none()
    form = CreatePostForm(
        title=post.title,
        subtitle=post.subtitle,
        author=post.author,
        img_url=post.img_url,
        body=post.body
    )
    if form.validate_on_submit():
        post.title = form.title.data
        post.subtitle = form.subtitle.data
        post.author = form.author.data
        post.img_url = form.img_url.data
        post.body = form.body.data
        db.session.commit()

        return redirect(f'/post/{post_id}')
    return render_template("make-post.html", post=post, title="Edit post", form=form)


@app.route("/delete/<post_id>", methods=['GET'])
@admin_only
def delete(post_id):
    with app.app_context():
        post_to_delete = db.session.execute(db.select(BlogPost).where(BlogPost.id == post_id)).scalar()
        db.session.delete(post_to_delete)
        db.session.commit()
    return redirect('/')


@app.route("/register", methods=['GET','POST'])
def register():
    form = RegisterForm()
    if request.method == 'POST':
        new_user = User(
            email=form.email.data,
            password=werkzeug.security.generate_password_hash
                (request.form["password"], method='pbkdf2:sha256', salt_length=8),
            name=form.name.data
        )

        user_search = User.query.filter_by(email=request.form["email"]).first()
        if not user_search:
            db.session.add(new_user)
            db.session.commit()
            login_user(new_user)
            return redirect(url_for('home'))
        else:
            flask.flash('Already registered. Please Login')
            return redirect(url_for('login'))
    return render_template("register.html", form=form)


@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if request.method == 'POST':
        email = request.form["email"]
        password = request.form["password"]
        user = User.query.filter_by(email=email).first()
        if user and werkzeug.security.check_password_hash(user.password, password):
            login_user(user)
            return redirect(url_for('home'))
        elif not user:
            flask.flash('Invalid email.')
        elif not werkzeug.security.check_password_hash(user.password, password):
            flask.flash('Invalid password.')
    return render_template("login.html", form=form)


@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('home'))

with app.app_context():
    db.create_all()


if __name__ == '__main__':
    app.run(debug=True)

