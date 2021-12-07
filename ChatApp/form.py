from flask_wtf import FlaskForm
from wtforms.fields import StringField, PasswordField
from wtforms.validators import InputRequired, Length, EqualTo
from wtforms.widgets.core import Input

class RegisterForm(FlaskForm):
    username = StringField('Username', validators=[InputRequired(message='Username Required'), Length(min=4, max=25, message='Username must be between 4 to 25 characters')])
    password = PasswordField('Password', validators=[InputRequired(message='Password Required'), Length(min=4, max=25, message='Password must be between 4 to 25 characters')])
    confirm_password = PasswordField('Confirm Password', validators=[InputRequired(message='Password Required'), EqualTo('password', message='Passwords must match')])


class LoginForm(FlaskForm):
    username = StringField('Username', validators=[InputRequired(message='Username Required')])
    password = PasswordField('Password', validators=[InputRequired(message='Password Required')])    