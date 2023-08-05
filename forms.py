from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField, PasswordField, ValidationError, EmailField, TextAreaField
from wtforms.validators import DataRequired, Length, Email, EqualTo


class RegisterForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(),Length(min=4, max=200)])
    email = EmailField('Email', validators=[DataRequired(),Length(min=4, max=300) ,Email()])
    password = PasswordField('Password', validators=[DataRequired(), Length(min=8,max=300)])
    confirm_password = PasswordField('Confirm Password', validators=[
        DataRequired(),Length(min=8,max=300),
        EqualTo('password', message='Passwords must match.')
    ])
    submit = SubmitField('Register')
    def validate_confirm_password(self, field):
        if field.data != self.password.data:
            raise ValidationError('Passwords must match.')

class LoginForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(),Length( max=200)])
    password = PasswordField('Password', validators=[DataRequired(),Length(min=8, max=300)])
    submit = SubmitField('Let Me In')


class TaskForm(FlaskForm):
    title = StringField('Task', validators=[DataRequired(),Length(min=3,max=250)])
    description = TextAreaField('Description',validators=[Length(min=5, max=600), DataRequired()])
    submit = SubmitField('Submit')

class ChangeUsernameForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(),Length(min=4, max=200)])
    submit = SubmitField('Update Details')


class ResetPasswordForm(FlaskForm):
    old_password = PasswordField('Password', validators=[DataRequired(), Length(min=8, max=300)])
    new_password = PasswordField('Password', validators=[DataRequired(), Length(min=8,max=300)])
    new_confirm_password = PasswordField('Confirm Password', validators=[
        DataRequired(),Length(min=8,max=300),
        EqualTo('new_password', message='Passwords must match.')
    ])
    submit = SubmitField('Reset Password')
    def validate_confirm_password(self, field):
        if field.data != self.new_password.data:
            raise ValidationError('Passwords must match.')
