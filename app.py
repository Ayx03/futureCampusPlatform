# encoding='utf-8'

from typing import Callable

from werkzeug.utils import secure_filename

from config import *
import hashlib
import random
import smtplib
from email.mime.text import MIMEText
from email.utils import formataddr
from flask import Flask, \
    render_template, \
    redirect, \
    url_for, \
    flash, \
    abort, \
    session, \
    request, \
    jsonify, \
    send_from_directory
from flask_bootstrap import Bootstrap
from flask_mail import Mail
from flask_migrate import Migrate, MigrateCommand
from flask_script import Manager
from flask_sqlalchemy import SQLAlchemy
from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField, PasswordField, ValidationError, RadioField
from wtforms.validators import Email, DataRequired, Length, EqualTo

app = Flask(__name__)

SECRET_KEY = '\xfe{\xa9\n\x1b0\x16\xcfF\xb103\x9d)\xdf\xfd\xab\xd8\x9b\xbf\xf2\xf5\xb0\x86'

app.config.from_object(__name__)


class MySQLAlchemy(SQLAlchemy):
    Column: Callable
    String: Callable
    Integer: Callable
    Boolean: Callable
    relationship: Callable
    ForeignKey: Callable


bootstrap = Bootstrap(app)
db = MySQLAlchemy(app)
mail = Mail(app)
manager = Manager(app)
migrate = Migrate(app, db)
manager.add_command('db', MigrateCommand)

activate_mail_html = open("templates/activatemail.html", "r", encoding='utf-8').read()
find_pass_mail_html = open("templates/email.html", "r", encoding='utf-8').read()


def dosthwithself(self):
    return self


def send_mail(to, subject, link, extra_info, template):
    try:
        mail_content = ''
        if template == 0:
            mail_content = link
        elif template == 1:
            mail_content = activate_mail_html.replace("${link}", link, 2)
            # print("We're good so far")
        elif template == 2:
            mail_content = find_pass_mail_html.replace("${link}", link, 2).replace("${password}", extra_info, 2)
        else:
            print(mail_content)
            print("Error occurred when sending email: Unknown template " + template)
            return False
        msg = MIMEText(mail_content, 'html', 'utf-8')
        msg['From'] = formataddr(('noreply', MAIL_USERNAME))
        msg['To'] = formataddr(('future.Campus.Platform.user', to))
        msg['Subject'] = subject
        if MAIL_USE_SSL:
            server = smtplib.SMTP_SSL(MAIL_SERVER, MAIL_PORT)
        else:
            server = smtplib.SMTP(MAIL_SERVER, MAIL_PORT)
        server.login(MAIL_USERNAME, MAIL_PASSWORD)
        server.sendmail(MAIL_USERNAME, [to, ],
                        msg.as_string().encode('utf-8'))
        server.quit()
    except Exception as error:
        print("Error occurred when sending email: " + str(error))
        return False
    return True


class AdminForm(FlaskForm):
    def account_check(self, field):
        dosthwithself(self)
        if field.data != ADMIN_NAME:
            raise ValidationError(string_come_on_baby)

    def password_check(self, field):
        dosthwithself(self)
        if field.data != ADMIN_PASS:
            raise ValidationError(string_come_on_baby)

    email = StringField(string_admin_email, validators=[DataRequired(message=string_come_on_baby),
                                                        Email(message=string_email_invalid), account_check])
    password = PasswordField(string_admin_password,
                             validators=[DataRequired(message=string_password_empty), password_check])
    login = SubmitField(string_login)


class AdminAddForm(FlaskForm):
    def email_unique(self, field):
        dosthwithself(self)
        if User.query.filter_by(email=field.data).first():
            raise ValidationError(string_email_bond)

    name = StringField('用户名', validators=[DataRequired()])
    email = StringField('用户邮箱', validators=[DataRequired(), email_unique])
    password = StringField('用户密码', validators=[DataRequired()])
    account_type = RadioField('身份', choices=[(string_student, string_student), (string_teacher, string_teacher)],
                              default=string_student)
    add = SubmitField("增加用户")


class LoginForm(FlaskForm):
    def email_exist(self, field):
        dosthwithself(self)
        if not User.query.filter_by(email=field.data).first():
            raise ValidationError(string_email_invalid)

    email = StringField("邮箱", validators=[DataRequired(message=string_email_required),
                                          Email(message=string_email_invalid), email_exist])
    password = PasswordField("密码", validators=[DataRequired(message=string_password_empty)])
    login = SubmitField(string_login)


class RegisterForm(FlaskForm):
    def email_unique(self, field):
        dosthwithself(self)
        if User.query.filter_by(email=field.data).first():
            raise ValidationError(string_email_bond)

    def password_noblank(self, field):
        dosthwithself(self)
        for s in field.data:
            if s == ' ':
                raise ValidationError(string_password_no_space)

    account_type = RadioField('账号类型', choices=[(string_student, string_student), (string_teacher, string_teacher)],
                              default=string_teacher)
    name = StringField('用户名', validators=[DataRequired(message=string_data_required)])
    email = StringField("邮箱", validators=[DataRequired(message=string_email_required),
                                          Email(message=string_email_invalid), email_unique])
    password = PasswordField("密码", validators=[DataRequired(message=string_password_empty),
                                               Length(6, message=string_password_too_short), password_noblank])
    confirm = PasswordField("确认密码", validators=[DataRequired(message=string_password_confirm_required),
                                                EqualTo('password', string_password_confirm_failure)])
    register = SubmitField(string_register)


class ForgetForm(FlaskForm):
    def email_exist(self, field):
        dosthwithself(self)
        if not User.query.filter_by(email=field.data).first():
            raise ValidationError(string_email_not_registered)

    def password_noblank(self, field):
        dosthwithself(self)
        for s in field.data:
            if s == ' ':
                raise ValidationError(string_come_on_baby)

    email = StringField("邮箱", validators=[DataRequired(message=string_email_required),
                                          Email(message=string_email_invalid), email_exist])
    password = PasswordField("要设置的新密码", validators=[DataRequired(message=string_password_empty),
                                                    Length(6, message=string_password_too_short), password_noblank])
    confirm = PasswordField("确认要设置的新密码", validators=[DataRequired(message=string_password_confirm_required),
                                                     EqualTo('password', string_password_confirm_failure)])
    getback = SubmitField("提交验证")


class AddForm(FlaskForm):
    def student_exist(self, field):
        dosthwithself(self)
        fcpuser = User.query.filter_by(id=session.get('user_id')).first()
        for fcpstudent in fcpuser.students:
            if fcpstudent.stu_id == field.data:
                raise ValidationError(string_student_id_exist)

    stu_id = StringField("学生学号", validators=[DataRequired(message=string_student_id_required),
                                             Length(6, 15, "学号长度必须在 6 - 15 位之间"), student_exist])
    name = StringField("学生姓名", validators=[DataRequired(
        message=string_student_name_empty),
        Length(-1, 10, string_student_name_too_long)
    ])
    cls = StringField("专业班级", validators=[DataRequired(message=string_data_required),
                                          Length(-1, 15, string_class_name_too_long)])
    addr = StringField("所在寝室", validators=[DataRequired(message=string_data_required),
                                           Length(-1, 15, string_address_too_long)])
    phone = StringField("联系方式", validators=[DataRequired(message=string_data_required)])
    add = SubmitField(string_add_student)


class SearchForm(FlaskForm):
    keyword = StringField("输入查询关键字", validators=[DataRequired(message=string_search_input_empty)])
    search = SubmitField(string_search)


class AdminSendMailForm(FlaskForm):
    email = StringField('邮箱', validators=[DataRequired()])
    content = StringField("内容", validators=[DataRequired(message='string_search_input_empty')])
    Send = SubmitField(string_send_mail)


class User(db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(64))
    email = db.Column(db.String(64), index=True, unique=True)
    password = db.Column(db.String(64))
    account_type = db.Column(db.String(64), default=string_student)
    active_code = db.Column(db.String(10))
    active_state = db.Column(db.Boolean, default=False)
    students = db.relationship('Student', backref='user', lazy='dynamic')
    banned = db.Column(db.Boolean, default=False)


class Student(db.Model):
    __tablename__ = 'students'
    id = db.Column(db.Integer, primary_key=True)
    stu_id = db.Column(db.String(64), index=True)
    name = db.Column(db.String(64))
    cls = db.Column(db.String(64))
    addr = db.Column(db.String(64))
    phone = db.Column(db.String(64))
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'))


db.create_all()


@app.route('/', methods=['GET', 'POST'])
@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        fcpuser = User.query.filter_by(email=form.email.data).first()
        hashed_password = hashlib.md5()
        hashed_password.update(form.password.data.encode(encoding='utf-8'))
        if fcpuser.banned:
            flash(string_account_banned)
            return redirect(url_for('login'))
        if not fcpuser.active_state:
            flash(string_account_not_activated)
            return redirect(url_for('login'))
        elif fcpuser.password != hashed_password.hexdigest():
            flash(string_password_wrong)
            return redirect(url_for('login'))
        session['user_id'] = fcpuser.id
        if fcpuser.account_type == string_teacher:
            return redirect('/u/' + str(fcpuser.id))
        if fcpuser.account_type == string_student:
            return redirect('/s/' + str(fcpuser.id))
    return render_template('form.html', form=form)


@app.route('/logout')
def logout():
    if session.get('admin'):
        session['admin'] = None
    elif session.get('user_id') is None:
        flash(string_quit_when_not_logged_in)
        return redirect(url_for('login'))
    flash(string_logout_success)
    session['user_id'] = None
    return redirect(url_for('login'))


@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegisterForm()
    if form.validate_on_submit():
        n = []
        for i in range(10):
            n.append(str(random.randint(0, 9)))
        active_code = ''.join(n)
        hashed_password = hashlib.md5()
        hashed_password.update(form.password.data.encode(encoding='utf-8'))
        new_user = User(name=form.name.data, email=form.email.data, password=hashed_password.hexdigest(),
                        account_type=form.account_type.data, active_code=active_code)
        db.session.add(new_user)

        fcpuser = User.query.filter_by(email=form.email.data).first()
        sub = "激活你在未来校园平台注册的新账号"
        link = domain + '/activate/' + str(fcpuser.id) + '/' + active_code
        if send_mail(new_user.email, sub, link, 'None', 1):
            print("[Debug] 邮件发送成功")
        else:
            print("[Debug] 邮件发送失败")
        print("[Debug] 新用户 " + new_user.email + " 的激活链接是 " + link)
        flash(string_check_email_to_activate)
        return redirect(url_for('login'))
    return render_template('form.html', form=form)


@app.route('/c/<int:id>/<active_code>')
@app.route('/activate/<int:id>/<active_code>')
def check(id, active_code):
    fcpuser = User.query.filter_by(id=id).first()
    if fcpuser is not None and fcpuser.active_code == active_code:
        if fcpuser.active_state:
            return render_template('warn.html', message=string_account_already_activated)
        fcpuser.active_state = True
        db.session.add(fcpuser)
        return render_template('success.html', action=string_register)
    abort(400)


@app.route('/forget', methods=['GET', 'POST'])
@app.route('/iforgot', methods=['GET', 'POST'])
def iforget():
    form = ForgetForm()
    if form.validate_on_submit():
        fcpuser = User.query.filter_by(email=form.email.data).first()
        n = []
        for i in range(10):
            n.append(str(random.randint(0, 9)))
        verify_code = ''.join(n)
        fcpuser.active_code = verify_code
        sub = "请点击下方链接的完成密码更改："
        link = domain + '/f/' + str(fcpuser.id) + '/' + fcpuser.active_code + '/' + form.password.data
        flash(string_check_email_to_change_password)
        send_mail(fcpuser.email, sub, link, form.password.data, 2)
        return redirect(url_for('login'))
    return render_template("form.html", form=form)


@app.route('/f/<int:id>/<active_code>/<password>')
@app.route('/find/<int:id>/<active_code>/<password>')
def new_password(id, active_code, password):
    fcpuser = User.query.filter_by(id=id).first()
    if fcpuser is not None and fcpuser.active_code == '已修改':
        return render_template('warn.html', message=string_password_reset_code_used)
    if fcpuser is not None and fcpuser.active_code == active_code:
        hashed_password = hashlib.md5()
        hashed_password.update(password.encode(encoding='utf-8'))
        fcpuser.password = hashed_password.hexdigest()
        db.session.add(fcpuser)
        fcpuser.active_code = '已修改'
        return render_template('success.html', action=string_password_change)
    abort(400)


@app.route('/u/<int:id>')
@app.route('/teacher/<int:id>')
def user(id):
    if session.get('user_id') is None or id != session.get('user_id'):
        session['user_id'] = None
        flash(string_not_logged_in)
        return redirect(url_for('login'))
    fcpuser = User.query.filter_by(id=id).first()
    if fcpuser.account_type != string_teacher:
        abort(400)
    return render_template('user.html', user=fcpuser)


@app.route('/s/<int:id>')
@app.route('/student/<int:id>')
def student(id):
    if session.get('user_id') is None or id != session.get('user_id'):
        session['user_id'] = None
        flash(string_not_logged_in)
        return redirect(url_for('login'))
    fcpuser = User.query.filter_by(id=id).first()
    teachers = User.query.filter_by(account_type=string_teacher).all()
    if fcpuser.account_type != string_student:
        abort(400)
    return render_template('student.html', user=fcpuser, teachers=teachers)


@app.route('/u/<int:id>/account')
def account(id):
    if session.get('user_id') is None or id != session.get('user_id'):
        session['user_id'] = None
        flash(string_not_logged_in)
        return redirect(url_for('login'))
    fcpuser = User.query.filter_by(id=id).first()
    num = fcpuser.students.count()
    return render_template('account.html', user=fcpuser, num=num)


@app.route('/s/<int:user_id>/<int:teacher_id>')
def detail(user_id, teacher_id):
    if session.get('user_id') is None or user_id != session.get('user_id'):
        session['user_id'] = None
        flash(string_not_logged_in)
        return redirect(url_for('login'))
    fcpuser = User.query.filter_by(id=user_id).first()
    if fcpuser.account_type != string_student:
        abort(400)
    teacher = User.query.filter_by(id=teacher_id).first()
    x_user = {'id': user_id, 'account_type': string_student, 'name': teacher.name, 'students': teacher.students}
    return render_template('detail.html', user=x_user)


@app.route('/u/<int:id>/add', methods=['GET', 'POST'])
def add(id):
    if session.get('user_id') is None or id != session.get('user_id'):
        session['user_id'] = None
        flash(string_not_logged_in)
        return redirect(url_for('login'))
    fcpuser = User.query.filter_by(id=id).first()
    if fcpuser.account_type != string_teacher:
        abort(400)
    form = AddForm()
    if form.validate_on_submit():
        new_student = Student(stu_id=form.stu_id.data, name=form.name.data,
                              cls=form.cls.data, addr=form.addr.data, phone=form.phone.data, user_id=id)
        db.session.add(new_student)
        flash(string_add_success)
        return redirect('/u/' + str(id) + '/add')
    return render_template('form.html', form=form, user=fcpuser)


@app.route('/u/<int:id>/search', methods=['GET', 'POST'])
def search(id):
    if session.get('user_id') is None or id != session.get('user_id'):
        session['user_id'] = None
        flash(string_not_logged_in)
        return redirect(url_for('login'))
    form = SearchForm()
    fcpuser = User.query.filter_by(id=id).first()
    if fcpuser.account_type != string_teacher:
        abort(400)

    hide = set()
    if form.validate_on_submit():
        for fcpstudent in fcpuser.students:
            word = str(fcpstudent.stu_id) + ' ' + fcpstudent.name + ' ' + fcpstudent.cls + ' ' + \
                   fcpstudent.addr + ' ' + fcpstudent.phone
            if form.keyword.data not in word:
                hide.add(fcpstudent)
    return render_template('form.html', form=form, search=True, user=fcpuser, hide=hide)


@app.route('/u/<int:id>/delete', methods=['POST'])
def delete(id):
    if session.get('user_id') is None or id != session.get('user_id'):
        session['user_id'] = None
        flash(string_not_logged_in)
        return redirect(url_for('login'))
    fcpuser = User.query.filter_by(id=id).first()
    if fcpuser.account_type != string_teacher:
        abort(400)

    fcpstudent = Student.query.filter_by(stu_id=request.form.get('stu_id'), user_id=id).first()
    if fcpstudent:
        db.session.delete(fcpstudent)
    return jsonify({'result': 'success'})


@app.route('/u/<int:id>/change', methods=['POST'])
def change(id):
    if session.get('user_id') is None or id != session.get('user_id'):
        session['user_id'] = None
        flash(string_not_logged_in)
        return redirect(url_for('login'))
    fcpuser = User.query.filter_by(id=id).first()
    if fcpuser.account_type != string_teacher:
        abort(400)
    fcpstudent = Student.query.filter_by(id=request.form.get('id')).first()
    fcpstudent.stu_id = request.form.get('stu_id')
    fcpstudent.name = request.form.get('name')
    fcpstudent.cls = request.form.get('cls')
    fcpstudent.addr = request.form.get('addr')
    fcpstudent.phone = request.form.get('phone')
    db.session.add(fcpstudent)
    return jsonify({'result': 'success'})


@app.route('/admin', methods=['GET', 'POST'])
@app.route('/admin/', methods=['GET', 'POST'])
def fake_admin():
    return 'Sorry, this is not the panel ;)'


@app.route(admin_entrance, methods=['GET', 'POST'])
def admin():
    form = AdminForm()
    if form.validate_on_submit():
        session['admin'] = True
        return redirect('/admin/control')
    return render_template('form.html', form=form)


@app.route('/admin/control', methods=['GET', 'POST'])
@app.route(admin_entrance + '/control', methods=['GET', 'POST'])
def control():
    if not session.get('admin'):
        abort(400)
    users = User.query.all()
    return render_template('control.html', users=users)


@app.route('/admin/add', methods=['GET', 'POST'])
def admin_add():
    if not session.get('admin'):
        abort(400)
    form = AdminAddForm()
    if form.validate_on_submit():
        n = []
        for i in range(10):
            n.append(str(random.randint(0, 9)))
        active_code = ''.join(n)
        hashed_password = hashlib.md5()
        hashed_password.update(form.password.data.encode(encoding='utf-8'))
        fcpuser = User(name=form.name.data, email=form.email.data, password=hashed_password.hexdigest(),
                       account_type=form.account_type.data, active_code=active_code, active_state=True)
        db.session.add(fcpuser)
        flash(string_add_success)
        return redirect(url_for('admin_add'))
    return render_template('adminadd.html', form=form)


@app.route('/admin/remove', methods=['POST'])
def admin_remove_user():
    if session.get('admin'):
        fcp_user = User.query.filter_by(id=request.form.get('id')).first()
        if fcp_user:
            db.session.delete(fcp_user)
        return 'ok'
    abort(400)


@app.route('/admin/ban', methods=['POST'])
def admin_ban_user():
    if session.get('admin'):
        fcpuser = User.query.filter_by(id=request.form.get('id')).first()
        if fcpuser:
            fcpuser.banned = True
            db.session.add(fcpuser)
        return 'ok'
    abort(400)


@app.route('/admin/unban', methods=['POST'])
def admin_normal():
    if session.get('admin'):
        fcpuser = User.query.filter_by(id=request.form.get('id')).first()
        fcpuser.banned = False
        db.session.add(fcpuser)
        return 'ok'
    abort(400)


@app.route('/admin/sendmail', methods=['GET', 'POST'])
def admin_send_mail():
    if not session.get('admin'):
        abort(400)
    form = AdminSendMailForm()
    if form.validate_on_submit():
        send_mail(form.email.data, form.content.data, form.content.data, 'None', 0)
    return render_template('sendmail.html', form=form)


@app.errorhandler(405)
def bad_request(e):
    print("405" + str(e))
    return render_template('error.html', code='400'), 500


@app.errorhandler(404)
def page_not_found(e):
    print("404" + str(e))
    return render_template('error.html', code='404'), 404


@app.errorhandler(500)
def internal_server_error(e):
    print("500" + str(e))
    return render_template('error.html', code='500'), 500


@app.errorhandler(400)
def bad_request(e):
    print("400" + str(e))
    return render_template('error.html', code='400'), 500


@app.route('/cdn/<path:filename>')
def download(filename):
    return send_from_directory('static', filename, as_attachment=True)


@app.route('/app')
def android_app():
    return render_template("announcement.html", title='安卓应用即将上线，敬请期待！', content='其实已经放弃了')


def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1] in ALLOWED_EXTENSIONS


@app.route('/file/upload', methods=['GET', 'POST'])
def upload_file():
    if request.method == 'POST':
        file = request.files['file']
        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            file.save(os.path.join(UPLOAD_FOLDER, filename))
            return render_template("announcement.html", title='上传成功！', content='')
        return render_template("announcement.html", title='抱歉，不支持上传这种类型的文件！', content='')
    return render_template('upload.html')


if __name__ == '__main__':
    print('本地调试请访问 http://localhost/ 或 http://127.0.0.1/')
    app.run(debug=True, host='0.0.0.0', port=80)

    