import os

domain = "http://localhost"

admin_entrance = "/phpyouradmin"

basedir = os.path.abspath(os.path.dirname(__file__))
SQLALCHEMY_DATABASE_URI = 'sqlite:///' + os.path.join(basedir, 'data.sqlite')
SQLALCHEMY_COMMIT_ON_TEARDOWN = True
SQLALCHEMY_TRACK_MODIFICATIONS = True

MAIL_SERVER = 'smtp.qq.com'
MAIL_PORT = 465
MAIL_USE_SSL = True
MAIL_USERNAME = ''
MAIL_PASSWORD = ""

ADMIN_NAME = "aynxul03@gmail.com"
ADMIN_PASS = "aynxul03"


UPLOAD_FOLDER = r'upldfldr'
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}

string_data_required = '必填'
string_account_type = '账号类型'
string_come_on_baby = '你加油'
string_admin_email = '管理员邮箱'
string_admin_password = '管理员密码'
string_email_bond = '邮箱已被其他账号绑定，请登录或联系管理员'
string_email_not_registered = '该邮箱未在本站注册过'
string_email_required = '请输入邮箱'
string_email_invalid = '邮箱不可用'
string_account_already_activated = '您的账号已激活，请勿重复激活！'
string_account_banned = '该账号已被封禁，请联系系统管理员'
string_account_not_activated = '该账号还未激活，请登录注册邮箱并使用激活链接完成注册后登录'
string_password_empty = '请输入密码'
string_password_wrong = '邮箱不存在或密码不正确'
string_password_too_short = '密码请长于6位'
string_password_confirm_required = '请再次输入密码'
string_password_confirm_failure = '两次输入的密码不一致'
string_password_no_space = '密码中不能包含空格'
string_student_id_exist = '该学号已被其他学生使用'
string_student_id_required = '请输入学号'
string_logout_success = '账号退出登录成功，最好关闭所有浏览器标签页'
string_not_logged_in = '未登录'
string_quit_when_not_logged_in = '压根没登陆你退出个寂寞'
string_check_email_to_activate = '请查收邮件以继续完成注册'
string_check_email_to_change_password = '请查收邮件以完成密码修改'
string_register = '注册'
string_login = '登录'
string_teacher = '教师'
string_student = '学生'
string_password_change = '密码修改'
string_password_reset_code_used = '您已使用此验证码修改过密码，如需再次修改密码请重新提交一次请求。'
string_add_success = '添加成功'
string_student_name_empty = '学生姓名不得为空'
string_student_name_too_long = '学生姓名不得超过 10 个字符'
string_class_name_too_long = '专业班级不得超过 15 个字符'
string_address_too_long = '所在寝室不得超过 15 个字符'
string_add_student = '添加学生'
string_search = '搜索'
string_search_input_empty = '搜索关键词不得为空'
string_send_mail = '发送邮件'
