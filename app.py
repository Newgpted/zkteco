import sys
import socket
import os  # 添加这个导入
import logging  # 添加这个导入
from logging.handlers import RotatingFileHandler  # 添加这个导入
import tkinter as tk
from tkinter.scrolledtext import ScrolledText
import tkinter.messagebox as messagebox  # 添加这个导入
import threading
from flask import Flask, render_template, request, redirect, url_for, flash, jsonify, session, send_file, current_app, \
    abort
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_migrate import Migrate
from flask_session import Session
from flask_wtf import CSRFProtect, FlaskForm
from werkzeug.security import generate_password_hash, check_password_hash
import pymysql
import queue
import pystray
from pystray import Icon, MenuItem as item
from PIL import Image, ImageDraw, ImageFont
from datetime import datetime, timedelta  # 确保正确导入用于时间处理的库
import random
import string
from forms import LoginForm
from io import BytesIO  # 确保导入这个模块
import pythoncom  # 确保导入这个模块
import win32com.client  # Import win32com.client
import pandas as pd
import json
from cryptography.fernet import Fernet
import mysql.connector  # 导入 mysql.connector 库
from mysql.connector import Error

pymysql.install_as_MySQLdb()

app = Flask(__name__)
app.config['SECRET_KEY'] = 'N@6Sr4Yopas5%!pdmF'
app.config['WTF_CSRF_SECRET_KEY'] = 'Oj5.1$a)37ogkVmWKs'
csrf = CSRFProtect(app)

# 创建日志目录
if not os.path.exists('log'):
    os.makedirs('log')

# 设置日志文件路径
log_filename = os.path.join('log', f"log_{datetime.now().strftime('%Y-%m-%d')}.log")
log_handler = RotatingFileHandler(log_filename, maxBytes=50 * 1024 * 1024, backupCount=5)
log_handler.setLevel(logging.INFO)
log_formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
log_handler.setFormatter(log_formatter)

logger = logging.getLogger()
logger.setLevel(logging.INFO)
logger.addHandler(log_handler)

# 数据库配置
# 数据库配置文件路径
DATABASE_CONFIG_FILE = 'database_config.json'

# 默认数据库配置
DEFAULT_DB_CONFIG = {
    "host": "localhost",
    "user": "root",
    "password": "",
    "database": "zkteco"
}


def generate_key():
    """生成 Fernet 密钥"""
    key = Fernet.generate_key()
    with open("secret.key", "wb") as key_file:
        key_file.write(key)


def load_key():
    """从文件加载 Fernet 密钥"""
    return open("secret.key", "rb").read()


# 在程序启动时生成密钥
if not os.path.exists("secret.key"):
    generate_key()

# 加载密钥
key = load_key()


# 从配置文件读取数据库配置
def load_db_config():
    try:
        with open(DATABASE_CONFIG_FILE, 'r') as f:
            config = json.load(f)
            # 解密密码
            if config.get('password'):
                try:
                    config['password'] = decrypt_password(config['password'], key)
                except InvalidToken:
                    return DEFAULT_DB_CONFIG  # 返回默认配置，提示用户重新设置密码
            return config
    except FileNotFoundError:
        return DEFAULT_DB_CONFIG


# 保存数据库配置到文件
def save_db_config(config):
    # 加密密码
    if config.get('password'):
        config['password'] = encrypt_password(config['password'], key)
    with open(DATABASE_CONFIG_FILE, 'w') as f:
        json.dump(config, f)


# 加密数据库密码
def encrypt_password(password, key):
    """使用 Fernet 加密密码"""
    f = Fernet(key)
    return f.encrypt(password.encode()).decode()


# 解密数据库密码
def decrypt_password(encrypted_password, key):
    """使用 Fernet 解密密码"""
    f = Fernet(key)
    return f.decrypt(encrypted_password.encode()).decode()


# 数据库配置
if os.path.exists(DATABASE_CONFIG_FILE):  # 检查配置文件是否存在
    db_config = load_db_config()
else:
    db_config = DEFAULT_DB_CONFIG  # 使用默认配置

app.config[
    'SQLALCHEMY_DATABASE_URI'] = f"mysql+pymysql://{db_config['user']}:{db_config['password']}@{db_config['host']}/{db_config['database']}"
app.config['SESSION_TYPE'] = 'filesystem'
app.permanent_session_lifetime = timedelta(minutes=10)
db = SQLAlchemy(app)
migrate = Migrate(app, db)
login_manager = LoginManager(app)
login_manager.login_view = 'login'
sess = Session(app)


# --- 数据库设置窗口 ---
# ... 其他代码 ...

def test_database_connection():
    """使用 mysql.connector 测试数据库连接"""
    global host_entry, username_entry, password_entry, database_entry

    print("测试连接函数被调用")
    # print(f"参数：host={host_entry.get()}, user={username_entry.get()}, pwd={password_entry.get()}, db={database_entry.get()}")

    connection = None  # 初始化 connection 变量
    try:
        connection = mysql.connector.connect(
            host=host_entry.get(),
            user=username_entry.get(),
            password=password_entry.get(),
            database=database_entry.get(),
            # 将字符集校对规则改为 utf8_general_ci
            collation='utf8mb4_general_ci'  # 或 'utf8mb4_unicode_ci'
        )

        if connection.is_connected():
            print("数据库连接成功！请保存后重启程序！")
            messagebox.showinfo("成功", "数据库连接测试成功！请保存后重启程序")
        else:
            print("数据库连接失败")
            messagebox.showerror("错误", "数据库连接测试失败！")

    except Error as e:
        print(f"数据库连接测试失败: {e}")
        messagebox.showerror("错误", f"数据库连接测试失败: {e}")
    finally:
        # 检查 connection 是否已经赋值
        if connection is not None and connection.is_connected():
            connection.close()


# --- 数据库设置窗口 ---
def save_database_settings():
    global db_config
    # 获取用户输入的数据库配置信息
    db_config = {
        "host": host_entry.get(),
        "user": username_entry.get(),
        "password": password_entry.get(),
        "database": database_entry.get()
    }
    # 保存数据库配置到文件
    save_db_config(db_config)
    messagebox.showinfo("成功", "数据库配置已保存！请重启程序")
    settings_window.destroy()

    # 从配置文件重新加载数据库配置 (确保读取的是最新的配置)
    db_config = load_db_config()

    # 更新 app 的数据库配置
    app.config[
        'SQLALCHEMY_DATABASE_URI'] = f"mysql+pymysql://{db_config['user']}:{db_config['password']}@{db_config['host']}/{db_config['database']}"

    # 关闭现有连接并释放资源
    with app.app_context():
        db.session.remove()
        db.engine.dispose()


def open_settings_window():
    global settings_window, host_entry, username_entry, password_entry, database_entry
    settings_window = tk.Toplevel(root)
    settings_window.title("数据库设置")
    settings_window.geometry("300x250")
    settings_window.resizable(False, False)

    # 读取数据库配置
    global db_config
    db_config = load_db_config()

    host_label = tk.Label(settings_window, text="地址:")
    host_label.grid(row=0, column=0, padx=5, pady=5, sticky="w")
    host_entry = tk.Entry(settings_window)
    host_entry.grid(row=0, column=1, padx=5, pady=5)
    host_entry.insert(0, db_config.get("host", "localhost"))

    username_label = tk.Label(settings_window, text="用户名:")
    username_label.grid(row=1, column=0, padx=5, pady=5, sticky="w")
    username_entry = tk.Entry(settings_window)
    username_entry.grid(row=1, column=1, padx=5, pady=5)
    username_entry.insert(0, db_config.get("user", "root"))

    password_label = tk.Label(settings_window, text="密码:")
    password_label.grid(row=2, column=0, padx=5, pady=5, sticky="w")
    password_entry = tk.Entry(settings_window, show="*")
    password_entry.grid(row=2, column=1, padx=5, pady=5)
    password_entry.insert(0, db_config.get("password", ""))

    database_label = tk.Label(settings_window, text="数据库:")
    database_label.grid(row=3, column=0, padx=5, pady=5, sticky="w")  # 添加 grid 布局
    database_entry = tk.Entry(settings_window)
    database_entry.grid(row=3, column=1, padx=5, pady=5)  # 添加 grid 布局
    database_entry.insert(0, db_config.get("database", "zkteco"))

    # 添加测试连接按钮
    test_button = tk.Button(settings_window, text="测试连接", command=test_database_connection)
    test_button.grid(row=4, column=0, columnspan=2, pady=10)

    save_button = tk.Button(settings_window, text="保存", command=save_database_settings)
    save_button.grid(row=5, column=0, columnspan=2, pady=10)  # 添加 grid 布局


# 数据库模型
class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(150), nullable=False)
    role = db.Column(db.String(20), nullable=False, default='user')
    nickname = db.Column(db.String(255))
    allowed_tags = db.Column(db.String(255), nullable=True)
    allowed_groups = db.Column(db.String(255), nullable=True)
    is_disabled = db.Column(db.Boolean, default=False)
    login_attempts = db.Column(db.Integer, default=0)
    last_attempt = db.Column(db.DateTime, nullable=True)


class Tag(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False, unique=True)


class Region(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), unique=True, nullable=False)


class Device(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    ip_address = db.Column(db.String(100), nullable=False)
    comm_key = db.Column(db.Integer, nullable=True, default=0)
    port = db.Column(db.Integer, nullable=False, default=4370)
    alias = db.Column(db.String(100), nullable=False)
    region_id = db.Column(db.Integer, db.ForeignKey('region.id'), nullable=False)
    tags = db.relationship('Tag', secondary='device_tags', lazy='subquery', backref=db.backref('devices', lazy=True))
    group = db.Column(db.String(100), nullable=True)


device_tags = db.Table(
    'device_tags',
    db.Column('device_id', db.Integer, db.ForeignKey('device.id'), primary_key=True),
    db.Column('tag_id', db.Integer, db.ForeignKey('tag.id'), primary_key=True)
)


class Log(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)
    action = db.Column(db.String(150), nullable=False)
    timestamp = db.Column(db.DateTime, default=db.func.current_timestamp())
    username = db.Column(db.String(150))
    user_ip_address = db.Column(db.String(100))


# 工具函数
def log_action(user_id, action, username, user_ip_address=None, device_alias=None, code=None):
    if device_alias:
        action = f"{action} ({device_alias})"
    if code:
        action = f"{action} - 事由: {code}"
    new_log = Log(user_id=user_id, action=action, username=username, user_ip_address=user_ip_address)
    db.session.add(new_log)
    db.session.commit()


def create_user(username, password, nickname, role='user', is_disabled=False):
    if not User.query.filter_by(username=username).first():
        hashed_password = generate_password_hash(password)
        new_user = User(username=username, password=hashed_password, nickname=nickname, role=role,
                        is_disabled=is_disabled)
        db.session.add(new_user)
        db.session.commit()


# 验证码生成函数
def generate_captcha():
    img = Image.new('RGB', (100, 30), color=(255, 255, 255))
    draw = ImageDraw.Draw(img)
    font = ImageFont.truetype("arial.ttf", 20)
    captcha_text = ''.join(random.choices(string.ascii_uppercase + string.digits, k=6))
    draw.text((10, 5), captcha_text, font=font, fill=(0, 0, 0))
    buffer = BytesIO()
    img.save(buffer, format="PNG")
    buffer.seek(0)
    session['captcha'] = captcha_text
    return buffer


# 会话持续事件
@app.before_request
def make_session_permanent():
    session.permanent = True


@login_manager.user_loader
def load_user(user_id):
    with current_app.app_context():
        user = db.session.get(User, int(user_id))
    return user


# 视图函数
@app.route('/')
@login_required
def index():
    from forms import CSRFForm  # 添加这个导入

    selected_region_id = request.args.get('region')
    filter_text = request.args.get('filter', '').strip()
    devices_query = Device.query

    # 保持现有的查询逻辑
    if current_user.role == 'admin':
        if selected_region_id:
            devices_query = devices_query.filter_by(region_id=selected_region_id)
        if filter_text:
            devices_query = devices_query.filter(Device.alias.contains(filter_text))
    else:
        allowed_tags = [int(tag) for tag in current_user.allowed_tags.split(',')] if current_user.allowed_tags else []
        allowed_groups = current_user.allowed_groups.split(',') if current_user.allowed_groups else []
        if selected_region_id:
            devices_query = devices_query.filter_by(region_id=selected_region_id)
        if allowed_tags or allowed_groups:
            devices_query = devices_query.filter(
                db.or_(
                    Device.tags.any(Tag.id.in_(allowed_tags)),
                    Device.group.in_(allowed_groups)
                )
            )
        else:
            devices_query = devices_query.filter(False)
        if filter_text:
            devices_query = devices_query.filter(Device.alias.contains(filter_text))
    if not selected_region_id and not filter_text:
        devices_query = Device.query

    devices = devices_query.all()
    regions = Region.query.all()
    user_agent = request.headers.get('User-Agent').lower()

    form = CSRFForm()  # 创建 CSRF 表单实例

    if any(device in user_agent for device in ["android", "iphone", "ipad", "windows phone"]):
        template = 'mindex.html'
    else:
        template = 'index.html'

    return render_template(template, nickname=current_user.nickname, devices=devices, regions=regions,
                           selected_region_id=selected_region_id, filter_text=filter_text, form=form)


@app.route('/captcha')
def captcha():
    buffer = generate_captcha()
    return send_file(buffer, mimetype='image/png')


@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    session.setdefault('login_attempts', 0)

    if form.validate_on_submit():
        username = form.username.data
        password = form.password.data
        captcha = form.captcha.data
        user = User.query.filter_by(username=username).first()
        user_ip = request.remote_addr

        if user:
            # 检查用户是否被禁用
            if user.is_disabled:
                log_action(None, f"用户已被禁用：", username, user_ip_address=user_ip)
                flash('用户已被禁用，请联系管理员。', 'danger')
                return redirect(url_for('login'))

            # 如果超过5次错误或上一次失败时间超过一定时间（如15分钟），显示验证码
            if user.login_attempts >= 5:
                if not captcha or captcha.lower() != session.get('captcha', '').lower():
                    flash('验证码错误，请重新输入。', 'danger')
                    return redirect(url_for('login'))

            if check_password_hash(user.password, password):
                login_user(user)
                session.permanent = True
                user.login_attempts = 0  # 登录成功时重置尝试次数
                session.pop('captcha', None)  # 移除Captcha
                db.session.commit()
                flash('登录成功', 'success')
                log_action(user.id, f"用户登录：   {user.nickname}", user.username, user_ip_address=user_ip)
                return redirect(url_for('index'))
            else:
                user.login_attempts += 1
                session['login_attempts'] = user.login_attempts
                db.session.commit()

                # 如果用户尝试登录失败次数超过5次，生成验证码并存储在Session中
                if user.login_attempts >= 5:
                    session['captcha'] = generate_captcha()

                log_action(None, "登录失败：", username, user_ip_address=user_ip)
                flash('登录失败，请检查用户名和密码', 'danger')
                return redirect(url_for('login'))
        else:
            flash('用户不存在。', 'danger')

    return render_template('login.html', form=form)


@app.route('/logout')
@login_required
def logout():
    user_ip = request.remote_addr
    log_action(current_user.id, "用户退出登录：", current_user.username, user_ip_address=user_ip)  # 确保记录退出登录日志
    logout_user()
    return redirect(url_for('login'))


@app.route('/add_device', methods=['POST'])
@login_required
def add_device():
    if current_user.role != 'admin':
        flash("你没有权限访问此页面", "danger")
        return redirect(url_for('index'))

    ip_address = request.form['ip_address']
    alias = request.form['alias']
    port = request.form.get('port', 4370)
    region_id = request.form['region_id']
    tags = request.form.getlist('tags')
    comm_key = request.form['comm_key']
    comm_key = int(comm_key) if comm_key else None

    device = Device(ip_address=ip_address, alias=alias, region_id=region_id, comm_key=comm_key, port=port)
    db.session.add(device)
    db.session.commit()

    if tags:
        for tag_id in tags:
            tag = db.session.get(Tag, int(tag_id))
            if tag:
                device.tags.append(tag)

    db.session.commit()
    log_action(current_user.id, f"添加设备: {device.alias} ({device.ip_address})", current_user.username)
    flash('门禁添加成功', 'success')
    return redirect(url_for('manage_devices'))


# 在视图函数中传递 CSRF 表单对象
@app.route('/manage_devices')
@login_required
def manage_devices():
    from forms import CSRFForm  # 确保导入 CSRFForm

    if current_user.role != 'admin':
        flash("你没有权限访问此页面", "danger")
        return redirect(url_for('index'))

    selected_region_id = request.args.get('region')
    selected_tag_id = request.args.get('tag')

    devices_query = Device.query
    tags = Tag.query.all()
    users = User.query.all()
    regions = Region.query.all()
    all_devices = devices_query.all()

    if current_user.role != 'admin':
        allowed_tags = [int(tag) for tag in current_user.allowed_tags.split(',')] if current_user.allowed_tags else []
        allowed_groups = current_user.allowed_groups.split(',') if current_user.allowed_groups else []

        if allowed_tags or allowed_groups:
            devices_query = devices_query.filter(
                db.or_(
                    Device.tags.any(Tag.id.in_(allowed_tags)),
                    Device.group.in_(allowed_groups)
                )
            )
        else:
            devices_query = devices_query.filter(False)

    if selected_region_id:
        devices_query = devices_query.filter_by(region_id=selected_region_id)

    if selected_tag_id:
        devices_query = devices_query.filter(Device.tags.any(Tag.id == selected_tag_id))

    devices = devices_query.order_by(Device.id).all()
    device_count = len(devices)
    user_count = len(users)
    tag_device_counts = {tag.id: len(tag.devices) for tag in tags}
    selected_tag_device_count = tag_device_counts[int(selected_tag_id)] if selected_tag_id else 0

    form = CSRFForm()  # 创建 CSRF 表单实例

    return render_template('manage_devices.html', devices=devices, users=users, regions=regions,
                           selected_region_id=selected_region_id, selected_tag_id=selected_tag_id, tags=tags,
                           device_count=device_count, user_count=user_count, tag_device_counts=tag_device_counts,
                           selected_tag_device_count=selected_tag_device_count, all_devices=all_devices, form=form)


@app.route('/users')
def users():
    page = request.args.get(get_page_parameter(), type=int, default=1)
    per_page = 10
    total = User.query.count()
    users = (User.query.order_by(User.id).paginate(page, per_page, False).items)

    pagination = Pagination(page=page, total=total, per_page=per_page, css_framework='bootstrap4')
    return render_template('users.html', users=users, pagination=pagination)


@app.route('/delete_device/<int:device_id>', methods=['POST'])
@login_required
def delete_device(device_id):
    region_id = request.form.get('region_id')
    if current_user.role != 'admin':
        flash("你没有权限进行此操作", "danger")
        return redirect(url_for('index'))

    device = db.session.get(Device, device_id)  # 使用 Session.get 方法
    if device is None:
        abort(404)

    try:
        db.session.delete(device)
        db.session.commit()
        log_action(current_user.id, f"删除设备: {device.alias} ({device.ip_address})", current_user.username)
        flash("删除门禁控制器成功", "success")
    except Exception as e:
        db.session.rollback()
        flash(str(e), "danger")

    return redirect(url_for('manage_devices', region=region_id))


@app.route('/open_door/<int:device_id>', methods=['POST'])
@login_required
def open_door(device_id):
    device = Device.query.get_or_404(device_id)
    code = request.form.get('code', '')
    region_id = request.form.get('region_id')
    filter_text = request.form.get('filter')

    if not code:
        flash('请填写必要的字段。', 'danger')
        return redirect(url_for('index', region=region_id, filter=filter_text))

    comm_key = device.comm_key
    alias = device.alias
    port = device.port
    result = try_open_door(device.ip_address, alias, comm_key=comm_key, port=port)
    log_action(current_user.id, f"远程开门： {device.alias} ({device.ip_address}): {result}", current_user.username,
               code=code)

    flash(result, 'info')
    return redirect(url_for('index', region=region_id, filter=filter_text))


@app.route('/add_user', methods=['POST'])
@login_required
def add_user():
    if current_user.role != 'admin':
        flash("你没有权限进行此操作。", "danger")
        return redirect(url_for('index'))

    username = request.form.get('username')
    password = request.form.get('password')
    nickname = request.form.get('nickname')
    role = request.form.get('role')
    tags = request.form.getlist('tags')
    allowed_groups = request.form.get('allowed_groups')
    is_disabled = request.form.get('is_disabled') == 'on'  # 获取是否禁用的值
    section = request.form.get('section')

    if not username or not password or not nickname or not role:
        flash("所有字段都是必填项。", "danger")
        return redirect(url_for('manage_devices', section=section))

    if User.query.filter_by(username=username).first():
        flash("该用户已经存在。", "danger")
        return redirect(url_for('manage_devices', section=section))

    try:
        create_user(username, password, nickname, role, is_disabled)  # 调用 create_user 函数并传递 is_disabled 参数
        user = User.query.filter_by(username=username).first()

        if tags:
            user.allowed_tags = ','.join(tags)

        if allowed_groups:
            user.allowed_groups = allowed_groups

        db.session.commit()
        log_action(current_user.id, f"添加用户: {username}", current_user.username)
        flash("添加用户成功", "success")
    except Exception as e:
        db.session.rollback()
        flash(str(e), "danger")

    return redirect(url_for('manage_devices', section=section))


@app.route('/delete_user/<int:user_id>', methods=['POST'])
@login_required
def delete_user(user_id):
    section = request.form.get('section')
    if current_user.role != 'admin':
        flash("你没有权限进行此操作", "danger")
        return redirect(url_for('index'))

    user = db.session.get(User, user_id)
    if user is None:
        abort(404)

    if user.username == 'admin':
        flash("超级管理员用户不能被删除", "danger")
        return redirect(url_for('manage_devices', section=section))

    try:
        db.session.delete(user)
        db.session.commit()
        log_action(current_user.id, f"删除用户: {user.username}", current_user.username)
        flash("删除用户成功", "success")
    except Exception as e:
        db.session.rollback()
        flash(str(e), "danger")
    return redirect(url_for('manage_devices', section=section))


@app.route('/edit_user', methods=['POST'])
@login_required
def edit_user():
    if current_user.role != 'admin':
        flash("你没有权限进行此操作", "danger")
        return redirect(url_for('index'))

    user_id = request.form.get('user_id')
    username = request.form.get('username')
    nickname = request.form.get('nickname')
    role = request.form.get('role')
    tags = request.form.getlist('tags')
    allowed_groups = request.form.get('allowed_groups')
    section = request.form.get('section')

    user = db.session.get(User, user_id)  # 使用 Session.get 方法
    if user is None:
        flash("用户不存在。", "danger")
        return redirect(url_for('manage_devices', section=section))

    user.username = username
    user.nickname = nickname
    user.role = role
    user.allowed_tags = ','.join(tags) if tags else None
    user.allowed_groups = allowed_groups

    db.session.commit()
    log_action(current_user.id, f"修改用户: {user.username}", current_user.username)
    flash("用户信息修改成功", "success")

    return redirect(url_for('manage_devices', section=section))


@app.route('/add_region', methods=['POST'])
@login_required
def add_region():
    if current_user.role != 'admin':
        flash("你没有权限进行此操作", "danger")
        return redirect(url_for('index'))

    region_name = request.form['region']
    section = request.form.get('section')

    existing_region = Region.query.filter_by(name=region_name).first()
    if existing_region:
        flash('区域已存在', 'danger')
    else:
        new_region = Region(name=region_name)
        db.session.add(new_region)
        db.session.commit()
        log_action(current_user.id, f"添加区域: {region_name}", current_user.username)
        flash('区域添加成功', 'success')

    return redirect(url_for('manage_devices', section=section))


@app.route('/delete_region/<int:region_id>', methods=['POST'])
@login_required
def delete_region(region_id):
    if current_user.role != 'admin':
        flash("你没有权限进行此操作", "danger")
        return redirect(url_for('index'))

    section = request.form.get('section')

    region = Region.query.get(region_id)
    if not region:
        flash('区域不存在', 'danger')
    else:
        db.session.delete(region)
        db.session.commit()
        log_action(current_user.id, f"删除区域: {region.name}", current_user.username)
        flash('区域删除成功', 'success')

    return redirect(url_for('manage_devices', section=section))


@app.route('/toggle_user_status/<int:user_id>', methods=['POST'])
@login_required
def toggle_user_status(user_id):
    if current_user.role != 'admin':
        flash("你没有权限进行此操作", "danger")
        return redirect(url_for('index'))

    section = request.form.get('section')
    user = User.query.get_or_404(user_id)
    if user.username == 'admin':
        flash("超级管理员用户不能被禁用", "danger")
        return redirect(url_for('manage_devices', section=section))

    try:
        user.is_disabled = not user.is_disabled
        db.session.commit()
        status = '禁用' if user.is_disabled else '启用'
        log_action(current_user.id, f"用户{status}: {user.username}", current_user.username)
        flash(f"用户{status}成功", "success")
    except Exception as e:
        db.session.rollback()
        flash(str(e), "danger")
    return redirect(url_for('manage_devices', section=section))  # 更改为 'manage_devices' 或者你的用户管理页面


@app.route('/edit_region', methods=['POST'])
@login_required
def edit_region():
    if current_user.role != 'admin':
        flash("你没有权限进行此操作", "danger")
        return redirect(url_for('index'))

    region_id = request.form['region_id']
    region_name = request.form['region_name']
    section = request.form.get('section')

    region = Region.query.get(region_id)
    if not region:
        flash('区域不存在', 'danger')
    else:
        region.name = region_name
        db.session.commit()
        log_action(current_user.id, f"编辑区域: {region_name}", current_user.username)
        flash('区域编辑成功', 'success')

    return redirect(url_for('manage_devices', section=section))


@app.route('/add_tag', methods=['POST'])
@login_required
def add_tag():
    if current_user.role != 'admin':
        flash("你没有权限进行此操作", "danger")
        return redirect(url_for('index'))

    name = request.form['tag_name']
    section = request.form.get('section')
    existing_tag = Tag.query.filter_by(name=name).first()
    if existing_tag:
        flash('标签已存在', 'danger')
    else:
        new_tag = Tag(name=name)
        db.session.add(new_tag)
        db.session.commit()
        log_action(current_user.id, f"添加标签: {name}", current_user.username)
        flash('标签添加成功！', 'success')
    return redirect(url_for('manage_devices', section=section))


@app.route('/delete_tag/<int:tag_id>', methods=['POST'])
@login_required
def delete_tag(tag_id):
    if current_user.role != 'admin':
        flash("你没有权限进行此操作", "danger")
        return redirect(url_for('index'))

    tag = Tag.query.get_or_404(tag_id)
    tag_name = tag.name
    section = request.form.get('section')
    db.session.delete(tag)
    db.session.commit()
    log_action(current_user.id, f"删除标签: {tag_name}", current_user.username)
    flash('标签删除成功！', 'success')
    return redirect(url_for('manage_devices', section=section))


@app.route('/edit_tag', methods=['POST'])
@login_required
def edit_tag():
    if current_user.role != 'admin':
        flash("你没有权限进行此操作", "danger")
        return redirect(url_for('index'))

    tag_id = request.form.get('tag_id')
    tag_name = request.form.get('tag_name')
    device_ids = request.form.getlist('devices')
    section = request.form.get('section')

    tag = db.session.get(Tag, tag_id)
    if not tag:
        flash('指定的标签不存在。', 'danger')
        return redirect(url_for('manage_devices', section=section))

    tag.name = tag_name

    if device_ids:
        devices = Device.query.filter(Device.id.in_(device_ids)).all()
        tag.devices = devices

    db.session.commit()
    log_action(current_user.id, f"修改标签: {tag_name}", current_user.username)
    flash('标签已成功更新。', 'success')
    return redirect(url_for('manage_devices', section=section))


@app.route('/get_tag_devices/<int:tag_id>', methods=['GET'])
@login_required
def get_tag_devices(tag_id):
    tag = db.session.get(Tag, tag_id)
    if not tag:
        return jsonify({'error': 'Tag not found'}), 404
    devices = [{'id': device.id, 'alias': device.alias, 'ip_address': device.ip_address} for device in tag.devices]
    device_count = len(devices)
    return jsonify({'devices': devices, 'device_count': device_count})


@app.route('/delete_device_tag', methods=['POST'])
@login_required
def delete_device_tag():
    device_id = request.form.get('device_id')
    tag_id = request.form.get('tag_id')

    device = db.session.get(Device, device_id)
    tag = db.session.get(Tag, tag_id)

    if not device or not tag:
        flash('Device or tag not found', 'danger')
        return redirect(url_for('manage_devices'))

    device.tags.remove(tag)
    db.session.commit()
    log_action(current_user.id, f"从设备： {device.alias} 中删除标签: {tag.name}", current_user.username)
    flash('Tag removed from device', 'success')
    return redirect(url_for('manage_devices'))


@app.route('/add_devices_to_tag', methods=['POST'])
@login_required
def add_devices_to_tag():
    tag_id = request.form.get('tag_id')
    device_ids = request.form.getlist('devices')

    tag = db.session.get(Tag, tag_id)
    if not tag:
        flash('Tag not found', 'danger')
        return redirect(url_for('manage_devices'))

    for device_id in device_ids:
        device = db.session.get(Device, device_id)
        if device and tag not in device.tags:
            device.tags.append(tag)

    db.session.commit()
    log_action(current_user.id, f"给标签： {tag.name} 添加了设备", current_user.username)
    flash('Devices added to tag', 'success')
    return redirect(url_for('manage_devices'))


@app.route('/remove_device_from_tag', methods=['POST'])
@login_required
def remove_device_from_tag():
    data = request.get_json()
    device_id = data.get('device_id')
    tag_id = data.get('tag_id')
    device = Device.query.get(device_id)
    tag = Tag.query.get(tag_id)
    if not device or not tag:
        return jsonify({'success': False, 'error': 'Device or Tag not found'})
    try:
        tag.devices.remove(device)
        db.session.commit()
        return jsonify({'success': True})
    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'error': str(e)})


@app.route('/logs')
@login_required
def view_logs():
    if current_user.role != 'admin':
        flash("你没有权限进行此操作。", "danger")
        return redirect(url_for('index'))

    log_type = request.args.get('type')
    device_id = request.args.get('device_id')
    start_date = request.args.get('start_date')
    end_date = request.args.get('end_date')
    page = request.args.get('page', 1, type=int)
    per_page = request.args.get('per_page', 15, type=int)

    user_logs_query = Log.query.order_by(Log.timestamp.desc())

    if log_type:
        user_logs_query = user_logs_query.filter(Log.action.like(f'%{log_type}%'))

    if device_id:
        device = Device.query.get(device_id)
        if device:
            user_logs_query = user_logs_query.filter(Log.action.like(f'%{device.alias}%'))

    if start_date:
        user_logs_query = user_logs_query.filter(Log.timestamp >= start_date)

    if end_date:
        user_logs_query = user_logs_query.filter(Log.timestamp <= end_date + ' 23:59:59')

    user_logs_pagination = user_logs_query.paginate(page=page, per_page=per_page, error_out=False)

    devices = Device.query.all()

    return render_template('logs.html',
                           user_logs=user_logs_pagination.items,
                           devices=devices,
                           user_pagination=user_logs_pagination,
                           per_page=per_page,
                           log_type=log_type,
                           device_id=device_id,
                           start_date=start_date,
                           end_date=end_date)


@app.route('/change_password', methods=['POST'])
@login_required
def change_password():
    old_password = request.form.get('old_password')
    new_password = request.form.get('new_password')

    if not old_password or not new_password:
        flash('所有字段都是必填项。', 'danger')
        return redirect(url_for('index'))

    user = User.query.get(current_user.id)

    if not check_password_hash(user.password, old_password):
        flash('旧密码不正确。', 'danger')
        return redirect(url_for('index', modal='myModal'))

    user.password = generate_password_hash(new_password)
    db.session.commit()

    log_action(user.id, '用户修改密码', user.username)

    flash('密码修改成功。', 'success')
    return redirect(url_for('index'))


@app.route('/change_user_password', methods=['POST'])
@login_required
def change_user_password():
    if current_user.role != 'admin':
        flash("你没有权限进行此操作", "danger")
        return redirect(url_for('index'))

    user_id = request.form.get('user_id')
    new_password = request.form.get('new_password')
    section = request.form.get('section')

    if not user_id or not new_password:
        flash('所有字段都是必填项。', 'danger')
        return redirect(url_for('manage_devices', section=section))

    user = User.query.get(user_id)
    if not user:
        flash('用户不存在。', 'danger')
        return redirect(url_for('manage_devices', section=section))

    user.password = generate_password_hash(new_password)
    db.session.commit()

    log_action(current_user.id, f'修改密码： {user.username}', current_user.username)

    flash(f'{user.username} 的密码修改成功。', 'success')
    return redirect(url_for('manage_devices', section=section))


@app.route('/edit_device', methods=['POST'])
@login_required
def edit_device():
    if current_user.role != 'admin':
        flash("你没有权限进行此操作", "danger")
        return redirect(url_for('index'))

    device_id = request.form.get('device_id')
    ip_address = request.form.get('ip_address')
    alias = request.form.get('alias')
    region_id = request.form.get('region_id')
    tags = request.form.getlist('tags')

    try:
        comm_key = request.form.get('comm_key')
        comm_key = int(comm_key) if comm_key else None
    except ValueError:
        comm_key = None

    try:
        port = int(request.form.get('port', 4370))
    except ValueError:
        port = 4370

    device = db.session.get(Device, device_id)
    if not device:
        flash('设备不存在。', 'danger')
        return redirect(url_for('manage_devices'))

    device.ip_address = ip_address
    device.alias = alias
    device.region_id = region_id
    device.comm_key = comm_key
    device.port = port

    current_tags = [tag.id for tag in device.tags]

    for tag_id in tags:
        tag_id = int(tag_id)
        if tag_id not in current_tags:
            tag = db.session.get(Tag, tag_id)
            if tag:
                device.tags.append(tag)

    for tag_id in current_tags:
        if str(tag_id) not in tags:
            tag = db.session.get(Tag, tag_id)
            if tag:
                device.tags.remove(tag)

    db.session.commit()

    log_action(current_user.id, f'编辑设备： {device.alias} ({device.ip_address})', current_user.username)

    flash('门禁信息修改成功。', 'success')
    return redirect(url_for('manage_devices', region=region_id))


@app.route('/export_logs')
@login_required
def export_logs():
    log_type = request.args.get('type')
    device_id = request.args.get('device_id')
    start_date = request.args.get('start_date')
    end_date = request.args.get('end_date')

    logs_query = Log.query.order_by(Log.timestamp.desc())

    if log_type:
        logs_query = logs_query.filter(Log.action.like(f'%{log_type}%'))

    if device_id:
        device = Device.query.get(device_id)
        if device:
            logs_query = logs_query.filter(Log.action.like(f'%{device.alias}%'))

    if start_date:
        logs_query = logs_query.filter(Log.timestamp >= start_date)

    if end_date:
        logs_query = logs_query.filter(Log.timestamp <= end_date + ' 23:59:59')

    logs = logs_query.all()

    data = [{
        '序号': log.id,
        '用户ID': log.user_id,
        '用户名': log.username,
        '操作记录': log.action,
        '日期时间': log.timestamp
    } for log in logs]

    df = pd.DataFrame(data)
    output = BytesIO()
    with pd.ExcelWriter(output, engine='xlsxwriter') as writer:
        df.to_excel(writer, index=False, sheet_name='Logs')

    output.seek(0)
    return send_file(output, download_name="logs.xlsx", as_attachment=True)


@app.route('/test_device/<int:device_id>', methods=['POST'])
@login_required
def test_device(device_id):
    region_id = request.form.get('region_id')
    device = Device.query.get_or_404(device_id)
    try:
        port = device.port
        result = try_open_door(device.ip_address, comm_key=device.comm_key, port=port, test_only=True)
        flash(result, 'info')
    except Exception as e:
        flash(str(e), 'danger')
    return redirect(url_for('manage_devices', region=region_id))


# 一些用于网络检查和门禁操作的辅助函数
def check_network(ip_address, port):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(1)
    try:
        result = sock.connect_ex((ip_address, port))
        if result == 0:
            print(f"设备 {ip_address} 网络连接正常")
            return True
        else:
            print(f"设备 {ip_address} 网络连接失败")
            return False
    except Exception as e:
        print(f"无法连接到设备 {ip_address} 的端口 {port}: {e}")
        return False
    finally:
        sock.close()


def try_open_door(ip_address, alias=None, comm_key=None, port=4370, test_only=False):
    rlt = ""
    zk = None
    try:
        pythoncom.CoInitialize()
        zk = win32com.client.Dispatch("zkemkeeper.ZKEM")
        print(f"IP Address: {ip_address}, Alias: {alias}, Port: {port}")
        alias = alias if alias else ip_address
        if not check_network(ip_address, port):
            return f"{alias} ：失败：无法连接设备 (请检查网络和端口)."
        if comm_key:
            if not zk.SetCommPassword(str(comm_key)):
                error_info = zk.GetLastError()
                return f"{alias} ：失败：通讯密码错误，错误码: {error_info}"
        if zk.Connect_Net(ip_address, port):
            if test_only:
                rlt = f"{alias} ：测试连接成功。"
            else:
                if zk.ACUnlock(1, 100):
                    rlt = f"{alias} ：远程开门成功"
                else:
                    error_info = zk.GetLastError()
                    rlt = f"{alias} ：远程开门失败，错误码: {error_info}"
        else:
            error_info = zk.GetLastError()
            rlt = f" {alias} ：失败：通讯密码错误失败，错误码: {error_info}"
    except Exception as e:
        rlt = f"{alias} ：发生异常：{e}"
    finally:
        if zk:
            del zk
        pythoncom.CoUninitialize()
    print(f"Try open door result: {rlt}")
    return rlt


# 系统托盘图标相关代码


# 系统托盘图标相关代码
def on_activate(icon, item):
    if str(item) == "IT-门禁管理系统1.3":
        gui_queue.put("show_window")
    elif str(item) == "设置":
        open_settings_window()
    elif str(item) == "关于":
        gui_queue.put("show_about")
    elif str(item) == "退出":
        gui_queue.put("confirm_exit")


# 修改 create_image 函数来加载你的图标图片
def create_image():
    # 加载图标图片
    icon_image_path = "door.ico"  # 修改为你的图标图片路径
    return Image.open(icon_image_path)


# 用于托盘图标的全局变量
tray_icon = None


def run_tray_icon():
    global tray_icon
    icon = Icon("name", create_image(), "IT-门禁管理系统1.3",
                menu=pystray.Menu(
                    item("IT-门禁管理系统1.3", on_activate),
                    item("设置", on_activate),  # 添加设置菜单项
                    item("关于", on_activate),
                    item("退出", on_activate)
                ),
                on_click=show_window
                )
    tray_icon = icon
    icon.run()


def process_queue():
    try:
        while not gui_queue.empty():
            msg = gui_queue.get_nowait()
            if msg == "confirm_exit":
                if messagebox.askyesno("关闭程序", "你确定要退出吗?"):
                    if tray_icon:
                        tray_icon.stop()
                    root.destroy()
                    sys.exit(0)
            elif msg == "show_window":
                root.deiconify()
            elif msg == "show_about":
                show_about()
    except queue.Empty:
        pass
    root.after(100, process_queue)


def show_about():
    about_window = tk.Toplevel(root)
    about_window.title("关于 IT-门禁管理系统1.3")
    about_window.geometry("400x300")

    about_text = ScrolledText(about_window, wrap='word', state='normal')
    about_text.pack(fill='both', expand=True)

    update_log = """
    IT-门禁管理系统 1.3 更新日志:

    1. 在后台管理中增加门禁数量、用户数量显示。
    2. 增加远程开门页面手机版本、优化页面。
    3. 修改bug 编辑标签时没有列出门禁信息。
    4. 给添加门禁增加端口字段可以自定义修改门禁端口。
    5. 美化后台管理页面整体缩小元素
    """

    about_text.insert("1.3", update_log)
    about_text.configure(state='disabled')


def show_window(icon=None, item=None):
    root.deiconify()  # 显示Tkinter窗口
    root.after(0, lambda: root.state('normal'))  # 恢复窗口


def minimize_to_tray(event=None):
    root.withdraw()  # 隐藏Tkinter窗口
    if tray_icon:
        tray_icon.notify("IT-门禁管理系统1.3", "程序正在后台运行。")


def close_to_tray():
    minimize_to_tray()
    return "break"


def redirect_stdout_to_text(widget):
    class TextRedirector:
        def __init__(self, widget, tag):
            self.widget = widget
            self.tag = tag

        def write(self, message):
            self.widget.configure(state='normal')
            self.widget.insert('end', message, (self.tag,))
            self.widget.configure(state='disabled')
            self.widget.see("end")

        def flush(self):
            pass

    class WidgetLogger(logging.Handler):
        def __init__(self, widget):
            logging.Handler.__init__(self)
            self.widget = widget

        def emit(self, record):
            message = self.format(record)
            self.widget.configure(state='normal')
            self.widget.insert('end', f'{message}\n')
            self.widget.configure(state='disabled')
            self.widget.see("end")

    text_handler = WidgetLogger(widget)
    text_handler.setLevel(logging.INFO)
    formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    text_handler.setFormatter(formatter)

    logger.addHandler(text_handler)

    sys.stdout = TextRedirector(widget, "stdout")
    sys.stderr = TextRedirector(widget, "stderr")


if __name__ == '__main__':
    root = tk.Tk()
    root.withdraw()
    root.title("IT-门禁管理系统1.3")
    root.wm_iconbitmap('door.ico')

    log_text = ScrolledText(root, wrap='word', state='disabled')
    log_text.pack(fill='both', expand=True)
    redirect_stdout_to_text(log_text)  # 确保调用这个函数

    root.protocol("WM_DELETE_WINDOW", close_to_tray)
    root.bind("<Unmap>", lambda event: minimize_to_tray() if root.state() == 'iconic' else None)

    gui_queue = queue.Queue()

    tray_icon_thread = threading.Thread(target=run_tray_icon)
    tray_icon_thread.daemon = True
    tray_icon_thread.start()

    root.after(100, process_queue)

    with app.app_context():
        try:
            db.create_all()
        except Exception as e:
            print(f"数据库连接失败: {e}")
            messagebox.showerror("错误", f"数据库连接失败: {e}，请检查数据库配置！")


    def flask_thread_func():
        print("Starting Flask server...")
        sys.stdout.flush()
        redirect_stdout_to_text(log_text)
        app.run(host='0.0.0.0', port=5001)
        print("Flask 应用已启动，访问 http://127.0.0.1:5001")
        sys.stdout.flush()


    app_thread = threading.Thread(target=flask_thread_func)
    app_thread.daemon = True
    app_thread.start()

    root.deiconify()
    root.mainloop()
