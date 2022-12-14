# future.Campus.Platform
基于 Python 3 + Flask 的学生信息管理系统

Original: [ljhshuai/Flasky](https://github.com/ljhshuai/Flasky)

[//]: # (&#40;相应的安卓版在 future.Campus.Platform_app 库&#41;)

## 技术栈
后端框架 Flask

数据库管理 SQLAlchemy

数据库 SQLite

前端 Bootstrap
  
## 特色功能

- 用户注册与密码找回（验证邮箱），所有密码不可逆加密后存储（可以自行为散列算法加盐）
![image](https://user-images.githubusercontent.com/75155322/185481346-498a819c-ef97-4c16-88c9-51d9976c58ff.png)
- 教师，学生，管理员拥有不同权限
![image](https://user-images.githubusercontent.com/75155322/185481401-b28cca3a-d1dc-4a70-8c57-970444b301ba.png)
- 教师：对学生增删查改，展示自己所管理的学生信息
![image](https://user-images.githubusercontent.com/75155322/185481525-d495faf7-fb4a-4210-83cb-ad7619034f6f.png)
- 学生： 选择教师以参看教师所管理的学生信息，但是不能进行增加/删除/修改操作
![image](https://user-images.githubusercontent.com/75155322/185482046-f9d05036-9837-49e6-be4e-4429264dc379.png)
- 管理员：管理所有用户数据，可以新增、封禁、解封以及删除用户账号
![image](https://user-images.githubusercontent.com/75155322/185481903-529186df-a4a5-4a63-8e60-c4f8d9ee95ce.png)

## 使用协议
仅供学习交流，请勿用于生产环境或商业用途 ~~也没人会想不开这么干~~

请勿进行 Fork 以外的提供公开副本的行为

## 配置工作环境
- 通过 `git clone` 或 `Download ZIP` 将项目下载到本地

- 进入（cd）目录

- 创建虚拟环境（venv）并激活，亲测 Python 3.6.0 可用
  - Python 3.10.2 会出问题，附 [StackOverFlow](https://stackoverflow.com/questions/69381312/in-vs-code-importerror-cannot-import-name-mapping-from-collections) ，希望使用高版本 Python 的需要自行解决兼容性问题。
- 执行 ```pip install -r requirements.txt``` 来为虚拟环境安装指定版本的所有所需包

- 输入 ```python app.py runserver``` 运行

- 为了使用户能正常收到激活及找回密码邮件，请在 `config.py` 中配置好 SMTP 服务器地址、端口号以及账号密码。
  - 如使用 QQ 邮箱需要生成授权码而非使用 QQ 密码。QQ 邮箱对普通用户的发邮件限制是每分钟限发 40 封，每天限发 100 封。出现注册和找回密码次数每天加起来超过 100 人次时需要多个邮箱轮换发件。（当然，这不太可能发生）

- 登录管理员后台：访问路径 `/phpyouradmin`，默认账号密码为 `aynxul03@gmail.com` / `aynxul03`，可自行在 config.py 中修改
  
## [Flasky](https://github.com/ljhshuai/Flasky) 曾经存在的不足之处

- ~~储存在数据库中的密码未进行不可逆加密，存在被窃取后导致用户其他网站的账号也被盗的风险。~~
  - 已对除管理员密码外的所有密码进行不可逆加密

- ~~所有 Python 代码全部集中于 app.py 一个文件中，应用未模块化。~~ 
  - 其实就把一些配置分离到了 `config.py` 中
