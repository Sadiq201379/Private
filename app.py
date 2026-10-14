import os, sqlite3, secrets
from functools import wraps
from flask import Flask, request, redirect, url_for, session, flash, render_template_string, abort
from werkzeug.security import generate_password_hash, check_password_hash

BASE=os.path.dirname(os.path.abspath(__file__))
DB=os.environ.get('DATABASE_PATH',os.path.join(BASE,'school.db'))
app=Flask(__name__)
app.secret_key=os.environ.get('SECRET_KEY',secrets.token_hex(32))
app.config.update(SESSION_COOKIE_HTTPONLY=True,SESSION_COOKIE_SAMESITE='Lax',SESSION_COOKIE_SECURE=os.environ.get('COOKIE_SECURE','0')=='1',MAX_CONTENT_LENGTH=1024*1024)
GRADES=['تمهيدي','الأول','الثاني','الثالث','الرابع','الخامس','السادس']

def conn():
 c=sqlite3.connect(DB);c.row_factory=sqlite3.Row;c.execute('PRAGMA foreign_keys=ON');return c

def init():
 with conn() as c:
  c.executescript('''CREATE TABLE IF NOT EXISTS users(id INTEGER PRIMARY KEY,username TEXT UNIQUE NOT NULL,password TEXT NOT NULL,name TEXT NOT NULL,role TEXT NOT NULL CHECK(role IN ('admin','teacher','student')),grade TEXT NOT NULL DEFAULT '');CREATE TABLE IF NOT EXISTS lessons(id INTEGER PRIMARY KEY,title TEXT NOT NULL,grade TEXT NOT NULL,kind TEXT NOT NULL CHECK(kind IN ('درس','واجب','اختبار','حصة مباشرة')),url TEXT NOT NULL DEFAULT '',description TEXT NOT NULL DEFAULT '',author INTEGER NOT NULL REFERENCES users(id),created TEXT DEFAULT CURRENT_TIMESTAMP);CREATE TABLE IF NOT EXISTS submissions(id INTEGER PRIMARY KEY,lesson_id INTEGER NOT NULL REFERENCES lessons(id) ON DELETE CASCADE,student_id INTEGER NOT NULL REFERENCES users(id),answer TEXT NOT NULL,score TEXT DEFAULT '',created TEXT DEFAULT CURRENT_TIMESTAMP,UNIQUE(lesson_id,student_id));''')
  if not c.execute("SELECT 1 FROM users WHERE role='admin'").fetchone():
   pwd=os.environ.get('ADMIN_PASSWORD')
   if not pwd or len(pwd)<12: raise RuntimeError('Set ADMIN_PASSWORD to a unique password of at least 12 characters before first start.')
   c.execute('INSERT INTO users(username,password,name,role) VALUES(?,?,?,?)',(os.environ.get('ADMIN_USERNAME','admin'),generate_password_hash(pwd),'مدير المدرسة','admin'))

@app.before_request
def csrf():
 if 'csrf' not in session:session['csrf']=secrets.token_urlsafe(24)
 if request.method=='POST' and not secrets.compare_digest(request.form.get('csrf',''),session['csrf']):abort(400)

def login_required(fn):
 @wraps(fn)
 def wrapped(*a,**kw):
  if 'uid' not in session:return redirect(url_for('login'))
  return fn(*a,**kw)
 return wrapped

def current():
 if 'uid' not in session:return None
 with conn() as c:return c.execute('SELECT id,name,role,grade FROM users WHERE id=?',(session['uid'],)).fetchone()

HTML='''<!doctype html><html lang="ar" dir="rtl"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>منصة البهجة التعليمية</title><style>body{margin:0;background:#f1f6fc;font-family:Tahoma,Arial;color:#153f76}header{text-align:center;background:white;border-bottom:5px solid #ffd900;padding:16px}header img{width:105px;max-width:25vw}header h1{margin:8px;color:#064a97}header p{line-height:1.8;margin:0}main{max-width:1050px;margin:24px auto;padding:0 14px}.panel{background:white;border:1px solid #d7e4f2;border-radius:15px;padding:20px;margin:16px 0;box-shadow:0 3px 12px #12457812}input,select,textarea{box-sizing:border-box;display:block;width:100%;padding:11px;margin:8px 0 14px;border:1px solid #afc5df;border-radius:8px;font:inherit}textarea{min-height:90px}button,.btn{background:#0754a4;color:white;border:0;border-radius:8px;padding:10px 18px;cursor:pointer;text-decoration:none;display:inline-block;font:inherit}.btn.alt{background:#d7a700;color:#162c4b}.bar{display:flex;justify-content:space-between;gap:10px;flex-wrap:wrap;align-items:center}.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(240px,1fr));gap:12px}.item{border:1px solid #d5e4f5;border-radius:10px;padding:14px;background:#fbfdff}small{color:#526e91}.msg{background:#fff4ce;padding:12px;border-radius:8px;margin:10px 0}a{color:#0754a4}label{font-weight:bold}footer{text-align:center;color:#527198;padding:25px}</style></head><body><header><p>الجمهورية اليمنية<br>وزارة التربية والتعليم<br>مكتب التربية والتعليم – تعز<br>إدارة التربية والتعليم / م – المظفر</p><img src="{{url_for('static',filename='logo.png')}}" alt="شعار مدرسة البهجة الأهلية"><h1>مدرسة البهجة الأهلية</h1><strong>المنصة التعليمية للتعليم عن بُعد</strong></header><main>{% with messages=get_flashed_messages() %}{% for m in messages %}<div class="msg">{{m}}</div>{% endfor %}{% endwith %}{% if user %}<div class="bar"><b>مرحبًا، {{user.name}} ({{ {'admin':'مدير','teacher':'معلم','student':'طالب'}[user.role] }})</b><form action="{{url_for('logout')}}" method="post"><input type="hidden" name="csrf" value="{{csrf}}"><button>تسجيل الخروج</button></form></div>{% endif %}{{content|safe}}</main><footer>تعليم متميز • قيم راسخة • مستقبل مشرق</footer></body></html>'''

def page(content,**kwargs):
 return render_template_string(HTML,content=render_template_string(content,**kwargs),user=current(),csrf=session['csrf'])

@app.route('/login',methods=['GET','POST'])
def login():
 if request.method=='POST':
  with conn() as c:u=c.execute('SELECT * FROM users WHERE username=?',(request.form.get('username',''),)).fetchone()
  if u and check_password_hash(u['password'],request.form.get('password','')):
   session.clear();session['uid']=u['id'];session['csrf']=secrets.token_urlsafe(24);return redirect(url_for('home'))
  flash('بيانات الدخول غير صحيحة')
 return page('''<div class="panel"><h2>تسجيل الدخول</h2><form method="post"><input type="hidden" name="csrf" value="{{csrf}}"><label>اسم المستخدم</label><input name="username" required autocomplete="username"><label>كلمة المرور</label><input name="password" type="password" required autocomplete="current-password"><button>دخول</button></form></div>''',csrf=session['csrf'])

@app.post('/logout')
def logout():session.clear();return redirect(url_for('login'))

@app.route('/')
@login_required
def home():
 u=current()
 with conn() as c:
  if u['role']=='student':lessons=c.execute('SELECT l.*,u.name author_name FROM lessons l JOIN users u ON u.id=l.author WHERE l.grade=? ORDER BY l.id DESC',(u['grade'],)).fetchall()
  else:lessons=c.execute('SELECT l.*,u.name author_name FROM lessons l JOIN users u ON u.id=l.author ORDER BY l.id DESC').fetchall()
 return page('''{% if user.role=='admin' %}<div class="bar"><a class="btn" href="{{url_for('users')}}">إدارة الحسابات</a><a class="btn alt" href="{{url_for('add_lesson')}}">إضافة محتوى تعليمي</a></div>{% elif user.role=='teacher' %}<a class="btn" href="{{url_for('add_lesson')}}">إضافة محتوى تعليمي</a>{% endif %}<div class="panel"><h2>الدروس والواجبات والحصص</h2><div class="grid">{% for l in lessons %}<div class="item"><small>{{l.grade}} • {{l.kind}} • {{l.created}}</small><h3>{{l.title}}</h3><p style="white-space:pre-wrap">{{l.description}}</p><small>المعلم: {{l.author_name}}</small><p>{% if l.url %}<a href="{{l.url}}" target="_blank" rel="noopener noreferrer">فتح رابط المحتوى</a>{% endif %}</p>{% if l.kind in ['واجب','اختبار'] %}<a class="btn" href="{{url_for('lesson',lesson_id=l.id)}}">{{'تسليم الإجابة' if user.role=='student' else 'عرض الإجابات'}}</a>{% endif %}</div>{% else %}<p>لم يُضف محتوى تعليمي بعد.</p>{% endfor %}</div></div>''',user=u,lessons=lessons)

@app.route('/users',methods=['GET','POST'])
@login_required
def users():
 if current()['role']!='admin':abort(403)
 if request.method=='POST':
  username=request.form.get('username','').strip();pwd=request.form.get('password','');name=request.form.get('name','').strip();role=request.form.get('role');grade=request.form.get('grade','') if role=='student' else ''
  if not username or not name or len(pwd)<10 or role not in ('teacher','student') or (role=='student' and grade not in GRADES):flash('تحقق من الحقول. كلمة المرور 10 أحرف على الأقل.')
  else:
   try:
    with conn() as c:c.execute('INSERT INTO users(username,password,name,role,grade) VALUES(?,?,?,?,?)',(username,generate_password_hash(pwd),name,role,grade))
    flash('تم إنشاء الحساب')
   except sqlite3.IntegrityError:flash('اسم المستخدم مستخدم بالفعل')
 with conn() as c:allusers=c.execute('SELECT username,name,role,grade FROM users ORDER BY id DESC').fetchall()
 return page('''<a href="/">الرئيسية</a><div class="panel"><h2>إضافة معلم أو طالب</h2><form method="post"><input type="hidden" name="csrf" value="{{csrf}}"><label>الاسم الكامل</label><input name="name" required><label>اسم المستخدم</label><input name="username" required><label>كلمة مرور مؤقتة (10 أحرف على الأقل)</label><input name="password" type="password" minlength="10" required><label>نوع الحساب</label><select name="role"><option value="student">طالب</option><option value="teacher">معلم</option></select><label>صف الطالب</label><select name="grade">{% for g in grades %}<option>{{g}}</option>{% endfor %}</select><button>إنشاء الحساب</button></form></div><div class="panel"><h2>الحسابات</h2>{% for u in allusers %}<p>{{u.name}} — {{u.username}} — {{u.role}} {{u.grade}}</p>{% endfor %}</div>''',csrf=session['csrf'],grades=GRADES,allusers=allusers)

@app.route('/lessons/new',methods=['GET','POST'])
@login_required
def add_lesson():
 if current()['role'] not in ('admin','teacher'):abort(403)
 if request.method=='POST':
  title=request.form.get('title','').strip();grade=request.form.get('grade');kind=request.form.get('kind');url=request.form.get('url','').strip();description=request.form.get('description','').strip()
  if not title or grade not in GRADES or kind not in ('درس','واجب','اختبار','حصة مباشرة') or (url and not url.startswith('https://')):flash('تحقق من البيانات، والروابط يجب أن تبدأ بـ https://')
  else:
   with conn() as c:c.execute('INSERT INTO lessons(title,grade,kind,url,description,author) VALUES(?,?,?,?,?,?)',(title,grade,kind,url,description,current()['id']))
   flash('تم نشر المحتوى');return redirect(url_for('home'))
 return page('''<a href="/">الرئيسية</a><div class="panel"><h2>إضافة درس أو واجب أو حصة</h2><form method="post"><input type="hidden" name="csrf" value="{{csrf}}"><label>العنوان</label><input name="title" required maxlength="200"><label>الصف</label><select name="grade">{% for g in grades %}<option>{{g}}</option>{% endfor %}</select><label>نوع المحتوى</label><select name="kind"><option>درس</option><option>واجب</option><option>اختبار</option><option>حصة مباشرة</option></select><label>رابط فيديو أو اجتماع (اختياري)</label><input type="url" name="url" placeholder="https://..."><label>الشرح أو السؤال</label><textarea name="description" maxlength="10000"></textarea><button>نشر</button></form></div>''',csrf=session['csrf'],grades=GRADES)

@app.route('/lessons/<int:lesson_id>',methods=['GET','POST'])
@login_required
def lesson(lesson_id):
 u=current()
 with conn() as c:
  l=c.execute('SELECT * FROM lessons WHERE id=?',(lesson_id,)).fetchone()
  if not l:abort(404)
  if l['kind'] not in ('واجب','اختبار'):abort(404)
  if u['role']=='student' and u['grade']!=l['grade']:abort(403)
  if request.method=='POST':
   if u['role']!='student':abort(403)
   answer=request.form.get('answer','').strip()
   if not answer:flash('أدخل الإجابة')
   else:
    c.execute('INSERT INTO submissions(lesson_id,student_id,answer) VALUES(?,?,?) ON CONFLICT(lesson_id,student_id) DO UPDATE SET answer=excluded.answer,created=CURRENT_TIMESTAMP',(lesson_id,u['id'],answer));flash('تم حفظ الإجابة')
  submissions=c.execute('SELECT s.*,u.name FROM submissions s JOIN users u ON u.id=s.student_id WHERE s.lesson_id=? ORDER BY s.id DESC',(lesson_id,)).fetchall() if u['role']!='student' else []
  mine=c.execute('SELECT * FROM submissions WHERE lesson_id=? AND student_id=?',(lesson_id,u['id'])).fetchone() if u['role']=='student' else None
 return page('''<a href="/">الرئيسية</a><div class="panel"><h2>{{l.title}}</h2><p style="white-space:pre-wrap">{{l.description}}</p>{% if user.role=='student' %}<form method="post"><input type="hidden" name="csrf" value="{{csrf}}"><label>إجابتي</label><textarea name="answer" required>{{mine.answer if mine else ''}}</textarea><button>حفظ الإجابة</button></form>{% else %}<h3>إجابات الطلاب</h3>{% for s in submissions %}<div class="item"><b>{{s.name}}</b><small> {{s.created}}</small><p style="white-space:pre-wrap">{{s.answer}}</p></div>{% else %}<p>لا توجد إجابات بعد.</p>{% endfor %}{% endif %}</div>''',l=l,user=u,csrf=session['csrf'],mine=mine,submissions=submissions)

if __name__=='__main__':
 init();app.run(host='127.0.0.1',port=5000,debug=False)
