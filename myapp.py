from flask import Flask, render_template, request, redirect, url_for, session, send_file, flash
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
import os
from datetime import datetime, timedelta

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
app.config['SECRET_KEY'] = 'supersecretkey'
app.config['SESSION_PERMANENT'] = False  # Oturum kalıcı değil
db = SQLAlchemy(app)

# Kullanıcı modeli
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    score = db.Column(db.Integer, default=0)
    solved_flags = db.relationship('Flag', secondary='user_flags')
    failed_attempts = db.Column(db.Integer, default=0)
    last_failed_attempt = db.Column(db.DateTime, default=datetime.utcnow)

# Flag modeli
class Flag(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(200), unique=True)
    correct_flag = db.Column(db.String(200))

# Kullanıcı ve Flag arasındaki ilişkiyi tanımlıyoruz
class UserFlags(db.Model):
    __tablename__ = 'user_flags'
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), primary_key=True)
    flag_id = db.Column(db.Integer, db.ForeignKey('flag.id'), primary_key=True)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)

# Seviye flag’leri için liste (normal seviyeler)
FLAGS = {
    "CZHT.jpg": "FLAG{Z0R_D3G1LD1}",   # 1. seviye
    "gs.jpg": "FLAG{2_1n_A_R0W}",         # 2. seviye
    "fener.png": "FLAG{SEZAR_SIFRE}",      # 3. seviye (fb = fener)
    "bjk.jpeg": "FLAG{VIGENERE_CTF}",      # 4. seviye
    "gizliresim.jpeg": "FLAG{YaR1SMaya_KAt1lD1G1N_1c1n_T3S3KKuRl3R}",
}


@app.route('/')
def home():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    user = User.query.get(session['user_id'])
    return render_template('index.html', user=user)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()
        
        # Hatalı giriş sayısı kontrolü
        if user:
            if user.failed_attempts >= 3 and datetime.utcnow() - user.last_failed_attempt < timedelta(minutes=5):
                flash('Hesabınız kilitlendi. Lütfen birkaç dakika sonra tekrar deneyin.', 'danger')
                return render_template('login.html')

            if check_password_hash(user.password, password):
                session['user_id'] = user.id
                user.failed_attempts = 0  # Başarılı giriş sonrası başarısız denemeleri sıfırla
                db.session.commit()
                return redirect(url_for('home'))
            else:
                user.failed_attempts += 1
                user.last_failed_attempt = datetime.utcnow()
                db.session.commit()
                flash('Hatalı kullanıcı adı veya şifre!', 'danger')
        else:
            flash('Kullanıcı adı bulunamadı!', 'danger')
        
    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = generate_password_hash(request.form['password'])
        
        if User.query.filter_by(username=username).first():
            flash('Bu kullanıcı adı zaten alınmış!', 'danger')
        else:
            user = User(username=username, password=password)
            db.session.add(user)
            db.session.commit()
            flash('Başarıyla kayıt oldunuz, giriş yapabilirsiniz!', 'success')
            return redirect(url_for('login'))
    return render_template('register.html')

@app.route('/logout')
def logout():
    session.pop('user_id', None)
    return redirect(url_for('login'))

@app.route('/scoreboard')
def scoreboard():
    # Tüm kullanıcıları puana göre azalan sırada çekiyoruz
    users = User.query.order_by(User.score.desc()).all()
    top_users = users[:10]  # Top 10 kullanıcı

    current_user = None
    current_user_rank = None
    current_user_in_top = False

    # Eğer login olmuşsa, login olan kullanıcının sıralamasını hesaplıyoruz.
    if 'user_id' in session:
        current_user = User.query.get(session['user_id'])
        for index, user in enumerate(users):
            if user.id == current_user.id:
                current_user_rank = index + 1  # Sıralama 1'den başlıyor
                break
        # Login olan kullanıcı top_users içerisinde mi kontrol ediyoruz.
        if any(user.id == current_user.id for user in top_users):
            current_user_in_top = True

    return render_template(
        'scoreboard.html', 
        top_users=top_users, 
        current_user=current_user, 
        current_user_rank=current_user_rank,
        current_user_in_top=current_user_in_top
    )

@app.route('/level/<int:level>', methods=['GET', 'POST'])
def level(level):
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    images = list(FLAGS.keys())
    if level < 1 or level > len(images):
        return redirect(url_for('home'))
    
    user = User.query.get(session['user_id'])
    image = images[level - 1]
    flag_correct = False
    
    if request.method == 'POST':
        submitted_flag = request.form['flag']
        if submitted_flag == FLAGS[image]:
            if not any(f.name == image for f in user.solved_flags):
                user.score += 10
                flag = Flag.query.filter_by(name=image).first()
                if flag:
                    user.solved_flags.append(flag)
                db.session.commit()
            flash('Tebrikler! 🎉👏', 'success')
            flag_correct = True
        else:
            flash('Yanlış flag, tekrar dene!', 'danger')
    
    # solved_flags None olursa boş bir liste olarak işleme
    if user.solved_flags is None:
        user.solved_flags = []

    return render_template('level.html', level=level, image=image, flag_correct=flag_correct)

@app.route('/download/<image>')
def download(image):
    image_path = os.path.join('static', image)
    return send_file(image_path, as_attachment=True)

# --- Yeni: robots.txt rotası ---
@app.route('/robots.txt')
def robots_txt():
    robots_txt_content = "User-agent: EXSREM Tarafından Cyber Zone Group için hazırlanmıştır\Maded by EXSREM for Cyber ZOne Group*\nDisallow: /cokgizlidizinimben\n"
    return app.response_class(robots_txt_content, mimetype='text/plain')

# --- Yeni: /cokgizlidizinimben rotası ---
@app.route('/cokgizlidizinimben', methods=['GET', 'POST'])
def cokgizlidizinimben():
    if 'user_id' not in session:
        flash("Lütfen bu challenge'a erişmek için giriş yapın.", "warning")
        return redirect(url_for('login'))
    user = User.query.get(session['user_id'])
    # Challenge resmi olarak artık 'gizliresim.jpeg' kullanılıyor (static klasöründe mevcut)
    challenge_image = "gizliresim.jpeg"
    challenge_flag = "FLAG{GIZLIGOREVTAMAM}"
    flag_correct = False

    if request.method == "POST":
        submitted_flag = request.form['flag']
        if submitted_flag == challenge_flag:
            if not any(f.name == challenge_image for f in user.solved_flags):
                user.score += 10
                flag_obj = Flag.query.filter_by(name=challenge_image).first()
                if flag_obj:
                    user.solved_flags.append(flag_obj)
                db.session.commit()
            flash("Tebrikler! 🎉👏", "success")
            flag_correct = True
        else:
            flash("Yanlış flag, tekrar dene!", "danger")

    if user.solved_flags is None:
        user.solved_flags = []
        
    return render_template("challenge.html", image=challenge_image, flag_correct=flag_correct)

if __name__ == '__main__':
    with app.app_context():
        # Veritabanı zaten mevcutsa sıfırlama yapmayın
        db.create_all()
        # Flag'leri yalnızca bir kez ekleyin, eğer henüz eklenmemişse (normal seviyeler)
        if not Flag.query.first():
            for name, correct_flag in FLAGS.items():
                flag = Flag(name=name, correct_flag=correct_flag)
                db.session.add(flag)
            db.session.commit()
        # Eğer Flag tablosunda "gizliresim.jpeg" adlı kayıt yoksa, ekleyelim.
        if not Flag.query.filter_by(name="gizliresim.jpeg").first():
            new_flag = Flag(name="gizliresim.jpeg", correct_flag="FLAG{GIZLIGOREVTAMAM}")
            db.session.add(new_flag)
            db.session.commit()
    app.run(debug=True)
