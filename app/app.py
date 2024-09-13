from email import message
from email.mime.application import MIMEApplication
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.mime.image import MIMEImage
import os
import json
from jinja2 import Environment, FileSystemLoader
import shutil
import pdfkit
from functools import wraps
from http import server
from flask import Flask, render_template, request, redirect, url_for, session, Response, render_template_string, jsonify
from flask_login import LoginManager, login_user, logout_user, login_required, current_user
from flask_login import UserMixin
from datetime import datetime
import re
import random
import subprocess as sp
from flask_mysqldb import MySQL, MySQLdb
import bcrypt
import smtplib
import string
from os import listdir
app = Flask(__name__)
app.secret_key = "AbcDefGhi12345()!?==-=/.,;:'?¿¡"
app.config['MYSQL_HOST'] = 'localhost'
app.config['MYSQL_USER'] = 'root'
app.config['MYSQL_PASSWORD'] = ''
app.config['MYSQL_DB'] = 'login_db'
app.config['MYSQL_CURSORCLASS'] = 'DictCursor'
mysql = MySQL(app)

# Poner en producción
# Info puertos ping
# API

#Ruta por defecto /login

@app.route("/", methods=["GET"])
def home():
    if current_user.is_authenticated:
        if current_user.has_role(['invitado']):
            return render_template("invitado.html")
        else:
            return render_template("menu.html")
    else:
        return render_template("home.html")

@app.route('/invitado', methods=["GET"])
def invitado():
    return render_template("invitado.html")

#Configurar el login_manager
login_manager = LoginManager()
login_manager.init_app(app)

class User(UserMixin):
    def __init__(self, user_id, role, user_email):
        self.id = user_id
        self.role = role
        self.email = user_email

    def has_role(self, roles):
        return self.role in roles

@login_manager.user_loader
def load_user(user_id):
    cur = mysql.connection.cursor()
    cur.execute("SELECT * FROM users WHERE email=%s", (user_id,))
    user = cur.fetchone()
    cur.close()

    if user:
        return User(user_id, user['role'], user['email'])
    return None

def role_required(roles):
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if current_user.is_anonymous or current_user.role not in roles:
                return redirect(url_for('menu'))
            return f(*args, **kwargs)
        return decorated_function
    return decorator

#Carga el Registro de la Web
@app.route('/register', methods=["GET","POST"])
@login_required
@role_required('admin')
def register():
    if request.method == 'GET':
        return render_template("register.html")
    else:
        name = request.form['name']
        email = request.form['email']
        password = request.form['password']
        password_confirm = request.form['password_confirm']
        role = request.form['role']
        error = validate_password(password)
        role_mapping = {
            '1': 'admin',
            '2': 'usuario',
            '3': 'invitado'
        }
        role_str = role_mapping.get(role)
        if error:
            return render_template("register.html", error=error)
        else:
            if password != password_confirm:
                return render_template("register.html", error="Las contraseñas no coinciden")
            else:
                password = password.encode('utf-8')
                hash_password = bcrypt.hashpw(password, bcrypt.gensalt())
        try:
            cur = mysql.connection.cursor()
            cur.execute("SELECT email FROM users WHERE email = %s", (email,))
            result = cur.fetchone()
            if result:
                return render_template("register.html", error="El correo ya esta registrado.")
            else:
                cur.execute("INSERT INTO users (name,email,password, password_changed, role) VALUES (%s,%s,%s,%s,%s)",(name,email,hash_password,False, role_str))
                mysql.connection.commit()
                return render_template("register.html", info="Usuario registrado correctamente")
        except Exception as e:
            return render_template("register.html", error="Error al insertar datos en la base de datos: " + str(e))

@app.route('/users', methods=["GET","POST"])
@login_required
@role_required('admin')
def users():
    cur = mysql.connection.cursor()
    cur.execute("SELECT id, name, email, role FROM users")
    result = cur.fetchall()
    cur.close()
    return render_template('users.html', users=result)

@app.route('/edit_user/<int:user_id>', methods=['GET', 'POST'])
@login_required
@role_required('admin')
def edit_user(user_id):
    cur = mysql.connection.cursor()
    cur.execute("SELECT * FROM users WHERE id = %s", (user_id,))
    user = cur.fetchone()
    cur.close()
    return render_template('edit_user.html', user=user)

@app.route('/update_user/<int:user_id>', methods=['POST'])
@login_required
@role_required('admin')
def update_user(user_id):
    new_id = request.form['id']
    name = request.form['name']
    role = request.form['role']
    cur = mysql.connection.cursor()
    cur.execute("UPDATE users SET id = %s, name = %s, role = %s WHERE id = %s", (new_id, name, role, user_id))
    mysql.connection.commit()
    cur.execute("SELECT id, name, email, role FROM users")
    result = cur.fetchall()
    cur.close()
    return render_template("users.html", users=result, info="Usuario actualizado correctamente")

@app.route('/delete_user/<int:user_id>', methods=['POST'])
@login_required
@role_required('admin')
def delete_user(user_id):
    cur = mysql.connection.cursor()
    cur.execute("DELETE FROM users WHERE id = %s", (user_id,))
    mysql.connection.commit()
    cur.execute("SELECT id, name, email, role FROM users")
    result = cur.fetchall()
    cur.close
    return render_template("users.html", users=result, info="Usuario eliminado correctamente")

#Carga el Login
@app.route('/login',methods=["GET","POST"])
def login():
    if request.method == "POST":
        email = request.form['email']
        password = request.form['password'].encode('utf-8')

        try:
            cur = mysql.connection.cursor()
            cur.execute("SELECT * FROM users WHERE email=%s",(email,))
            user = cur.fetchone()
            cur.close()

            if user:
                if bcrypt.checkpw(password, user['password'].encode('utf-8')):
                    if user['password_changed'] == False:
                        return redirect(url_for("request_email"))
                    else:
                        login_user(User(user['email'], user['role'], user['email']))
                        session["name"] = user["name"]
                        session["email"] = user["email"]
                        if current_user.has_role(['invitado']):
                            return render_template("invitado.html")
                        else:
                            return render_template("menu.html")
                else:
                    return render_template("login.html", error="Usuario o contraseña incorrectos")
            else:
                return render_template("login.html", error="Usuario o contraseña incorrectos")
        except Exception as e:
            return render_template("login.html", error="Error al leer los datos en la base de datos: " + str(e))
    else:
        return render_template("login.html")

@app.route("/request_email", methods=["GET", "POST"])
def request_email():
    if request.method == "POST":
        email = request.form['email']

        #Verificar si el correo está registrado
        cur = mysql.connection.cursor()
        cur.execute("SELECT * FROM users WHERE email=%s", (email,))
        user = cur.fetchone()
        cur.close()
        if not user:
            return render_template("request_email.html", error="El correo no está registrado")

        code = generate_random_code()
        if send_verification_code(email, code):
            session['verification_code'] = code
            return redirect(url_for("change_password", email=email))
        else:
            return render_template("request_email.html", error="Error al enviar el correo de verificación")
    else:
        return render_template("request_email.html")

@app.route("/change_password", methods=["GET", "POST"])
def change_password():
    if request.method == "POST":
        email = request.form['email']
        password = request.form['password']
        password_confirm = request.form['password_confirm']
        verification_code = request.form['verification_code']
        stored_code = session.get('verification_code', None)
        
        if not stored_code or stored_code != verification_code:
            return render_template("change_password.html", error="Código de verificación incorrecto")

        error = validate_password(password)
        if error:
            return render_template("change_password.html", error=error)
        else:
            if password != password_confirm:
                return render_template("change_password.html", error="Las contraseñas no coinciden")
            else:
                password = password.encode('utf-8')
                hash_password = bcrypt.hashpw(password, bcrypt.gensalt())

        try:
            cur = mysql.connection.cursor()
            cur.execute("UPDATE users SET password=%s, password_changed=%s WHERE email=%s", (hash_password, True, email))
            cur.execute("SELECT * FROM users WHERE email=%s", (email,))
            user = cur.fetchone()
            mysql.connection.commit()
            cur.close()
        except Exception as e:
            return render_template("change_password.html", error="Error al modificar la contraseña en la base de datos: " + str(e))
        if user:
            login_user(User(user['email'], user['role'], user['email']))
            session["name"] = user["name"]
            session["email"] = user["email"]
            return render_template("menu.html")
        else:
            return render_template("change_password.html", error="El usuario no existe")
    return render_template("change_password.html")

#Función para poner unas condiciones a la contraseña
def validate_password(password):
    MIN_LENGTH = 8
    if len(password) < MIN_LENGTH:
        return "La contraseña debe tener al menos 8 caracteres y contener una mayúscula, una minúscula, un número y un caracter especial."
    if not any(x.isupper() for x in password):
        return "La contraseña debe tener al menos 8 caracteres y contener una mayúscula, una minúscula, un número y un caracter especial."
    if not any(x.islower() for x in password):
        return "La contraseña debe tener al menos 8 caracteres y contener una mayúscula, una minúscula, un número y un caracter especial."
    if not any(x.isdigit() for x in password):
        return "La contraseña debe tener al menos 8 caracteres y contener una mayúscula, una minúscula, un número y un caracter especial."
    if not any(x in string.punctuation for x in password):
        return "La contraseña debe tener al menos 8 caracteres y contener una mayúscula, una minúscula, un número y un caracter especial."
    return None

def generate_random_code():
    return str(random.randint(100000, 999999))

def send_verification_code(email, code):
    sender = "formularios@sic24.com"
    subject = "Código de verificación"
    body = f"Tu código de verificación es: {code}"
    msg = MIMEText(body)
    msg['Subject'] = subject
    msg['From'] = sender
    msg['To'] = email
    try:
        server = smtplib.SMTP("smtp.office365.com")
        server.starttls()
        server.login(sender, "APN!g@vh")
        server.sendmail(sender, email, msg.as_string())
        server.quit()
    except Exception as e:
        print("Error al enviar el correo: " + str(e))
        return False
    return True

#Funcion para requerir esta loggeado
def login_required_all(func):
    @wraps(func)
    def wrapper(*args, **kwargs):
        if not current_user.is_authenticated:
            return redirect(url_for('home'))
        return func(*args, **kwargs)
    return wrapper

#Verificar si el usuario esta loggeado para poder acceder a todas las páginas
@app.before_request
def before_request():
    if request.endpoint not in ['login', 'request_email', 'home', 'static', 'change_password'] and not current_user.is_authenticated:
        return redirect(url_for('home'))
        
#Cerrar Sesion
@app.route('/logout')
@login_required
def logout():
    session.clear()
    logout_user()
    return render_template("home.html")

#Carga el Menu de la Web
@app.route("/menu", methods=["GET","POST"])
@login_required
def menu():
	return render_template("/menu.html")

#Escaner de Puertos
@app.route("/escaner/puertos", methods=["POST", "GET"])
@login_required
@role_required(['admin', 'usuario'])
def port_scanner():
    if request.method == "POST":
        ip = request.form.get("ip")
        port = request.form.get("puerto")

        # Validar y desinfectar la entrada del usuario
        forbidden_chars = r"[/;:&]"
        port_pattern = r"^(\d{1,5}(,\d{1,5})*)$"
        if re.search(forbidden_chars, ip) or not re.match(port_pattern, port):
            return render_template("/port_scanner.html", output="Error: Entrada no válida")

        ports = port.split(',')
        output = sp.getoutput("nmap -p " + ",".join(ports) + " " + ip)
        return render_template("/port_scanner.html", output=output)

    return render_template("/port_scanner.html")

#Escaner de Servicios
@app.route("/escaner/servicios", methods=["POST", "GET"])
@login_required
@role_required(['admin', 'usuario'])
def service_scanner():
	if request.method == "POST":
		ip = request.form.get("ip")
		output = sp.getoutput("nmap " + ip + " -sV -Pn")
		return render_template("/service_scanner.html", output=output)

	return render_template("/service_scanner.html")

#Ping
@app.route("/ping", methods=["POST", "GET"])
@login_required
@role_required(['admin', 'usuario'])
def ping():
	if request.method == "POST":
		ip = request.form.get("ip")
		output = sp.getoutput("ping -c 4 " + ip)
		print(output)
		return render_template("/ping.html", output=output)

	return render_template("/ping.html")

#Escaner de Mac
@app.route("/mac", methods=["GET"])
@login_required
@role_required(['admin', 'usuario'])
def mac():
	return render_template("/mac.html")

@app.route("/form/robo", methods=["POST", "GET"])
@login_required
def robo():
    num_filas_str = request.form.get("zona")
    if num_filas_str is None or num_filas_str == "":
        num_filas = 0
    else:
        num_filas = int(num_filas_str)

    # Establece el número de columnas en la tabla
    num_columnas = 5

    # Recopila los valores de los campos de entrada en la tabla
    tabla = []
    for i in range(num_filas):
        fila = ["Zona " + str(i + 1)]
        for j in range(1, num_columnas):
            fila.append(request.form.get(f"fila{i}_columna{j}"))
        tabla.append(fila)
    num_zonas_str = request.form.get("zona")
    if num_zonas_str is None or num_zonas_str == "":
        num_zonas = 0
    else:
        num_zonas = int(num_zonas_str)
    zonas = []
    for i in range(num_zonas):
        zonas.append(request.form.get(f"zona{i}"))
    form_data = {
        "modelo_central": request.form.get("numero"),
        "otro_mod": request.form.get("otro_mod"),
        "ubi_central": request.form.get("ubi_central"),
        "cod_inst": request.form.get("cod_inst"),
        "n_serie_central": request.form.get("n_serie_central"),
        "GPRS": request.form.get("GPRS"),
        "operador_gprs": request.form.get("operador_gprs"),
        "modelo_gprs": request.form.get("modelo_gprs"),
        "n_sim": request.form.get("n_sim"),
        "imei": request.form.get("imei"),
        "IP": request.form.get("IP"),
        "DH": request.form.get("DH"),
        "dir_ip": request.form.get("dir_ip"),
        "puerta_enlace": request.form.get("puerta_enlace"),
        "APP": request.form.get("APP"),
        "id_app": request.form.get("id_app"),
        "email_app": request.form.get("email_app"),
        "cliente": request.form.get("cliente"),
        "abonado": request.form.get("abonado"),
        "tecn_inst": request.form.get("tecn_inst"),
        "fecha": request.form.get("fecha"),
        "text_box": request.form.get("text_box"),
        "zonas": zonas,
        "tabla": tabla,
        "numero_filas": num_filas,
        "numero_columnas": num_columnas,
        "tabla_vacia": len(tabla) == 0
    }
    if 'name' in session and 'email' in session:
        user_name = session['name']
        user_email = session['email']
        archivo = request.form.get("abonado")
        current_date_time = datetime.now().strftime('%d-%m-%Y %H-%M')
        input_nopol = request.form.get("text_box")
        fotos = request.files.getlist('fotos')
        if request.method == "POST":
            # Renderizar la plantilla con los datos del formulario
            rendered_html = render_template("robo_pdf.html", **form_data)

            # Crear PDF
            filename = "PROGRAMACIÓN ROBO AB. " + archivo + " " + current_date_time + '.pdf'
            options = {
            'enable-local-file-access': None  # Habilita el acceso a archivos locales (necesario para cargar recursos como CSS)
            }
            pdfkit.from_string(rendered_html, filename, options=options)

            folder_name = "Ab. " + archivo
            forms_folder = 'forms/'
            target_folder = os.path.join(forms_folder, folder_name)
            os.makedirs(target_folder, exist_ok=True)

            shutil.move(filename, os.path.join(target_folder, filename))
            for foto in fotos:
                if foto.filename == "":
                    continue
                if not allowed_file(foto.filename):
                    return render_template("robo.html", error="Archivo no permitido.")
            if not enviar_correo(filename, input_nopol, archivo, user_name, user_email, fotos, "formulario_generico"):
                return render_template("robo.html", error="El archivo PDF no existe")
            else:
                return render_template("robo.html", info="Correo enviado correctamente")

        # Devolver la plantilla 'robo.html' cuando el método de solicitud no sea POST
        return render_template("robo.html")
    else:
        return render_template("robo.html", error="No hay ningún usuario logueado en la aplicación")

@app.route("/form/cctv", methods=["POST","GET"])
@login_required
def cctv():
    num_filas_str = request.form.get("camara")
    if num_filas_str is None or num_filas_str == "":
        num_filas = 0
    else:
        num_filas = int(num_filas_str)

    # Establece el número de columnas en la tabla
    num_columnas = 5

    # Recopila los valores de los campos de entrada en la tabla
    tabla = []
    for i in range(num_filas):
        fila = ["Cámara " + str(i + 1)]
        for j in range(1, num_columnas):
            fila.append(request.form.get(f"fila{i}_columna{j}"))
        tabla.append(fila)
    num_camaras_str = request.form.get("camara")
    if num_camaras_str is None or num_camaras_str == "":
        num_camaras = 0
    else:
        num_camaras = int(num_camaras_str)
    camaras = []
    for i in range(num_camaras):
        camaras.append(request.form.get(f"camara{i}"))
    form_data = {
        "modelo_grabador": request.form.get("modelo_grabador"),
        "n_serie": request.form.get("n_serie"),
        "abonado": request.form.get("abonado"),
        "videoverificacio": request.form.get("videoverificacio"),
        "ip_gravador": request.form.get("ip_gravador"),
        "puerta_enlace": request.form.get("puerta_enlace"),
        "puertos": request.form.get("puertos"),
        "dns": request.form.get("dns"),
        "usuario": request.form.get("usuario"),
        "contraseña": request.form.get("contraseña"),
        "usuario2": request.form.get("usuario2"),
        "contraseña2": request.form.get("contraseña2"),
        "usuario_router": request.form.get("usuario_router"),
        "contraseña_router": request.form.get("contraseña_router"),
        "tecn_inst": request.form.get("tecn_inst"),
        "fecha": request.form.get("fecha"),
        "comentario": request.form.get("comentario"),
        "camaras": camaras,
        "tabla": tabla,
        "numero_filas": num_filas,
        "numero_columnas": num_columnas,
        "tabla_vacia": len(tabla) == 0
    }
    if 'name' in session and 'email' in session:
        user_name = session['name']
        user_email = session['email']
        archivo = request.form.get("abonado")
        current_date_time = datetime.now().strftime('%d-%m-%Y %H-%M')
        input_nopol = request.form.get("comentario")
        fotos = request.files.getlist('fotos')
        if request.method == "POST":
            # Renderizar la plantilla con los datos del formulario
            rendered_html = render_template("cctv_pdf.html", **form_data)

            # Crear PDF
            filename = "PROGRAMACIÓN CCTV AB. " + archivo + " " + current_date_time + '.pdf'
            options = {
                'enable-local-file-access': None  # Habilita el acceso a archivos locales (necesario para cargar recursos como CSS)
            }
            pdfkit.from_string(rendered_html, filename, options=options)

            folder_name = "Ab. " + archivo
            forms_folder = 'forms/'
            target_folder = os.path.join(forms_folder, folder_name)
            os.makedirs(target_folder, exist_ok=True)

            shutil.move(filename, os.path.join(target_folder, filename))
            for foto in fotos:
                if foto.filename == "":
                    continue
                if not allowed_file(foto.filename):
                    return render_template("cctv.html", error="Archivo no permitido.")
            if not enviar_correo(filename, input_nopol, archivo, user_name, user_email, fotos, "formulario_generico"):
                return render_template("cctv.html", error="El archivo PDF no existe")
            else:
                return render_template("cctv.html", info="Correo enviado correctamente")

        # Devolver la plantilla 'robo.html' cuando el método de solicitud no sea POST
        return render_template("cctv.html")
    else:
        return render_template("cctv.html", error="No hay ningún usuario logueado en la aplicación")

@app.route("/ampliacion_robo", methods=["POST", "GET"])
@login_required
def ampliacion_robo():
    num_filas_str = request.form.get("zona")
    if num_filas_str is None or num_filas_str == "":
        num_filas = 0
    else:
        num_filas = int(num_filas_str)

    # Establece el número de columnas en la tabla
    num_columnas = 5

    # Recopila los valores de los campos de entrada en la tabla
    tabla = []
    for i in range(num_filas):
        fila = []
        for j in range(num_columnas):
            fila.append(request.form.get(f"fila{i}_columna{j}"))
        tabla.append(fila)
    num_zonas_str = request.form.get("zona")
    if num_zonas_str is None or num_zonas_str == "":
        num_zonas = 0
    else:
        num_zonas = int(num_zonas_str)
    zonas = []
    for i in range(num_zonas):
        zonas.append(request.form.get(f"zona{i}"))
    form_data = {
        "cliente": request.form.get("cliente"),
        "abonado": request.form.get("abonado"),
        "tecn_inst": request.form.get("tecn_inst"),
        "fecha": request.form.get("fecha"),
        "text_box": request.form.get("text_box"),
        "zonas": zonas,
        "tabla": tabla,
        "numero_filas": num_filas,
        "numero_columnas": num_columnas,
        "tabla_vacia": len(tabla) == 0
    }
    if 'name' in session and 'email' in session:
        user_name = session['name']
        user_email = session['email']
        archivo = request.form.get("abonado")
        current_date_time = datetime.now().strftime('%d-%m-%Y %H-%M')
        input_nopol = request.form.get("text_box")
        fotos = request.files.getlist('fotos')
        if request.method == "POST":
            # Renderizar la plantilla con los datos del formulario
            rendered_html = render_template("ampliacion_robo_pdf.html", **form_data)

            # Crear PDF
            filename = "PROGRAMACIÓN AMPLIACIÓN ROBO AB. " + archivo + " " + current_date_time + '.pdf'
            options = {
                'enable-local-file-access': None  # Habilita el acceso a archivos locales (necesario para cargar recursos como CSS)
            }
            pdfkit.from_string(rendered_html, filename, options=options)

            folder_name = "Ab. " + archivo
            forms_folder = 'forms/'
            target_folder = os.path.join(forms_folder, folder_name)
            os.makedirs(target_folder, exist_ok=True)

            shutil.move(filename, os.path.join(target_folder, filename))
            for foto in fotos:
                if foto.filename == "":
                    continue
                if not allowed_file(foto.filename):
                    return render_template("ampliacion_robo.html", error="Archivo no permitido.")
            if not enviar_correo(filename, input_nopol, archivo, user_name, user_email, fotos, "formulario_generico"):
                return render_template("ampliacion_robo.html", error="El archivo PDF no existe")
            else:
                return render_template("ampliacion_robo.html", info="Correo enviado correctamente")
        return render_template("ampliacion_robo.html")
    else:
        return render_template("ampliacion_robo.html", error="No hay ningún usuario logueado en la aplicación")

@app.route("/ampliacion_cctv", methods=["POST", "GET"])
@login_required
def ampliacion_cctv():
    num_filas_str = request.form.get("camara")
    if num_filas_str is None or num_filas_str == "":
        num_filas = 0
    else:
        num_filas = int(num_filas_str)

    # Establece el número de columnas en la tabla
    num_columnas = 5

    # Recopila los valores de los campos de entrada en la tabla
    tabla = []
    for i in range(num_filas):
        fila = []
        for j in range(num_columnas):
            fila.append(request.form.get(f"fila{i}_columna{j}"))
        tabla.append(fila)
    num_camaras_str = request.form.get("camara")
    if num_camaras_str is None or num_camaras_str == "":
        num_camaras = 0
    else:
        num_camaras = int(num_camaras_str)
    camaras = []
    for i in range(num_camaras):
        camaras.append(request.form.get(f"camara{i}"))
    form_data = {
        "cliente": request.form.get("cliente"),
        "abonado": request.form.get("abonado"),
        "tecn_inst": request.form.get("tecn_inst"),
        "fecha": request.form.get("fecha"),
        "comentario": request.form.get("comentario"),
        "camaras": camaras,
        "tabla": tabla,
        "numero_filas": num_filas,
        "numero_columnas": num_columnas,
        "tabla_vacia": len(tabla) == 0
    }
    if 'name' in session and 'email' in session:
        user_name = session['name']
        user_email = session['email']
        archivo = request.form.get("abonado")
        current_date_time = datetime.now().strftime('%d-%m-%Y %H-%M')
        input_nopol = request.form.get("comentario")
        fotos = request.files.getlist('fotos')
        if request.method == "POST":
            # Renderizar la plantilla con los datos del formulario
            rendered_html = render_template("ampliacion_cctv_pdf.html", **form_data)

            # Crear PDF
            filename = "PROGRAMACIÓN AMPLIACIÓN CCTV AB. " + archivo + " " + current_date_time + '.pdf'
            options = {
                'enable-local-file-access': None  # Habilita el acceso a archivos locales (necesario para cargar recursos como CSS)
            }
            pdfkit.from_string(rendered_html, filename, options=options)

            folder_name = "Ab. " + archivo
            forms_folder = 'forms/'
            target_folder = os.path.join(forms_folder, folder_name)
            os.makedirs(target_folder, exist_ok=True)

            shutil.move(filename, os.path.join(target_folder, filename))
            for foto in fotos:
                if foto.filename == "":
                    continue
                if not allowed_file(foto.filename):
                    return render_template("ampliacion_cctv.html", error="Archivo no permitido.")
            if not enviar_correo(filename, input_nopol, archivo, user_name, user_email, fotos, "formulario_generico"):
                return render_template("ampliacion_cctv.html", error="El archivo PDF no existe")
            else:
                return render_template("ampliacion_cctv.html", info="Correo enviado correctamente")
        return render_template("ampliacion_cctv.html")
    else:
        return render_template("ampliacion_cctv.html", error="No hay ningún usuario logueado en la aplicación")

@app.route("/auditoria", methods=["POST", "GET"])
@login_required
def auditoria():
    form_data = {
        "cliente": request.form.get("cliente"),
        "abonado": request.form.get("abonado"),
        "tecnico": request.form.get("tecnico"),
        "fecha": request.form.get("fecha"),
        "defi_seg": request.form.get("defi_seg"),
        "prop_mej": request.form.get("prop_mej"),
        "defi_com": request.form.get("defi_com"),
        "prop_mej_com": request.form.get("prop_mej_com"),
        "elementos": request.form.get("elementos"),
        "cable": request.form.get("cable"),
        "mano_obra": request.form.get("mano_obra"),
        "ayudante": request.form.get("ayudante"),
        "elevacion": request.form.get("elevacion"),
        "otros": request.form.get("otros"),
    }
    if 'name' in session and 'email' in session:
        user_name = session['name']
        user_email = session['email']
        archivo = request.form.get("abonado")
        current_date_time = datetime.now().strftime('%d-%m-%Y %H-%M')
        input_nopol = request.form.get("comentario")
        fotos = request.files.getlist('fotos')
        if request.method == "POST":
            # Renderizar la plantilla con los datos del formulario
            rendered_html = render_template("auditoria_pdf.html", **form_data)

            # Crear PDF
            filename = "HOJA DE AUDITORIA AB." + archivo + " " + current_date_time + '.pdf'
            options = {
                'enable-local-file-access': None  # Habilita el acceso a archivos locales (necesario para cargar recursos como CSS)
            }
            pdfkit.from_string(rendered_html, filename, options=options)

            folder_name = "Ab. " + archivo
            forms_folder = 'forms/'
            target_folder = os.path.join(forms_folder, folder_name)
            os.makedirs(target_folder, exist_ok=True)

            shutil.move(filename, os.path.join(target_folder, filename))
            for foto in fotos:
                if foto.filename == "":
                    continue
                if not allowed_file(foto.filename):
                    return render_template("auditoria.html", error="Archivo no permitido.")
            if not enviar_correo(filename, input_nopol, archivo, user_name, user_email, fotos, "formulario_auditoria"):
                return render_template("auditoria.html", error="El archivo PDF no existe")
            else:
                return render_template("auditoria.html", info="Correo enviado correctamente")
        return render_template("auditoria.html")
    else:
        return render_template("auditoria.html", error="No hay ningún usuario logueado en la aplicación")

@app.route("/rma", methods=["POST", "GET"])
@login_required
def rma():
    num_filas_str = request.form.get("equipos")
    if num_filas_str is None or num_filas_str == "":
        num_filas = 0
    else:
        num_filas = int(num_filas_str)

    # Establece el número de columnas en la tabla
    num_columnas = 5

    # Recopila los valores de los campos de entrada en la tabla
    tabla = []
    for i in range(num_filas):
        fila = [str(i + 1)]
        for j in range(1, num_columnas):
            fila.append(request.form.get(f"fila{i}_columna{j}"))
        tabla.append(fila)
    num_equipos_str = request.form.get("equipos")
    if num_equipos_str is None or num_equipos_str == "":
        num_equipos = 0
    else:
        num_equipos = int(num_equipos_str)
    equipos = []
    for i in range(num_equipos):
        equipos.append(request.form.get(f"equipo{i}"))
    form_data = {
        "fecha": request.form.get("fecha"),
        "rma": request.form.get("rma"),
        "sat": request.form.get("sat"),
        "transporte": request.form.get("transporte"),
        "direccion": request.form.get("direccion"),
        "cod_postal": request.form.get("cod_postal"),
        "poblacion": request.form.get("poblacion"),
        "provincia": request.form.get("provincia"),
        "equipos": equipos,
        "tabla": tabla,
        "numero_filas": num_filas,
        "numero_columnas": num_columnas,
        "tabla_vacia": len(tabla) == 0,
        "comentario": request.form.get("comentario")
    }
    if 'name' in session and 'email' in session:
        user_name = session['name']
        user_email = session['email']
        archivo = request.form.get("rma")
        input_nopol = request.form.get("comentario")
        fotos = request.files.getlist('fotos')
        if request.method == "POST":
            # Renderizar la plantilla con los datos del formulario
            rendered_html = render_template("rma_pdf.html", **form_data)

            # Crear PDF
            filename = "HOJA RMA " + archivo + '.pdf'
            options = {
                'enable-local-file-access': None,  # Habilita el acceso a archivos locales (necesario para cargar recursos como CSS)
                'encoding': "utf-8"
            }
            pdfkit.from_string(rendered_html, filename, options=options)

            folder_name = "RMA " + archivo
            forms_folder = 'forms/'
            target_folder = os.path.join(forms_folder, folder_name)
            os.makedirs(target_folder, exist_ok=True)

            shutil.move(filename, os.path.join(target_folder, filename))
            for foto in fotos:
                if foto.filename == "":
                    continue
                if not allowed_file(foto.filename):
                    return render_template("rma.html", error="Archivo no permitido.")
            if not enviar_correo(filename, input_nopol, archivo, user_name, user_email, fotos, "formulario_rma"):
                return render_template("rma.html", error="El archivo PDF no existe")
            else:
                return render_template("rma.html", info="Correo enviado correctamente")
        return render_template("rma.html")
    else:
        return render_template("rma.html", error="No hay ningún usuario logueado en la aplicación")

def read_rma_number():
    if not os.path.exists('rma_number.json'):
        return 0

    with open('rma_number.json', 'r') as f:
        data = json.load(f)
        return data['rma_number']

def write_rma_number(rma_number):
    with open('rma_number.json', 'w') as f:
        json.dump({'rma_number': rma_number}, f)

@app.route('/get_rma_number', methods=['GET'])
def get_rma_number():
    current_rma_number = read_rma_number()
    return jsonify(rma_number=current_rma_number)

@app.route('/increment_rma_number', methods=['POST'])
def increment_rma_number():
    current_rma_number = read_rma_number()
    new_rma_number = current_rma_number + 1
    write_rma_number(new_rma_number)
    return jsonify(rma_number=new_rma_number)

def allowed_file(filename):
    ALLOWED_EXTENSIONS = {'jpg', 'jpeg', 'png'}
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def enviar_correo(nombre_archivo, input_nopol, archivo, user_name, user_email, fotos, formulario_tipo):
    #Configuración del envío de formularios.
    SERVER = "smtp.office365.com"
    FROM = "formularios@sic24.com"

    if formulario_tipo =="formulario_auditoria":
        SUBJECT = f"Formulari d'auditoria del Ab. {archivo} enviado por {user_name}"
        TEXT = "En aquest correu s'adjunta el full d'auditoria del Ab." + archivo
        TO = ["anaval@sic24.com"]
        if user_email not in TO:
            TO.append(user_email)
    elif formulario_tipo =="formulario_rma":
        SUBJECT = f"Formulari RMA de. {archivo} enviado por {user_name}"
        TEXT = "En aquest correu s'adjunta el full RMA de " + archivo
        TO = ["efrancas@sic24.com", "amoreno@sic24.com"]
        if user_email not in TO:
            TO.append(user_email)
    else:
        SUBJECT = f"Formulari Programacio Ab. {archivo} enviado por {user_name}"
        TEXT = "En aquest correu s'adjunta el full de programació del Ab." + archivo
        TO = ["instalaciones@sic24.com", "jmaguado@sic24.com", "jurrea@sic24.com", "miguel@sic24.com"] # must be a list
        if user_email not in TO:
            TO.append(user_email)

    # Preparar correo
    message = """From: %s\r\nTo: %s\r\nSubject: %s\r\n\

    %s
    """ % (FROM, ", ".join(TO), SUBJECT, TEXT)
    if formulario_tipo =="formulario_rma":
        #Adjuntar PDF
        filename = nombre_archivo
        folder_name = "RMA " + archivo
        filepath = f'forms/{folder_name}/{filename}'
        msg = MIMEMultipart()
        msg['From'] = FROM
        msg['To'] = ", ".join(TO)
        msg['Subject'] = SUBJECT
        msg.attach(MIMEText(TEXT))
    else:
        #Adjuntar PDF
        filename = nombre_archivo
        folder_name = "Ab. " + archivo
        filepath = f'forms/{folder_name}/{filename}'
        msg = MIMEMultipart()
        msg['From'] = FROM
        msg['To'] = ", ".join(TO)
        msg['Subject'] = SUBJECT
        msg.attach(MIMEText(TEXT))

    if os.path.exists(filepath):
        with open(filepath, "rb") as f:
            attach = MIMEApplication(f.read(),_subtype="pdf")
            attach.add_header('content-disposition','attachment',filename=filename)
            msg.attach(attach)
    else:
        return False

    for foto in fotos:
        if foto and allowed_file(foto.filename):
            image_data = foto.read()
            image = MIMEImage(image_data, name=foto.filename)
            msg.attach(image)

    #Enviar el correo
    server = smtplib.SMTP(SERVER)
    server.connect(SERVER)
    server.ehlo()
    server.starttls()
    server.ehlo()
    server.login("formularios@sic24.com", "APN!g@vh")
    server.sendmail(FROM, TO, msg.as_string())
    server.quit()
    return True

@app.route("/recursos", methods=["GET","POST"])
@login_required
@role_required(['admin', 'usuario'])
def recursos():
	return render_template("/recursos.html")

@app.route("/soporte", methods=["GET","POST"])
@login_required
@role_required(['admin', 'usuario'])
def soporte():
	return render_template("/soporte.html")

# Invalid URL
@app.errorhandler(404)
def page_not_found(e):
	return render_template("404.html"), 404

# Internal server error
@app.errorhandler(500)
def internal_server_error(e):
	return render_template("500.html"), 500

#Secret Key de la DB / Inicio de la APP
if __name__ == "__main__":
	app.secret_key = "AbcDefGhi12345()!?==-=/.,;:'?¿¡"
	app.run(debug=True, host='0.0.0.0', port='8000')
