#!/usr/bin/env python
# -*- coding: utf-8 -*-
from flask import Flask, render_template, g, request, redirect, url_for,  make_response, flash, session
import logging, psycopg2
import hashlib, os, time
from configparser import ConfigParser
import time
import pip
import bcrypt
from flask_wtf import form
from flask_wtf import FlaskForm, RecaptchaField, Form
from wtforms import StringField
import re
#import regex
#UsersStatus = []

class SignupForm(FlaskForm):
    username = StringField('Username')
    recaptcha = RecaptchaField()


from datetime import timedelta
app = Flask(__name__)
# The secret key is used to cryptographically-sign the cookies used for storing the session data.
app.secret_key = b'_5#y2L"F4Q8z\n\xec]/'
app.config['PERMANENT_SESSION_LIFETIME'] =  timedelta(minutes=10)

global COOKIE_TIME_OUT
#COOKIE_TIME_OUT = 60*60*24*7 #7 days
COOKIE_TIME_OUT = 60*5 #5 minutes

#from flask.ext.login import current_user

#import flask_login
#from flask_login import current_user, login_user, login_required, logout_user, LoginManager, UserMixin


#chaves para recaptcha
#falta definir as chaves certas para que funcione correctamente
#https://flask-wtf.readthedocs.io/en/latest/form/#recaptcha
#https://stackoverflow.com/questions/3232904/using-recaptcha-on-localhost
#Localhost domains are no longer supported by default. 
# If you wish to continue supporting them for development you can add them to the list of supported domains for your
# site key. Go to the admin console to update your list of supported domains. 
# We advise to use a separate key for development and production and to not allow localhost on your production site 
# key. Just add localhost to your list of domains for your site and you'll be good.
app.config['RECAPTCHA_USE_SSL'] = False
app.config['RECAPTCHA_PUBLIC_KEY'] = '6LeIxAcTAAAAAJcZVRqyHh71UMIEGNQ_MXjiZKhI'
app.config['RECAPTCHA_PRIVATE_KEY'] = '6LeIxAcTAAAAAGG-vFI1TnRWxMZNFuojJ4WifJWe'
app.config['RECAPTCHA_OPTIONS'] = {'theme': 'white'}



#users = []

'''
def init_app(app):
    login_manager = LoginManager()
    login_manager.init_app(app) # Enable Login
    login_manager.login_view = "login" # Enable redirects if unauthorized

    @login_manager.user_loader
    def load_user(id):
        return User.query.get(id)


@app.before_request
def before_request():
    #g.user = current_user  # PROBLEMA AQUI!
    g.user = None
'''

'''
# User class
class User(UserMixin, db.Model):
    """Wraps User object for Flask-Login"""
    def __init__(self, user):
        self._user = user

    def get_id(self):
        return unicode(self._user.id)

    def is_active(self):
        return self._user.enabled

    def is_anonymous(self):
        return False

    def is_authenticated(self):
        return True
'''


@app.route("/")
def home():
    logger.info("user session pop out")
    session.pop('user_id', None)
    logger.info(session)
    #logout_user()
    return render_template("index.html");


@app.route("/useradd.html", methods=['GET'])
def useraddhtml():
    form = SignupForm()
    logger.info("user session pop out")
    session.pop('user_id', None)
    logger.info(session)
    #logout_user()
    return render_template("/useradd.html",form = form)


@app.route("/useradd", methods=['POST'])
def useradd():
    form = SignupForm()
    password = request.form['new_password']
    username = request.form['new_username']
    cpassword = request.form['confirmed_password']
    
    #sanitize
    rexes = (' OR ', ' AND ', '<', '>','\'','\"',"--" )
    if  (any(re.search(r, username) for r in rexes)):
        # unsecure username
        t_message = "Insecure username. Please stop trying to hack this form!"
        flash(t_message)
        logger.info(t_message)
        return render_template("useradd.html",form = form)
    username=sanitize(username,'pass')
    password=sanitize(password,'pass')
    cpassword=sanitize(cpassword,'pass')
    
    #checks if the password and confirmed password are the same
    if password != cpassword:
        # password mismatch
        t_message = "password mismatch"
        flash(t_message)
        logger.info(t_message)
        return render_template("useradd.html",form = form)

    #forçar passwords seguras
    rexes = ('[A-Z]', '[a-z]', '[0-9]','@','!')
    if not (len(password) >= 12 and all(re.search(r, password) for r in rexes)):
        # unsecure password
        t_message = "Unsecure password. Please choose one password with more than 12 symbols, including lower and upper case letters, numbers and one of the simbols @ or !."
        flash(t_message)
        logger.info(t_message)
        return render_template("useradd.html",form = form)

    # Here we catch and display any errors that occur whe accesing the DB
    try:
        conn = get_db()
        cur = conn.cursor()
    except conn.Error as e: #isto nao esta bem?
        t_message = "Database error: " + e + "/n SQL: "
        logger.info(t_message)
        return render_template("part1.html", message = t_message)
    
    #Query the DB to check if the name already exists
    sqlquery=("SELECT * FROM users WHERE username = '{}'").format(username)
    cur.execute(sqlquery)
    array_row = cur.fetchone() #fetchall seria mais arriscado
    # array_row[0] is the username, array_row[1] is the h_password, array_row[2] is the salt
    logger.info(array_row) #just for logging the output of the query
    if array_row is not None:
        # User exists
        t_message = "Existing user, " + username + ", please define a new username!"
        flash(t_message)
        logger.info(t_message)
        conn.close ()
        return render_template("useradd.html",form = form)

    #*********************bcrypt
    salt = bcrypt.gensalt()
    h_password = bcrypt.hashpw(password.encode('utf-8'),salt)   
    sqlquery=('INSERT INTO users (username,password,salt) VALUES (%s,%s,%s)')
    val=(username,h_password.decode('utf-8'),salt.decode('utf-8'))
    cur.execute(sqlquery,val)
    conn.commit ()
    conn.close ()
    logger.info(val)

    t_message = "User "+username+" added with success."
    flash(t_message)
    logger.info(t_message)
    #test only export users
    #export_users()
    return render_template("part1.html",form = form);


@app.route("/approved.html", methods=['GET'])
#@login_required
def approved():
    logger.info('----APPROVED-----')
    #validação da sessão
    try:
        session['user_id']
    except:
        logger.info("Tentativa de aceder sem sessão iniciada!")
        return render_template("index.html");


    logger.info(session)
    #t_message='User: '+ session['user_id']
    #flash(t_message) 
    return render_template("approved.html");

@app.route("/part1.html", methods=['GET'])
def login():
  

    return render_template("part1.html");


@app.route("/part1_vulnerable", methods=['GET', 'POST'])
def part1_vulnerable():
    logger.info("---- part1_vulnerable ----")

    if request.method == 'GET':
        password = request.args.get('v_password') 
        username = request.args.get('v_username') 
        remember = request.args.get('v_remember') 
        #session['text'] = request.args.get('v_username') # isto pode ser comentado???
    else:
        password = request.form['v_password']
        username = request.form['v_username']
        remember = request.form['v_remember']
        # Save the form data to the session object
        #session['text'] = request.form['v_username']

    # Here we catch and display any errors that may occur
    try:
        conn = get_db()
        cur = conn.cursor()
    except conn.Error as e: #isto nao esta bem?
        t_message = "Database error: " + e + "/n SQL: "
        logger.info(t_message)
        return render_template("part1.html")
    
    #Query the DB unsecurely for the stored salt
    sqlquery=("SELECT * FROM users WHERE username = '" + username +"'")
    logger.info(sqlquery) 
    cur.execute(sqlquery)
    array_row = cur.fetchone() #fetchall seria mais arriscado
    # array_row[0] is the username, array_row[1] is the h_password, array_row[2] is the salt
    logger.info(array_row) #just for logging the output of the query
    if array_row is None:
        # User does not exist
        t_message = "User does not exist" #mensegem de erro insegura
        flash(t_message)
        logger.info(t_message)
        conn.close ()
        return render_template("part1.html")

    #SHA512
    # hpass_with_stored_salt=hashlib.sha512(array_row[2].encode() + password.encode()).hexdigest()
    #BCRYPT
    hpass_with_stored_salt=bcrypt.hashpw(password.encode('utf-8'),array_row[2].encode('utf-8'))

    #Query the DB unsecurely for the entry with salt and username
    sqlquery=("SELECT * FROM users WHERE username = '" + username +"' AND password = '" + hpass_with_stored_salt.decode('utf-8') +"'")
    logger.info(sqlquery) 
    cur.execute(sqlquery)
    array_row = cur.fetchone() #fetchall seria mais arriscado
    # array_row[0] is the username, array_row[1] is the h_password, array_row[2] is the salt
    conn.close ()
    if array_row is None:
        # User/pass are not correct
        t_message = "Password is not correct"
        flash(t_message)
        logger.info(t_message)
        return render_template("part1.html")


    #mensagem de sucesso da validação do user
    t_message = "You were successfully logged with the insecure form, user " + username
    flash(t_message)
    logger.info(t_message)

    #estabelecimento da sessão
    session['user_id'] = username
    logger.info(session)
    #next = request.args.get('next')
    #user = User.query.filter_by(username=username).first()
    #user = User.get(int(id))
    #t_message='User: '+ session['user_id']
    #flash(t_message) 
    return render_template("approved.html")

   

@app.route("/part1_correct", methods=['POST'])
# method get is dangerous
def part1_correct():
    logger.info("---- part1_correct ----")

    password = request.form['c_password']
    username = request.form['c_username']
    remember = request.form['c_remember']

    #sanitizacao de inputs
    rexes = (' OR ', ' AND ', '<', '>','\'','\"','--' )
    if  (any(re.search(r, username) for r in rexes)):
        # unsecure username
        t_message = "Unsecure username. Please stop trying to hack this form!"
        flash(t_message)
        logger.info(t_message)
        return render_template("part1.html", message = t_message)
    #password validation is probably not needed!
    if  (any(re.search(r, password) for r in rexes)):
        # unsecure username
        t_message = "Unsecure password. Please stop trying to hack this form!"
        flash(t_message)
        logger.info(t_message)
        return render_template("part1.html", message = t_message)
    username=sanitize(username,'pass')
    password=sanitize(password,'pass')
    
   
  
    # Here we catch and display any errors that occur
    try:
        conn = get_db()
        cur = conn.cursor()
    except conn.Error as e: #isto nao esta bem?
        t_message = "Database error: " + e + "/n SQL: "
        logger.info(t_message)
        return render_template("part1.html", message = t_message)
    
    #Query the DB and fetch the salt of the user
    sqlquery=("SELECT * FROM users WHERE username = '{}'").format(username)
    logger.info(sqlquery) 
    cur.execute(sqlquery)
    try: #maior protecção quanto a erros na query
        array_row = cur.fetchone() #fetchall seria mais arriscado
    except psycopg2.Error as e:
      t_error_message = "Database error: " + e + "/n SQL: " 
    conn.close ()

    logger.info(array_row)
    #logger.info(bcrypt.hashpw(password.encode('utf-8'),array_row[2].encode('utf-8')))
    check = False
    try:
        check = bcrypt.checkpw(password.encode('utf-8'),array_row[1].encode('utf-8'))
    except:
        t_message = "You have entered an invalid username or password"
        flash(t_message)
        logger.info(t_message)
        return render_template("part1.html")
    
    #mensagem de sucesso da validação do user
    t_message = "You were successfully logged with the secure form, user " + username
    flash(t_message)
    logger.info(t_message)

    #estabelecimento da sessão
    '''este codigo não funciona porque???
    if remember:
        print(t_message)
		response = make_response(redirect('index.html',500))
        response.set_cookie('user_id', username, max_age=COOKIE_TIME_OUT)
        return response
    '''
    session['user_id'] = username
    logger.info(session)

    return render_template("approved.html", message = t_message, user = session['user_id'])
    

@app.route("/part2.html", methods=['GET'])
#@login_required
def part2():
    logger.info("---- part2 ----")
    logger.info(session)

    try:
        session['user_id']
    except:
        logger.info("Tentativa de aceder sem sessão iniciada!")
        return render_template("index.html")

    return render_template("part2.html",user = session['user_id'])


@app.route("/part2_vulnerable", methods=['GET', 'POST'])
def part2_vulnerable():
    if request.method == 'GET':
        mensagem = request.args.get('v_text') 
    else:
        mensagem = request.form['v_text']

    # Here we catch and display any errors that occur
    try:
        conn = get_db()
        cur = conn.cursor()
    except conn.Error as e: #isto nao esta bem?
        t_message = "Database error: " + e + "/n SQL: "
        logger.info(t_message)
        flash(t_message)
        return render_template("part1.html", message = t_message)
    
    #escrita na BD
    sqlquery=("INSERT INTO messages (author,message) VALUES ('vulnerable','"+mensagem+"');COMMIT;")
    logger.info(sqlquery) 
    cur.execute(sqlquery)
    #leitura do ultimo elemento na BD
    sqlquery=("SELECT * FROM messages WHERE message_id=(SELECT max(message_id) FROM messages)")
    logger.info(sqlquery) 
    cur.execute(sqlquery)
    array_row = cur.fetchone() #fetchall seria mais arriscado
    t_message=array_row[2]
    logger.info(t_message) 
    conn.close ()
    flash(t_message)
    return  render_template("part2.html", message = t_message, user = session['user_id'])
    #return "/part2_vulnerable"


@app.route("/part2_correct", methods=['POST'])
def part2_correct():
    mensagem = request.form['c_text']

    # Here we catch and display any errors that occur
    try:
        conn = get_db()
        cur = conn.cursor()
    except conn.Error as e: #isto nao esta bem?
        t_message = "Database error: " + e + "/n SQL: "
        logger.info(t_message)
        flash(t_message)
        return render_template("part1.html", message = t_message)
    
    #sanitizacao
    mensagem=re.sub(r"[^a-zA-Z0-9!@?,. ]","",mensagem)
    mensagem = mensagem[:250] + ('..' if len(mensagem) > 250 else '')
    #escrita na BD
    sqlquery=('INSERT INTO messages (author,message) VALUES (%s,%s)')
    val=('correct',mensagem)
    try: #maior protecção quanto a erros na query
        cur.execute(sqlquery,val)
        conn.commit ()
    except psycopg2.Error as e:
        t_error_message = e
    #leitura do ultimo elemento na BD
    sqlquery=("SELECT * FROM messages WHERE message_id=(SELECT max(message_id) FROM messages)")
    logger.info(sqlquery) 
    try: #maior protecção quanto a erros na query
        cur.execute(sqlquery)
        array_row = cur.fetchone()
    except psycopg2.Error as e:
        t_error_message = e
    
    t_message=array_row[2]
    logger.info(t_message) 
    conn.close ()
    flash(t_message)
    
    return  render_template("part2.html",  message = t_message, user = session['user_id'])
    return "/part2_correct"


@app.route("/part3.html", methods=['GET'])
def part3():

    #validação da sessão
    try:
        session['user_id']
    except:
        logger.info("Tentativa de aceder sem sessão iniciada!")
        return render_template("index.html")

    return render_template("part3.html",user = session['user_id'])


@app.route("/part3_vulnerable", methods=['GET', 'POST'])
def part3_vulnerable():
    if request.method == 'GET':
        title = request.args.get('v_name') 
        author = request.args.get('v_author') 
        category = request.args.get('v_category_id') 
        pricemin = request.args.get('v_pricemin') 
        pricemax = request.args.get('v_pricemax') 
        search_input = request.args.get('v_search_input') 
        search_field = request.args.get('v_search_field') 
        sp_c = request.args.get('v_sp_c') 
        sp_m = request.args.get('v_sp_m') 
        radio_match = request.args.get('v_radio_match')
        sp_s = request.args.get('v_sp_s')
        sp_date_range = request.args.get('v_sp_date_range')
        sp_start_year = request.args.get('v_sp_start_year')
        sp_start_month = request.args.get('v_sp_start_month')
        sp_start_day = request.args.get('v_sp_start_day')
        sp_end_month= request.args.get('v_sp_end_month')
        sp_end_day = request.args.get('v_sp_end_day')
        sp_end_year = request.args.get('v_sp_end_year')
    else:
        title = request.form['v_name']
        author = request.form['v_author']
        category = request.form['v_category_id']
        pricemin = request.form['v_pricemin']
        pricemax = request.form['v_pricemax'] 
        search_input = request.form['v_search_input']
        search_field = request.form['v_search_field'] 
        sp_c = request.form['v_sp_c']
        sp_m = request.form['v_sp_m']
        radio_match = request.form['v_radio_match']
        sp_s = request.form['v_sp_s']
        sp_date_range = request.form['v_sp_date_range']
        sp_start_year = request.form['v_sp_start_year']
        sp_start_month = request.form['v_sp_start_month']
        sp_start_day = request.form['v_sp_start_day']
        sp_end_month= request.form['v_sp_end_month']
        sp_end_day = request.form['v_sp_end_day']
        sp_end_year = request.form['v_sp_end_year']
    
    sp_c=int(sp_c)

    # Here we catch and display any errors that occur
    try:
        conn = get_db()
        cur = conn.cursor()
    except conn.Error as e: #isto nao esta bem?
        t_message = "Database error: " + e + "/n SQL: "
        logger.info(t_message)
        flash(t_message)
        return render_template("part3.html", message = t_message)
    
    #construcao da query
    if search_input == '': #Search For vazio
        logger.info("Search For vazio")
        sqlquery=("SELECT * FROM books" +
        " WHERE (title LIKE '%" + title + "%'" +
        " AND authors LIKE '%" + author + "%'" +
        " AND category LIKE '%" + category + "%'" +
        " AND (price BETWEEN '" + pricemin + "'AND '" + pricemax + "'))" )
    else:
        if radio_match == 'phrase': #exact phrase
            if search_field =='any': #qualquer campo
                logger.info("Exact phrase e Within Anywhere")
                sqlquery=("SELECT * FROM books" +
                    " WHERE (title LIKE '%" + search_input + "%'" +
                    " OR authors LIKE '%" + search_input + "%'" +
                    " OR description LIKE '%" + search_input + "%'" +
                    " OR keywords LIKE '%" + search_input + "%'" + 
                    " OR notes LIKE '%" + search_input + "%')" )
            else: #campo especifico
                logger.info("Exact phrase e Withing specific")
                sqlquery=("SELECT * FROM books" +
                    " WHERE " + search_field +" LIKE '%" + search_input + "%'")
        elif radio_match == 'any': #Any word - ainda nao funciona
            if search_field =='any': #qualquer campo
                logger.info("Any word e Within Anywhere")
                sqlquery=("SELECT * FROM books" +
                    " WHERE ( LOWER(title) LIKE LOWER('%" + search_input + "%')" +
                    " OR LOWER(authors) LIKE LOWER('%" + search_input + "%')" +
                    " OR LOWER(description) LIKE LOWER('%" + search_input + "%')" +
                    " OR LOWER(keywords) LIKE LOWER('%" + search_input + "%')" + 
                    " OR LOWER(notes) LIKE LOWER('%" + search_input + "%'))" )
            else: #campo especifico
               logger.info("Any word e Within specific")
               sqlquery=("SELECT * FROM books" +
                    " WHERE LOWER(" + search_field +") LIKE LOWER('%" + search_input + "%')")
        elif radio_match == 'all': #All words - nao funciona
            if search_field =='any': #qualquer campo
                logger.info("All words e Within Anywhere")
                sqlquery=("SELECT * FROM books" +
                    " WHERE ( title LIKE '%" + search_input + "%'" +
                    " OR authors LIKE '%" + search_input + "%'" +
                    " OR description LIKE '%" + search_input + "%'" +
                    " OR keywords LIKE '%" + search_input + "%'" + 
                    " OR notes LIKE '%" + search_input + "%')" )
            else: #campo especifico
               logger.info("All words e Within specific")
               sqlquery=("SELECT * FROM books" +
                    " WHERE (" + search_field +" LIKE '%" + search_input + "%')")
    #sp_start_day=sp_start_month=sp_start_year=sp_end_day=sp_end_month=sp_end_year='00'
    #append do filtro do tempo
    if sp_date_range != '1' : #diferente de anytime
        sqlquery=sqlquery+" AND ( book_date BETWEEN DATE(NOW())-" + sp_date_range + " AND DATE(NOW()))"
        logger.info("filtro do tempo diferente de anytime")
    else:
        lista=(sp_start_day,sp_start_month,sp_start_year,sp_end_day,sp_end_month,sp_end_year)
        logger.info(lista)
        if not ((sp_start_day == '00') or (sp_start_month == '00')or (sp_start_year == '') or (sp_end_day == '00') or (sp_end_month == '00')or (sp_end_year == '')):
        #if any(i is not '00' for i in lista):       
            logger.info("filtro do tempo campos livres")
            date_start = sp_start_year + sp_start_month + sp_start_day
            date_end = sp_end_year + sp_end_month + sp_end_day
            logger.info(date_start)
            logger.info(date_end)
            sqlquery=sqlquery+" AND ( book_date BETWEEN '" + date_start + "' AND '" + date_end +"')"


    #sorting 
    if sp_s =='1': # ok por datas
        sqlquery=sqlquery+" ORDER BY book_date DESC"
    else:  # ainda nao esta bem por relevancia, faz apenas por titulo!
        sqlquery==sqlquery+" ORDER BY title DESC"
        
        '''(sqlquery+" ORDER BY CASE " +
               " WHEN word LIKE '"+search_input+"' THEN 1" +
               " WHEN word LIKE '"+search_input+"%' THEN 2" +
               " WHEN word LIKE '%"+search_input+"' THEN 4" +
               " ELSE 3 END")
        '''
    #sp_start_day=sp_start_month=sp_start_year=sp_end_day=sp_end_month=sp_end_year='00'
    logger.info(sqlquery)   
    try:
        cur.execute(sqlquery)
        array_row = cur.fetchmany(sp_c)
    except psycopg2.Error as e:
        t_error_message = e
        array_row = [None] 

  
    #esconder o campo description - ainda nao funciona
    if  sp_m=='0':
        as_list = list(array_row)
        logger.info("esconder campo description") 
        #array_row.remove(6)
        #for i in as_list: 
            #i.pop(6) #AttributeError: 'tuple' object has no attribute 'pop'
            #del i[6] #TypeError: 'tuple' object doesn't support item deletion
            #i.remove(6) #AttributeError: 'tuple' object has no attribute 'remove'
            #i.__delattr__('6')
        #array_row=tuple(as_list) 

    logger.info(array_row) 
    conn.close ()
    
    return  render_template("part3.html", livros = array_row, user = session['user_id'])
    #return "/part3_vulnerable"


@app.route("/part3_correct", methods=['POST'])
def part3_correct():
    title = sanitize(request.form['c_name'],'text')
    author = sanitize(request.form['c_author'],'text')
    category = sanitize(request.form['c_category_id'],'text')
    pricemin = sanitize(request.form['c_pricemin'],'number')
    pricemax = sanitize(request.form['c_pricemax'],'number')
    search_input = sanitize(request.form['c_search_input'],'text')
    search_field = sanitize(request.form['c_search_field'],'text')
    sp_c = sanitize(request.form['c_sp_c'],'number')
    sp_m = sanitize(request.form['c_sp_m'],'number')
    radio_match = sanitize(request.form['c_radio_match'],'text')
    sp_s = sanitize(request.form['c_sp_s'],'number')
    sp_date_range = sanitize(request.form['c_sp_date_range'],'number')
    sp_start_year = sanitize(request.form['c_sp_start_year'],'number')
    sp_start_month = sanitize(request.form['c_sp_start_month'],'number')
    sp_start_day = sanitize(request.form['c_sp_start_day'],'number')
    sp_end_month= sanitize(request.form['c_sp_end_month'],'number')
    sp_end_day = sanitize(request.form['c_sp_end_day'],'number')
    sp_end_year = sanitize(request.form['c_sp_end_year'],'number')
    
    sp_c=int(sp_c)

    # Here we catch and display any errors that occur
    try:
        conn = get_db()
        cur = conn.cursor()
    except conn.Error as e: #isto nao esta bem?
        t_message = "Database error: " + e + "/n SQL: "
        logger.info(t_message)
        flash(t_message)
        return render_template("part3.html", message = t_message)
    
    #construcao da query
    if search_input == '': #Search For vazio
        logger.info("Search For vazio")
        sqlquery=("SELECT * FROM books" +
        " WHERE (title LIKE '%" + title + "%'" +
        " AND authors LIKE '%" + author + "%'" +
        " AND category LIKE '%" + category + "%'" +
        " AND (price BETWEEN '" + pricemin + "'AND '" + pricemax + "'))" )
    else:
        if radio_match == 'phrase': #exact phrase
            if search_field =='any': #qualquer campo
                logger.info("Exact phrase e Within Anywhere")
                sqlquery=("SELECT * FROM books" +
                    " WHERE (title LIKE '%" + search_input + "%'" +
                    " OR authors LIKE '%" + search_input + "%'" +
                    " OR description LIKE '%" + search_input + "%'" +
                    " OR keywords LIKE '%" + search_input + "%'" + 
                    " OR notes LIKE '%" + search_input + "%')" )
            else: #campo especifico
                logger.info("Exact phrase e Withing specific")
                sqlquery=("SELECT * FROM books" +
                    " WHERE " + search_field +" LIKE '%" + search_input + "%'")
        elif radio_match == 'any': #Any word - ainda nao funciona
            if search_field =='any': #qualquer campo
                logger.info("Any word e Within Anywhere")
                sqlquery=("SELECT * FROM books" +
                    " WHERE ( LOWER(title) LIKE LOWER('%" + search_input + "%')" +
                    " OR LOWER(authors) LIKE LOWER('%" + search_input + "%')" +
                    " OR LOWER(description) LIKE LOWER('%" + search_input + "%')" +
                    " OR LOWER(keywords) LIKE LOWER('%" + search_input + "%')" + 
                    " OR LOWER(notes) LIKE LOWER('%" + search_input + "%'))" )
            else: #campo especifico
               logger.info("Any word e Within specific")
               sqlquery=("SELECT * FROM books" +
                    " WHERE LOWER(" + search_field +") LIKE LOWER('%" + search_input + "%')")
        elif radio_match == 'all': #All words - nao funciona
            if search_field =='any': #qualquer campo
                logger.info("All words e Within Anywhere")
                sqlquery=("SELECT * FROM books" +
                    " WHERE ( title LIKE '%" + search_input + "%'" +
                    " OR authors LIKE '%" + search_input + "%'" +
                    " OR description LIKE '%" + search_input + "%'" +
                    " OR keywords LIKE '%" + search_input + "%'" + 
                    " OR notes LIKE '%" + search_input + "%')" )
            else: #campo especifico
               logger.info("All words e Within specific")
               sqlquery=("SELECT * FROM books" +
                    " WHERE (" + search_field +" LIKE '%" + search_input + "%')")
    #sp_start_day=sp_start_month=sp_start_year=sp_end_day=sp_end_month=sp_end_year='00'
    #append do filtro do tempo
    logger.info("sp_date_range:"+ sp_date_range)
    if sp_date_range != '1' : #diferente de anytime
        sqlquery=sqlquery+" AND ( book_date BETWEEN DATE(NOW())-" + sp_date_range + " AND DATE(NOW()))"
        logger.info("filtro do tempo diferente de anytime")
    else:
        lista=(sp_start_day,sp_start_month,sp_start_year,sp_end_day,sp_end_month,sp_end_year)
        logger.info(lista)
        if not ((sp_start_day == '00') or (sp_start_month == '00')or (sp_start_year == '') or (sp_end_day == '00') or (sp_end_month == '00')or (sp_end_year == '')):
        #if any(i is not '00' for i in lista):       
            logger.info("filtro do tempo campos livres")
            date_start = sp_start_year + sp_start_month + sp_start_day
            date_end = sp_end_year + sp_end_month + sp_end_day
            logger.info(date_start)
            logger.info(date_end)
            sqlquery=sqlquery+" AND ( book_date BETWEEN '" + date_start + "' AND '" + date_end +"')"


    #sorting 
    if sp_s =='1': # ok por datas
        sqlquery=sqlquery+" ORDER BY book_date DESC"
    else:  # ainda nao esta bem por relevancia, faz apenas por titulo!
        sqlquery==sqlquery+" ORDER BY title DESC"
        

    logger.info(sqlquery)   
    try:
        cur.execute(sqlquery)
        array_row = cur.fetchmany(sp_c)
    except psycopg2.Error as e:
        t_error_message = e
        array_row = [None] 

  
    #esconder o campo description - ainda nao funciona
    if  sp_m=='0':
        as_list = list(array_row)
        logger.info("esconder campo description") 
        #array_row.remove(6)
        #for i in as_list: 
            #i.pop(6) #AttributeError: 'tuple' object has no attribute 'pop'
            #del i[6] #TypeError: 'tuple' object doesn't support item deletion
            #i.remove(6) #AttributeError: 'tuple' object has no attribute 'remove'
            #i.__delattr__('6')
        #array_row=tuple(as_list) 

    logger.info(array_row) 
    conn.close ()

    return  render_template("part3.html", livros = array_row, user = session['user_id'])

    #return "/part3_correct"


@app.route("/demo", methods=['GET', 'POST'])
def demo():
    logger.info("\n DEMO \n");   

    conn = get_db()
    cur = conn.cursor()

    logger.info("---- users  ----")
    cur.execute("SELECT * FROM users")
    rows = cur.fetchall()

    for row in rows:
        logger.info(row)

    for row in rows:
        logger.info(row)

    logger.info("---- messages ----")
    cur.execute("SELECT * FROM messages")
    rows = cur.fetchall()
 
    for row in rows:
        logger.info(row)

    logger.info("---- books ----")
    cur.execute("SELECT * FROM books")
    rows = cur.fetchall()
 
    for row in rows:
        logger.info(row)

    conn.close ()
    logger.info("\n---------------------\n\n") 

    return "/demo"

def sanitize(input,type):
    logger.info("sanitize input:")
    logger.info(input)
    if type=='pass': output=re.sub(r"[^a-zA-Z0-9!@]","",input)
    elif type=='text': output=re.sub(r"[^a-zA-Z0-9 ]","",input)
    elif type=='number': output=re.sub(r"[^0-9]","",input)
    logger.info("sanitize output:")
    logger.info(output)
    return output

##########################################################
## export full database
##########################################################
def export_db():
    conn = get_db()
    cur = conn.cursor()

    logger.info("---- users  ----")
    cur.execute("SELECT * FROM users")
    rows = cur.fetchall()

    for row in rows:
        logger.info(row)

    logger.info("---- messages ----")
    cur.execute("SELECT * FROM messages")
    rows = cur.fetchall()
 
    for row in rows:
        logger.info(row)

    logger.info("---- books ----")
    cur.execute("SELECT * FROM books")
    rows = cur.fetchall()
 
    for row in rows:
        logger.info(row)

    conn.close ()
    logger.info("\n---------------------\n\n") 
    return

def export_users():
    conn = get_db()
    cur = conn.cursor()

    logger.info("---- users  ----")
    cur.execute("SELECT * FROM users")
    rows = cur.fetchall()

    for row in rows:
        logger.info(row)

    conn.close ()
    logger.info("\n---------------------\n\n") 
    return

def export_books():
    conn = get_db()
    cur = conn.cursor()

    logger.info("---- books  ----")
    cur.execute("SELECT * FROM books")
    rows = cur.fetchall()

    for row in rows:
        logger.info(row)

    conn.close ()
    #logger.info("\n---------------------\n\n") 
    return
    
##########################################################
## DATABASE ACCESS
##########################################################
#https://www.postgresqltutorial.com/postgresql-python/connect/
# eliminação da vulnerabilidade de passwords no código,. Criado um ficheiro Database.ini onde são colocadas as credenciais.
def config(filename='Database.ini', section='postgresql'):
    # create a parser
    parser = ConfigParser()
    # read config file
    parser.read(filename)

    # get section, default to postgresql
    db = {}
    if parser.has_section(section):
        params = parser.items(section)
        for param in params:
            db[param[0]] = param[1]
    else:
        raise Exception('Section {0} not found in the {1} file'.format(section, filename))

    return db



def get_db():
    params = config()
    db = psycopg2.connect(**params)
    #db = psycopg2.connect(user = "ddss-database-assignment-2",
    #            password = "ddss-database-assignment-2",
    #            host = "db",
    #            port = "5432",
    #            database = "ddss-database-assignment-2")
    return db





##########################################################
## MAIN
##########################################################
if __name__ == "__main__":
    
    logging.basicConfig(filename="logs/log_file.log")
    # If ran from the compiler we get a permission eror because the owner of the log is root
    # PermissionError: [Errno 13] Permission denied: '/home/rpires/git/ddss2021-dominoro/python/app/logs/log_file.log'
    # run the docker "web"
    logger = logging.getLogger('logger')
    logger.setLevel(logging.DEBUG)
    ch = logging.StreamHandler()
    ch.setLevel(logging.DEBUG)

    # create formatter
    formatter = logging.Formatter('%(asctime)s [%(levelname)s] %(name)s:  %(message)s')

    # add formatter to ch
    ch.setFormatter(formatter)

    # add ch to logger
    logger.addHandler(ch)

    #logger.info("\n---------------------\n\n")

    app.run(host="0.0.0.0", debug=True, threaded=True)





