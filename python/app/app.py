#!/usr/bin/env python
# -*- coding: utf-8 -*-
from flask import Flask, render_template, g, request, redirect, url_for,  make_response, flash, session, Response, escape
import logging, psycopg2, sys, io
import hashlib, os, time
from configparser import ConfigParser
import time
import pip
import bcrypt
from flask_wtf import form
from flask_wtf import FlaskForm, RecaptchaField,  Form
from wtforms import StringField
from flask_recaptcha import ReCaptcha
import re
import pyotp, pyqrcode, qrcode, base64
import click, shutil
from itsdangerous import URLSafeSerializer
#from flask_wtf.csrf import CSRFProtect



from datetime import datetime, timedelta
app = Flask(__name__)
#csrf = CSRFProtect(app)
# The secret key is used to cryptographically-sign the cookies used for storing the session data.
#Random secret key
app.config['SECRET_KEY']=os.urandom(24)
app.config['PERMANENT_SESSION_LIFETIME'] =  timedelta(minutes=10)

app.config["OTP_ENABLED"] = "False"

global COOKIE_TIME_OUT
COOKIE_TIME_OUT = 60*5 #5 minutes

#chaves para recaptcha
app.config['RECAPTCHA_USE_SSL'] = False
app.config['RECAPTCHA_SITE_KEY'] = '6LfWQrgdAAAAAI32HGal7CDZwdqCr0nx7sDjJJv-' # <-- Add your site key
app.config['RECAPTCHA_SECRET_KEY'] = '6LfWQrgdAAAAAHS3MRJbLA0mtMQ7wewElzOHfd9h' # <-- Add your secret key
recaptcha = ReCaptcha(app) # Create a ReCaptcha object by passing in 'app' as parameter
class SignupForm(FlaskForm):
    username = StringField('Username')
    recaptcha = RecaptchaField()

#Before Requests for Session
@app.before_request
def before_request():
    g.user = None
    if 'user_id' in session:
        g.user = session['user_id']

#Logout
def logout():
    logger.info("logout user")
    #logger.info("delete cookie not yet working")
    #Response.set_cookie('csrf_token','',expires=0)
    #Response.delete_cookie('user_id')
    #resp = make_response(render_template(...))
    #resp.set_cookie('user_id', expires = 0)
    logger.info("session pop")
    session.pop('user_id', None)
    logger.info(session)
    return render_template("index.html")



@app.route("/")
def home():
    logger.info("user session pop out")
    session.pop('user_id', None)
    logger.info(session)
    
    #logout_user()
    #logger.info(export_db())
    return render_template("index.html")


@app.route("/useradd.html", methods=['GET'])
def useraddhtml():
    
    form = SignupForm()
    logout()
    return render_template("/useradd.html",form = form)

@app.route("/useradd_vulnerable", methods=['GET', 'POST'])
def useradd_vulnerable():
    form = SignupForm()
    if request.method == 'GET':
        password = request.args.get('new_password') 
        username = request.args.get('new_username') 
        cpassword = request.args.get('confirmed_password') 
    else:
        password = request.form['new_password']
        username = request.form['new_username']
        cpassword = request.form['confirmed_password']
    
    
    try:
        conn = get_db()
        cur = conn.cursor()
    except conn.Error as e: 
        t_message = "Database error: " + e + "/n SQL: "
        logger.info(t_message)
        return render_template("part1.html")
    
    #Query the DB to check if the name already exists
    sqlquery=("SELECT * FROM users WHERE username = '"+username+"'")
    logger.info(sqlquery)
    cur.execute(sqlquery)
    array_row = cur.fetchone() #fetchall seria mais arriscado
    # array_row[0] is the username, array_row[1] is the h_password, array_row[2] is the salt
    logger.info(array_row) #just for logging the output of the query
    if array_row is not None:
        # User exists
        t_message = "Existing user, " + username + ", please define a new username!"
        
        logger.info(t_message)
        conn.close ()
        return render_template("useradd.html",message_v=t_message,form = form)
    else:
        if password == cpassword:
            salt = bcrypt.gensalt()
            h_password = bcrypt.hashpw(password.encode('utf-8'),salt)   
            sqlquery=("INSERT INTO users (username,password,salt,otp) VALUES ('"+username+"', '"+h_password.decode('utf-8')+"', '"+salt.decode('utf-8')+"','none')")
            logger.info(sqlquery)
            cur.execute(sqlquery)
            conn.commit ()
            conn.close ()
            t_message = "User "+username+" added with success.You can now login in one of the displayed forms"
            logger.info(t_message)                            
            return render_template("part1.html", message_v=t_message)       
        else:
                t_message = "Password mismatch"
                logger.info(t_message)
                return render_template("useradd.html", message_v=t_message, form = form)
        
        
@app.route("/useradd_correct", methods=['POST'])
def useradd_correct():
    form = SignupForm()
    app.config["OTP_ENABLED"] = "False"
    password = request.form['new_password']
    username = request.form['new_username']
    cpassword = request.form['confirmed_password']
    
    #sanitize
    rexes = (' OR ', ' AND ', '<', '>','\'','\"',"--" )
    if  (any(re.search(r, username) for r in rexes)):
        # unsecure username
        t_message = "Insecure username. Please stop trying to hack this form!"
        logger.info(t_message)
        return render_template("useradd.html",form = form, message_c=t_message)
    
    username=sanitize(username,'pass')
    password=sanitize(password,'pass')
    cpassword=sanitize(cpassword,'pass')
    
    try:
        conn = get_db()
        cur = conn.cursor()
    except conn.Error as e: 
        t_message = "Database error: " + e + "/n SQL: "
        logger.info(t_message)
        return render_template("part1.html")
    
    #Query the DB to check if the name already exists
    sqlquery=("SELECT * FROM users WHERE username = '{}'").format(username)
    cur.execute(sqlquery)
    array_row = cur.fetchone() #fetchall seria mais arriscado
    # array_row[0] is the username, array_row[1] is the h_password, array_row[2] is the salt
    logger.info(array_row) #just for logging the output of the query
    if array_row is not None:
        # User exists
        t_message = "Existing user, " + username + ", please define a new username!"
        logger.info(t_message)
        conn.close ()
        return render_template("useradd.html",form = form, message_c=t_message)
    else:
        if recaptcha.verify():
            #Check if password is secure
            rexes = ('[A-Z]', '[a-z]', '[0-9]','[@,!]')
            if (len(password) >= 12 and all(re.search(r, password) for r in rexes)):
                #checks if the password and confirmed password are the same
                if password == cpassword:

                    logger.info(username)
                    salt = bcrypt.gensalt()
                    h_password = bcrypt.hashpw(password.encode('utf-8'),salt)  
                    logger.info(h_password.decode('utf-8'))
                    logger.info(salt.decode('utf-8'))
                    otp=pyotp.random_base32()
                    logger.info(otp)
                    cur.execute("INSERT INTO users(username,password,salt,otp) VALUES ('" + username + "', '" + h_password.decode('utf-8') + "','"+salt.decode('utf-8')+"', '"+otp+"')")
                    conn.commit ()
                    conn.close ()
                    
                    t_message = "User "+username+" added with success. You can now login"
                    logger.info(t_message)
                    return  render_template("auth.html", secret_key=otp)
                else:
                    t_message = "Password mismatch"
                    logger.info(t_message)
                    return render_template("useradd.html", message_c=t_message,form = form)
            else:
                t_message = "Unsecure password. Please choose one password with more than 12 symbols, including lower and upper case letters, numbers and one of the simbols @ or !."
                logger.info(t_message)
                return render_template("useradd.html", message_c=t_message, form = form)
        else:
            t_message = "Incorrect CAPTCHA"
            logger.info(t_message)
            return render_template("useradd.html", message_c=t_message, form = form)
                    

@app.route("/approved.html", methods=['GET'])
#@login_required
def approved():
    logger.info('---- reached approved.html -----')
    #validação da sessão
    if not g.user:
        logger.info("Tentativa de aceder sem sessão iniciada!")
        return render_template("index.html")
    logger.info(session)
    return render_template("approved.html")
    

@app.route("/part1.html", methods=['GET'])
def login():
    logger.info("---- reached part1.html ----")
    return render_template("part1.html")
    

@app.route("/part1_vulnerable", methods=['GET', 'POST'])
def part1_vulnerable():
    logger.info("---- part1_vulnerable ----")
    logger.info(g.user)
    if request.method == 'GET':
        password = request.args.get('v_password') 
        username = request.args.get('v_username') 
        remember = request.args.get('v_remember') 
        #session['text'] = request.args.get('v_username') 
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
    except conn.Error as e:
        t_message = "Database error: " + e + "/n SQL: "
        logger.info(t_message)
        return render_template("part1.html")
    
    #Query the DB unsecurely for the stored salt
    sqlquery=("SELECT * FROM users WHERE username = '" + username+"'" )
    logger.info(sqlquery) 
    cur.execute(sqlquery)
    array_row = cur.fetchone() #fetchall seria mais arriscado
    # array_row[0] is the username, array_row[1] is the h_password, array_row[2] is the salt
    logger.info(array_row) #just for logging the output of the query
    if array_row is None:
        # User does not exist
        t_message = "User does not exist" #mensegem de erro insegura
        #flash(t_message)
        logger.info(t_message)
        conn.close ()
        return render_template("part1.html", message_v=t_message)

    #BCRYPT
    hpass_with_stored_salt=bcrypt.hashpw(password.encode('utf-8'),array_row[2].encode('utf-8'))

    #Query the DB unsecurely for the entry with salt and username
    sqlquery=("SELECT * FROM users WHERE username = '" + username +"' AND password = '" + hpass_with_stored_salt.decode('utf-8')+"'")
    logger.info(sqlquery) 
    cur.execute(sqlquery)
    array_row = cur.fetchone() #fetchall seria mais arriscado
    # array_row[0] is the username, array_row[1] is the h_password, array_row[2] is the salt
    conn.close ()
    if array_row is None:
        # User/pass are not correct
        t_message = "Password is not correct"
        logger.info(t_message)
        return render_template("part1.html", message_v =t_message)

    username=array_row[0]
    #mensagem de sucesso da validação do user
    t_message = "You were successfully logged with the insecure form, user " + username
    
    flash(t_message)
    logger.info(t_message)

    #estabelecimento da sessao
    session['user_id'] = username
 
    if remember == "on":
        app.config["SESSION_PERMANENT"]  = True
    else:
       app.config["SESSION_PERMANENT"] = False 
  
    return render_template("approved.html",user=session['user_id'])

   

@app.route("/part1_correct", methods=['POST'])

def part1_correct():
    logger.info("---- part1_correct ----")
    logger.info(g.user)

    username = request.form['c_username']
    password = request.form['c_password']
    otp=request.form['c_otp']
    remember = request.form['c_remember']
    
    logger.info(password)
    logger.info(username)
    logger.info(otp)
    logger.info(remember)

    session.pop('username', None)
    logger.info(session)
    #sanitizacao de inputs
    rexes = (' OR ', ' AND ', '<', '>','\'','\"','--' )
    if  (any(re.search(r, username) for r in rexes)):
        # unsecure username
        t_message = "Unsecure username. Please stop trying to hack this form!"

        logger.info(t_message)
        return render_template("part1.html", message_c = t_message)
    
    #password validation is probably not needed!
    if  (any(re.search(r, password) for r in rexes)):
        # unsecure username
        t_message = "Unsecure password. Please stop trying to hack this form!"
        #flash(t_message)
        logger.info(t_message)
        return render_template("part1.html", message_c = t_message)
    username=sanitize(username,'pass')
    password=sanitize(password,'pass')
    
   
  
    # Here we catch and display any errors that occur
    try:
        conn = get_db()
        cur = conn.cursor()
    except conn.Error as e: 
        t_message = "Database error: " + e + "/n SQL: "
        logger.info(t_message)
        return render_template("part1.html")
    
    #Query the DB and fetch the salt of the user

    logger.info(("SELECT * FROM users WHERE username = '{}'").format(username)) 
    cur.execute("SELECT * FROM users WHERE username = %(username)s", {'username': username})
    try: #maior protecção quanto a erros na query
        array_row = cur.fetchone() #fetchall seria mais arriscado
    except psycopg2.Error as e:
      t_error_message = "Database error: " + e + "/n SQL: " 
    conn.close ()
 
    
    if array_row is None:
        t_message = "You have entered an invalid username or password"
        logger.info(t_message)
        return render_template("part1.html", message_c=t_message)
    else:    
        check = bcrypt.checkpw(password.encode('utf-8'),array_row[1].encode('utf-8'))
        logger.info(check)
        if check:
            #mensagem de sucesso da validação do user
            t_message = "You were successfully logged with the secure form, user " + username
            logger.info(t_message)

            #OTP
            #https://lorenzobn.github.io/how-to-implement-two-factor-authentication-web-application
            otp_db=array_row[3] # otp do user
            logger.info("Going for OTP authorization")
            otp_instance = pyotp.TOTP(otp_db)
            valid = otp_instance.verify(otp)
            if valid:
                #estabelecimento da sessao
                session['user_id'] = username
                
                logger.info(remember)
                if remember == "on":
                    app.config["SESSION_PERMANENT"]   = True
                else:
                    app.config["SESSION_PERMANENT"]   = False
                t_message = "You were successfully logged with the secure form as user " + session['user_id']
                
                logger.info(t_message)
                flash(t_message)
                return render_template("approved.html", user = session['user_id'])
            else:
                t_message="Invalid code. Please try again."
                return render_template("part1.html", message_c=t_message)

        
        else:
            t_message = "You have entered an invalid username or password"
        
            logger.info(t_message)
            return render_template("part1.html", message_c=t_message)
    return render_template("part1.html")

@app.route("/auth.html", methods=['GET'])
def OTP_auth():
    
    logger.info("auth")

    if app.config["OTP_ENABLED"] == "True":
        t_message =  "OTP already created"
        return render_template("part1.html", message_c= t_message)
           
    else:
        app.config["OTP_ENABLED"] = "True"
        t_message =  "User registered. You can login" 
        flash(t_message)
        logger.info(t_message)
        return render_template("part1.html", message_c= t_message)
      
  
@app.route("/part2.html", methods=['GET'])
#@login_required
def part2():
    logger.info("---- reached part2.html ----")
    logger.info(session)

    if not g.user:
        logger.info("Tentativa de aceder sem sessão iniciada!")
        return render_template("index.html")
    else:
        try:
            conn = get_db()
            cur = conn.cursor()
            cur.execute("SELECT * FROM messages")
            comments = cur.fetchall()
            conn.close()
        except conn.Error as e: 
            t_message = "Database error: " + e + "/n SQL: "
            logger.info(t_message)
            return render_template("part2.html")
    return render_template("part2.html",comments=comments, user = session['user_id'])


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
    except conn.Error as e: 
        t_message = "Database error: " + e + "/n SQL: "
        logger.info(t_message)
        return render_template("part1.html")
    
    #escrita na BD
    sqlquery=("INSERT INTO messages (author,message) VALUES ('Vulnerable','"+mensagem+"');COMMIT;")
    logger.info(sqlquery) 
    cur.execute(sqlquery)
    #leitura de todos os elementos da bd
    cur.execute("SELECT * FROM messages")
    comments = cur.fetchall()
    conn.close ()
    return  render_template("part2.html", comments=comments, user = session['user_id'])



@app.route("/part2_correct", methods=['POST'])
def part2_correct():
    logger.info("part2_correct")
    mensagem = request.form['c_text']

    # Here we catch and display any errors that occur
    try:
        conn = get_db()
        cur = conn.cursor()
    except conn.Error as e:
        t_message = "Database error: " + e + "/n SQL: "
        logger.info(t_message)
        return render_template("part1.html")
    
    #sanitizacao
    mensagem=re.sub(r"[^a-zA-Z0-9!@?,. ]","",mensagem)
    mensagem = mensagem[:250] + ('..' if len(mensagem) > 250 else '')
    #escrita na BD
    sqlquery=('INSERT INTO messages (author,message) VALUES (%s,%s)')
    val=('Correct',mensagem)
    try: #maior protecção quanto a erros na query
        cur.execute(sqlquery,val)
        conn.commit ()
    except psycopg2.Error as e:
        t_error_message = e
    #leitura do ultimo elemento na BD

    
    sqlquery=("SELECT * FROM messages")
    try: #maior protecção quanto a erros na query
        cur.execute(sqlquery)
        comments = cur.fetchall()
        sanitize(comments,'mensagem')
    except psycopg2.Error as e:
        t_error_message = e

    logger.info(comments) 
    conn.close ()
    return  render_template("part2.html",  comments=comments, user = session['user_id'])
    

@app.route("/part3.html", methods=['GET'])
def part3():
    logger.info("---- reached part3.html ----")
    #validação da sessão
    if not g.user:
        logger.info("Tentativa de aceder sem sessão iniciada!")
        return render_template("index.html")
    logger.info(session)
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
    except conn.Error as e:
        t_message = "Database error: " + e + "/n SQL: "
        logger.info(t_message)
        return render_template("part3.html")
    
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
     
    
    #esconder o campo description
    if  sp_m=='0':
        logger.info("esconder campo description") 
        hidedescription=True
    else:
        hidedescription=False 
    
    #sp_start_day=sp_start_month=sp_start_year=sp_end_day=sp_end_month=sp_end_year='00'
    logger.info(sqlquery)  
    try:
        cur.execute(sqlquery)
        array_row = cur.fetchmany(sp_c) #limite de linhas
    except psycopg2.Error as e:
        t_error_message = e
        array_row = [None] 

  
    

    logger.info(array_row) 
    conn.close ()
    
    return  render_template("part3.html", livros = array_row, user = session['user_id'], hidedescription=hidedescription)
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
    except conn.Error as e: 
        t_message = "Database error: " + e + "/n SQL: "
        logger.info(t_message)
        return render_template("part3.html")
    
    #construcao da query
    if search_input == '': #Search For vazio, ou seja search simples
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

  
    #esconder o campo description
    if  sp_m=='0':
        logger.info("esconder campo description") 
        hidedescription=True
    else:
        hidedescription=False 

    logger.info(array_row) 
    conn.close ()

    return  render_template("part3.html", livros = array_row, user = session['user_id'], hidedescription=hidedescription)

    #return "/part3_correct"


@app.route("/demo", methods=['GET', 'POST'])
def demo():
    logger.info("\n DEMO \n") 

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
    elif type=='mensagem': output=input
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
    return db





##########################################################
## MAIN
##########################################################
if __name__ == "__main__":
    
    logging.basicConfig(filename="logs/log_file.log")
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
    
    app.run(host="0.0.0.0", debug=False, threaded=True)




