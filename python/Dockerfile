#
# Authors: Nuno Antunes <nmsa@dei.uc.pt>, João Antunes <jcfa@dei.uc.pt>
#

from python:3.8-alpine

RUN apk update && apk add postgresql-dev gcc python3-dev musl-dev

run pip install flask==0.10.1 html5lib==1.0b10 Jinja2==2.10 six==1.10.0

run pip install psycopg2-binary

# add-ons

RUN apk add --update musl-dev gcc libffi-dev
RUN apk add --no-cache g++ freetype-dev jpeg-dev
RUN pip install bcrypt
RUN command pip install flask_wtf
RUN pip install regex
RUN pip install flask_login
#RUN pip install flask-sessionstore
#Run pip install flask_session_captcha
RUN pip install flask_recaptcha 
RUN pip install pyotp
RUN pip install pyqrcode

RUN pip install click
RUN pip install itsdangerous
RUN pip install qrcode[pil]


copy . /app

volume ["/app"]

workdir /app

run mkdir -p logs

EXPOSE 5000

CMD ["python", "app.py"]