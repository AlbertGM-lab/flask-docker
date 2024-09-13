FROM python:3.12-alpine3.20

# Actualizar repositorios y paquetes
RUN apk update

# Instalar dependencias necesarias para MariaDB y compilar mysqlclient
RUN apk add --no-cache mariadb mariadb-client mariadb-dev \
    python3-dev gcc libc-dev musl-dev libffi-dev pkgconfig \
    alpine-sdk mariadb-connector-c-dev

# Inicializar la base de datos de MariaDB
RUN mariadb-install-db --user=mysql --basedir=/usr --datadir=/var/lib/mysql

# Instalar dependencias de Python
RUN pip install flask bcrypt flask_login flask_mysqldb mysqlclient pdfkit mysql-connector-python

# Establecer el directorio de trabajo
WORKDIR /app

# Copiar todo el contenido de la aplicación en el contenedor
COPY . .

#Iniciar MariaDB
CMD rc-service mariadb start

# Exponer los puertos necesarios
EXPOSE 80
EXPOSE 3306

#Instalar y configurar Nginx y su Reverse-Proxy
RUN apk add nginx
COPY /nginx/flask_app /etc/nginx/sites-available/flask_app
RUN ln -s /etc/nginx/sites-available/flask_app /etc/nginx/sites-enabled
RUN rm -rf /etc/nginx/sites-available/default
CMD rc-service nginx start
CMD rc-service nginx enable
# Copiar el archivo SQL al contenedor
COPY ./init.sql /docker-entrypoint-initdb.d/

# Iniciar Flask cuando se inicie el contenedor
CMD python /app/app/app.py