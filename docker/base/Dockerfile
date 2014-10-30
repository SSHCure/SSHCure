FROM debian
# FROM debian:jessie ? 

# install deps
RUN apt-get update
RUN apt-get -y install gcc flex librrd-dev make bison autoconf nginx

ADD nfdump-1.6.12.tar.gz /tmp/
ADD nfsen-1.3.6p1.tar.gz /tmp/

# install nfdump
WORKDIR /tmp/nfdump-1.6.12
RUN ./configure --enable-nfprofile --enable-sflow
RUN make
RUN make install

# configure nginx

# install nfsen
RUN apt-get -y install libsocket6-perl php5-fpm libmailtools-perl rrdtool librrds-perl rsyslog
# Syslog is needed for NfSen or install.pl will fail
# But we need some special config stuff, http://www.projectatomic.io/blog/2014/09/running-syslog-within-a-docker-container/
RUN echo "\$OmitLocalLogging off" >> /etc/rsyslog.conf
RUN service rsyslog restart
WORKDIR /tmp/nfsen-1.3.6p1

RUN adduser netflow --no-create-home --disabled-password --disabled-login
RUN usermod -G www-data -a netflow
# replace $WWWUSER and $WWWGROUP to be "www-data" and create the new etc/nfsen.conf file
RUN sed -e 's/\(\$WWW\(USER\|GROUP\)\)\s*= "www"/\1 = "www-data"/g' etc/nfsen-dist.conf > etc/nfsen.conf

RUN mkdir -p /data/nfsen
RUN ./install.pl etc/nfsen.conf


# git clone
RUN git clone https://github.com/SSHCure/SSHCure.git /sshcure

# symlink front-end, back-end

# download MaxMind DB

# add database
#ADD SSHCure.sqlite3 /data/nfsen/plugins/SSHCure/data/
