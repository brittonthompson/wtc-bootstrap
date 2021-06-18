#!/bin/bash

#----------------- Import variables
if [ -e "wtc_env.sh" ]; then
  . wtc_env.sh
fi

#----------------- Install applications
export DEBIAN_FRONTEND=noninteractive
apt update -y
add-apt-repository ppa:certbot/certbot -y
apt install -y docker.io python3 python3-pip awscli git ssl-cert jq monit software-properties-common certbot unzip mysql-client


#----------------- Enable the Docker daemon
systemctl start docker
systemctl enable docker


#----------------- Upgrade the awscli
yes | pip3 install --upgrade pip
yes | pip install awscli --upgrade --user


#----------------- Set the hostname to the primary site URL
hostnamectl set-hostname $SITE_URL
sed -i "s/127.0.0.1 localhost/127.0.0.1 localhost $SITE_URL/g" /etc/hosts
sed -i "s/$HOSTNAME/$SITE_URL/g" /etc/hostname
sed -i "s/preserve_hostname: true/preserve_hostname: false/g" /etc/cloud/cloud.cfg


#----------------- Make all the required directories
mkdir -p /var/www/html
mkdir -p /var/www/html_wtc
mkdir -p /var/www/${SITE_URL}
mkdir -p /etc/apache2/sites-available
mkdir -p /etc/apache2/sites-enabled
mkdir -p /etc/nginx/conf.d
mkdir -p /root/.aws
mkdir -p /etc/php/conf.d


#----------------- Create the aws credentials file and config
{
  echo "[default]"
  echo "aws_access_key_id = ${AWS_ACCESS_KEY}"
  echo "aws_secret_access_key = ${AWS_SECRET_KEY}"
} > /root/.aws/credentials

cat > /root/.aws/config <<-'EOF'
[default]
output = json
region = us-east-1
EOF


#----------------- Authenticate to the AWS Elastic Container Registry
$(aws ecr get-login --no-include-email --region us-east-1)


#----------------- Create apache virtual host configuration files
cat > /etc/apache2/sites-available/000-default.conf <<-'EOF'
<VirtualHost *:80>
  ServerAdmin webmaster@localhost
  DocumentRoot /var/www/html_wtc
  ErrorLog /var/log/apache2/error.log
  CustomLog /var/log/apache2/access.log combined
</VirtualHost>
EOF

cat > /var/www/html_wtc/index.php <<-'EOF'
<!DOCTYPE html>
<html lang="en">
<head>
	<meta http-equiv="Content-Type" content="text/html; charset=utf-8" />
	<title></title>
</head>
<body>
  <div style="margin:10px auto; text-align: center; width:918px; clear:both; padding:8px; font-family:sans-serif; border: 1px solid #ccc; background-color: #e1e1e1">
    <?php echo gethostname(); ?>
  </div>
	<?php phpinfo(); ?>
</body>
</html>
EOF

ln -s /etc/apache2/sites-available/000-default.conf /etc/apache2/sites-enabled/000-default.conf

chown -R www-data:www-data /var/www/html_wtc
find /var/www/html_wtc -type f -exec chmod 644 {} + -o -type d -exec chmod 755 {} +

{
  echo "<VirtualHost *:80>"
  echo "  ServerName ${SITE_URL}"
  echo "  ServerAlias $(printf " %s" "${SITE_ALIASES[@]}")"
  echo "  DocumentRoot /var/www/${SITE_URL}"
  echo "  ErrorLog /var/log/apache2/${SITE_URL}.error.log"
  echo "  CustomLog /var/log/apache2/${SITE_URL}.access.log combined"
  echo
  echo "  # Check a HTTP header for our custom CloudFront header to allow only connections from CloudFront"
  echo "  <If \"%{HTTP:${WTC_HEADER}} in { '${WTC_HEADER_VALUE}' }\">"
  echo "    Require all granted"
  echo "  </If>"
  echo "  <Else>"
  echo "    Require all denied"
  echo "  </Else>"
  echo
  echo "  # Load the site if the header passes"
  echo "  <Directory /var/www/${SITE_URL}>"
  echo "    Options FollowSymLinks MultiViews"
  echo "    AllowOverride FileInfo Limit Options Indexes"
  echo "    Order allow,deny"
  echo "    allow from all"
  echo "  </Directory>"
  echo 
  echo "  # Deny access to the .git directory"
  echo "  <Directory ~ \"\.git\">"
  echo "    Order allow,deny"
  echo "    Deny from all"
  echo "  </Directory>"
  echo "</VirtualHost>"
} > /etc/apache2/sites-available/${SITE_URL}.conf

#----------------- Enable the new site
ln -s /etc/apache2/sites-available/${SITE_URL}.conf /etc/apache2/sites-enabled/${SITE_URL}.conf


#----------------- Nginx configuration files
cat > /etc/nginx/conf.d/default.conf <<-'EOF'
server {
  listen 80 default_server;
  listen [::]:80 default_server;

  server_name _;

  root /usr/share/nginx/html;

  # Add index.php to the list if you are using PHP
  index index.html index.htm index.nginx-debian.html;

  location ^~ /.well-known {
    allow all;
    root  /data/letsencrypt/;
  }

  location / {
    try_files $uri $uri/ =404;
  }
}

server {
  listen 443 default_server ssl http2;
  listen [::]:443 default_server ssl http2;

  root /usr/share/nginx/html;

  index index.html index.htm index.nginx-debian.html;

  server_name _;

  ssl_certificate /etc/ssl/certs/ssl-cert-snakeoil.pem;
  ssl_certificate_key /etc/ssl/private/ssl-cert-snakeoil.key;

  ssl_session_cache shared:SSL:50m;
  ssl_session_tickets off;
  ssl_protocols TLSv1.2;
  ssl_ciphers 'ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-SHA384:ECDHE-RSA-AES256-SHA384:ECDHE-ECDSA-AES128-SHA256:ECDHE-RSA-AES128-SHA256';
  ssl_prefer_server_ciphers on;

  location ^~ /.well-known {
    allow all;
    root  /data/letsencrypt/;
  }

  location / {
    try_files $uri $uri/ =404;
  }
}
EOF

cat > /etc/nginx/nginx.conf <<-'EOF'
user www-data;
worker_processes auto;
pid /run/nginx.pid;

events {
  worker_connections 768;
}

http {
  sendfile on;
  tcp_nopush on;
  tcp_nodelay on;
  keepalive_timeout 300;
  types_hash_max_size 2048;
  fastcgi_read_timeout 300;
  proxy_read_timeout 300;
  client_max_body_size 250M;

  include /etc/nginx/mime.types;
  default_type application/octet-stream;

  ssl_protocols TLSv1 TLSv1.1 TLSv1.2;
  ssl_prefer_server_ciphers on;

  access_log /var/log/nginx/access.log;
  error_log /var/log/nginx/error.log;

  gzip on;
  gzip_disable "msie6";

  include /etc/nginx/conf.d/*.conf;
  include /etc/nginx/sites-enabled/*;
}
EOF

{
  echo "server {"
  echo "  listen 80;"
  echo "  server_name ${SITE_URL}$(printf " %s" "${SITE_ALIASES[@]}");"
  echo "  root /var/www/${SITE_URL};"
  echo "  index index.html index.htm;"
  echo "  client_max_body_size 2048m;"
  echo ""
  echo "  #Set the VPC DNS server and disable IPv6 so the upstream endpoing is resolved for every proxy pass"
  echo "  resolver 1.1.1.1 8.8.8.8 ipv6=off;"
  echo "  set \$upstream_endpoint $PROXY_PASS;"
  echo "  #set \$upstream_endpoint 127.0.0.1:8080;"
  echo ""
  echo "  location ^~ /.well-known {"
  echo "    allow all;"
  echo "    root  /data/letsencrypt/;"
  echo "  }"
  echo ""
  echo "  location / {"
  if [ "$HTTP_REDIRECT" ]; then
    echo ""
    echo "    return 301 https://\$server_name\$request_uri;"
  fi
  echo "    proxy_pass http://\$upstream_endpoint;"
  echo "    proxy_set_header  host              \$host;"
  echo "    proxy_set_header  x-real-ip         \$remote_addr;"
  echo "    proxy_set_header  x-forwarded-for   \$proxy_add_x_forwarded_for;"
  echo "    proxy_set_header  x-forwarded-proto \$scheme;"
  echo "    proxy_pass_header Authorization;"
  if [ "$PROXY_REDIRECT" ]; then
      echo ""
      echo "      location ~ ^/\$ {"
      echo "          return 301 $PROXY_REDIRECT;"
      echo "      }"
  fi
  echo "  }"
  echo "}"
  echo ""
  if [ "$SSL_ENABLED" ]; then
      echo "server {"
      echo "  listen 443 ssl http2;"
      echo "  server_name ${SITE_URL}$(printf " %s" "${SITE_ALIASES[@]}");"
      echo "  root /var/www/${SITE_URL};"
      echo "  index index.html index.htm;"
      echo "  client_max_body_size 2048m;"
      echo ""
      echo "  #ssl_certificate /etc/letsencrypt/live/${SITE_URL}/fullchain.pem;"
      echo "  #ssl_certificate_key /etc/letsencrypt/live/${SITE_URL}/privkey.pem;"
      echo "  #ssl_certificate /etc/letsencrypt/fullchain.pem;"
      echo "  #ssl_certificate_key /etc/letsencrypt/privkey.pem;"
      echo "  ssl_certificate /etc/ssl/certs/ssl-cert-snakeoil.pem;"
      echo "  ssl_certificate_key /etc/ssl/private/ssl-cert-snakeoil.key;"
      echo "  ssl_session_cache shared:SSL:50m;"
      echo "  ssl_session_tickets off;"
      echo "  ssl_protocols TLSv1.2;"
      echo "  ssl_ciphers 'ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-SHA384:ECDHE-RSA-AES256-SHA384:ECDHE-ECDSA-AES128-SHA256:ECDHE-RSA-AES128-SHA256';"
      echo "  ssl_prefer_server_ciphers on;"
      echo ""
      echo "  #Set the VPC DNS server and disable IPv6 so the upstream endpoing is resolved for every proxy pass"
      echo "  resolver 1.1.1.1 8.8.8.8 ipv6=off;"
      echo "  set \$upstream_endpoint $PROXY_PASS;"
      echo "  #set \$upstream_endpoint 127.0.0.1:8080;"
      echo ""
      echo "  location ^~ /.well-known {"
      echo "    allow all;"
      echo "    root  /data/letsencrypt/;"
      echo "  }"
      echo ""
      echo "  location / {"
      echo "    proxy_pass https://\$upstream_endpoint;"
      echo "    #proxy_pass http://\$upstream_endpoint;"
      echo "    proxy_ssl_protocols TLSv1.2;"
      echo "    proxy_ssl_server_name on;"
      echo "    proxy_ssl_name    \$proxy_host;"
      echo "    proxy_set_header  host              \$host;"
      echo "    proxy_set_header  x-real-ip         \$remote_addr;"
      echo "    proxy_set_header  x-forwarded-for   \$proxy_add_x_forwarded_for;"
      echo "    proxy_set_header  x-forwarded-proto \$scheme;"
      echo "    proxy_pass_header Authorization;"
      if [ "$PROXY_REDIRECT" ]; then
        echo ""
        echo "      location ~ ^/\$ {"
        echo "          return 301 $PROXY_REDIRECT;"
        echo "      }"
      fi
      echo "  }"
      echo "}"
  fi
} > /etc/nginx/conf.d/${SITE_URL}.conf


#----------------- PHP adjustments
cat > /etc/php/conf.d/uploads.ini <<-'EOF'
file_uploads = On
memory_limit = 256M
upload_max_filesize = 256M
post_max_size = 256M
max_execution_time = 600
EOF

cat > /etc/php/conf.d/mail.ini <<-'EOF'
sendmail_path = "/usr/sbin/sendmail -t -i"
mail.log = /var/log/phpmail.log
EOF


#----------------- Launch docker containers
docker run --network host --name proftpd --restart always -e PROFTPD_MASQUERADE_ADDRESS=$(curl -s http://169.254.169.254/latest/meta-data/public-ipv4) -v /var/www:/var/www -td ${DOCKER_REGISTRY}/proftpd
#docker run --network host --name postfix --restart always -d ${DOCKER_REGISTRY}/postfix
docker run --name wordpress --restart always -p 8080:80 -v /var/www/html:/var/www/html -v /var/www:/var/www -v /etc/php/conf.d/uploads.ini:/usr/local/etc/php/conf.d/uploads.ini -v /etc/php/conf.d/mail.ini:/usr/local/etc/php/conf.d/mail.ini -v /etc/apache2/sites-available:/etc/apache2/sites-available -v /etc/apache2/sites-enabled:/etc/apache2/sites-enabled -v /var/log:/var/log -td ${DOCKER_REGISTRY}/wordpress:${WORDPRESS_VERSION}
docker run --network host --name nginx --restart always -v /root/certs-data:/data/letsencrypt -v /etc/letsencrypt:/etc/letsencrypt -v /etc/nginx/conf.d:/etc/nginx/conf.d -v /etc/nginx/nginx.conf:/etc/nginx/nginx.conf:ro -v /etc/ssl/certs/ssl-cert-snakeoil.pem:/etc/ssl/certs/ssl-cert-snakeoil.pem:ro -v /etc/ssl/private/ssl-cert-snakeoil.key:/etc/ssl/private/ssl-cert-snakeoil.key:ro -td nginx

#----------------- Create the certbot command scripts
{
  echo "certbot certonly --webroot -w /root/certs-data/ \\"
  echo "  --allow-subset-of-names \\"
  echo "  --keep-until-expiring \\"
  echo "  --expand \\"
  echo "  --agree-tos \\"
  echo "  --email ${ALERTS_EMAIL} \\"
  echo "  --no-eff-email \\"
  echo "  -d ${SITE_URL} \\"
  echo " $(printf " -d %s" "${SITE_ALIASES[@]}") \\"
  echo "  --dry-run"
} > /root/wtc_certbot_dryrun.sh

chmod +x /root/wtc_certbot_dryrun.sh

{
  echo "if [ ! -e /etc/letsencrypt/live/${SITE_URL} ]; then"
  echo "  certbot certonly --webroot -w /root/certs-data/ \\"
  echo "    --allow-subset-of-names \\"
  echo "    --keep-until-expiring \\"
  echo "    --expand \\"
  echo "    --agree-tos \\"
  echo "    --email ${ALERTS_EMAIL} \\"
  echo "    --no-eff-email \\"
  echo "    -d ${SITE_URL} \\"
  echo "   $(printf " -d %s" "${SITE_ALIASES[@]}")"
  echo "else"
  echo "  echo 'The /etc/letsencrypt/live/${SITE_URL} folder exists.'"
  echo "  echo 'You should use certbot renew command to keep from jacking up the Lets Encrypt directories.'"
  echo "fi"
} > /root/wtc_certbot_live.sh

chmod +x /root/wtc_certbot_live.sh

echo 'echo "0 */12 * * * certbot renew" | crontab -' > /root/wtc_certbot_schedule.sh
echo 'echo "0 */13 * * * docker container exec nginx nginx -s reload" | crontab -' > /root/wtc_certbot_schedule.sh

chmod +x /root/wtc_certbot_schedule.sh


#----------------- Certificate manager import scripts and monit

cat > /root/wtc_acm_import.sh <<-'EOF'
#!/bin/bash

echo "#== CERT IMPORT: `TZ=America/New_York date`"

#----------------- Import variables
if [ -e ~/wtc_envs.sh ]; then
  . wtc_envs.sh
  echo " -- SITE_URL=${SITE_URL}"
  echo " -- ACM_ARN=${ACM_ARN}"
  echo " -- ACM_ARN_ADD=${ACM_ARN_ADD}"
fi

echo " -- Certificate update"
if [ "$ACM_ARN" ]; then
  echo " -- Updating certificate ${ACM_ARN}"
  aws acm import-certificate \
    --certificate-arn $ACM_ARN \
    --certificate file:///etc/letsencrypt/live/${SITE_URL}/cert.pem \
    --private-key file:///etc/letsencrypt/live/${SITE_URL}/privkey.pem \
    --certificate-chain file:///etc/letsencrypt/live/${SITE_URL}/chain.pem
elif [ "$ACM_ARN_ADD" ]; then
  echo " -- Adding certificate to ACM"
  arn=`aws acm import-certificate \
    --certificate file:///etc/letsencrypt/live/${SITE_URL}/cert.pem \
    --private-key file:///etc/letsencrypt/live/${SITE_URL}/privkey.pem \
    --certificate-chain file:///etc/letsencrypt/live/${SITE_URL}/chain.pem`
    
  arn=`echo $arn | jq -r '.CertificateArn'`

  if [ "$arn" ]; then
    echo " -- New certificate arn is ${arn}"
    export ACM_ARN=${arn}
    echo "export ACM_ARN=${arn}" >> ~/.bashrc
    echo "export ACM_ARN=${arn}" > ~/wtc_envs.sh
    echo "export SITE_URL=${SITE_URL}" >> ~/wtc_envs.sh
  fi
fi

echo " -- Reloading NGINX"
docker container exec nginx nginx -s reload
EOF

chmod +x /root/wtc_acm_import.sh

{
  echo "#!/bin/bash"
  echo "SITE_URL=${SITE_URL}"
  echo "ACM_ARN=${ACM_ARN}"
  echo "ACM_ARN_ADD=${ACM_ARN_ADD}"
} > /root/wtc_envs.sh

chmod +x /root/wtc_envs.sh

{
  echo "check file certificate with path /etc/letsencrypt/live/${SITE_URL}/fullchain.pem"
  echo "    if changed checksum then exec \"/bin/bash -c /root/wtc_acm_import.sh >>/var/log/wtc_acm_import.log\""
} > /etc/monit/conf.d/certificate.monitrc

service monit restart

#----------------- Persist env
echo "export SITE_URL=${SITE_URL}" >> ~/.bashrc
echo "export SITE_ALIASES=($(echo ${SITE_ALIASES[@]}))" >> ~/.bashrc

#----------------- New site setup
if [ "$NEW_SITE" ]; then
  #Establishing a new site download and install Wordpress
  cd /var/www
  wget https://wordpress.org/latest.zip
  unzip latest.zip
  mv wordpress/* ${SITE_URL}
  rm -r wordpress latest.zip

  # Add the SSL redirect force if SSL is enabled
  if [ "$SSL_ENABLED" ]; then
    sed -i "s/\/\*\* Sets up WordPress vars and included files. \*\//\$_SERVER['HTTPS'] = 'on';\n\n\/\*\* Sets up WordPress vars and included files. \*\//g" /var/www/${SITE_URL}/wp-config-sample.php
  fi

  #Update the permissions for the copied data
  chown -R www-data:www-data /var/www/${SITE_URL}
  find /var/www/${SITE_URL} -type f -exec chmod 644 {} + -o -type d -exec chmod 755 {} +

  # Restart Apache and NGINX
  docker container exec nginx nginx -s reload
  docker container exec wordpress service apache2 reload

  # If we have an admin pass go ahead and run the database operations
  if [ -n ${DESTINATION_DBADMIN+x} ]; then 
    # Created the proftpd user
    mysql -h $DESTINATION_DBSERVER -u $DESTINATION_DBADMIN -p$DESTINATION_DBADMINPASS -e "USE proftpd; INSERT INTO \`users\` (\`id\`, \`userid\`, \`passwd\`, \`uid\`, \`gid\`, \`homedir\`, \`shell\`, \`last_accessed\`, \`login_allowed\`, \`count\`) VALUES (NULL, '${SHORTNAME}', ENCRYPT('${FTP_PASS}'), '33', '33', '/var/www/${SITE}', '/sbin/nologin', '2019-10-04 15:04:06', 'true', '0');"
    
    # Created the Wordpress database and user
    mysql -h $DESTINATION_DBSERVER -u $DESTINATION_DBADMIN -p$DESTINATION_DBADMINPASS -e "CREATE DATABASE IF NOT EXISTS ${DESTINATION_DB}; GRANT ALL ON ${DESTINATION_DB}.* TO '${DESTINATION_DB}'@'%' IDENTIFIED BY '${DESTINATION_DBPASS}'; FLUSH PRIVILEGES;"
  fi
fi
