#!/bin/bash

#----------------- Import variables
if [ -e "wtc_env.sh" ]; then
  . wtc_env.sh
fi

#----------------- Install applications
export DEBIAN_FRONTEND=noninteractive
apt update -y
add-apt-repository ppa:certbot/certbot -y
apt install -y docker.io python3 python3-pip awscli git ssl-cert jq monit software-properties-common certbot


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
mkdir -p ${CONFLUENCE_HOME}
mkdir -p /etc/mysql/connector
mkdir -p /root/.aws


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


#----------------- Get the MySQL Drivers
curl -sLOH 'Cache-Control: no-cache' 'https://dev.mysql.com/get/Downloads/Connector-J/mysql-connector-java-5.1.48.tar.gz';
tar -xvf mysql-connector-java-5.1.48.tar-bin.gz -C /etc/mysql/connector;


#----------------- Launch docker containers
docker run --network host --name proftpd --restart always -e PROFTPD_MASQUERADE_ADDRESS=$(curl -s http://169.254.169.254/latest/meta-data/public-ipv4) -v ${CONFLUENCE_HOME}:${CONFLUENCE_HOME} -td ${DOCKER_REGISTRY}/proftpd
#docker run --network host --name postfix --restart always -d ${DOCKER_REGISTRY}/postfix
docker run --name confluence --restart always \
  -p 8090:8090 -p 8091:8091 \
  -e ATL_PROXY_NAME=${ATL_PROXY_NAME} \
  -e ATL_PROXY_PORT=${ATL_PROXY_PORT} \
  -e ATL_JDBC_URL=${ATL_JDBC_URL} \
  -e ATL_JDBC_USER=${ATL_JDBC_USER} \
  -e ATL_JDBC_PASSWORD=${ATL_JDBC_PASSWORD} \
  -e ATL_DB_TYPE=${ATL_DB_TYPE} \
  -v ${CONFLUENCE_HOME}:/var/atlassian/application-data/confluence \
  -v /etc/mysql/connector/mysql-connector-java-5.1.48.jar:/opt/atlassian/confluence/WEB-INF/lib/mysql-connector-java-5.1.48.jar \
  -d atlassian/confluence-server:${CONFLUENCE_VERSION}

  #-e ATL_PROXY_NAME=${ATL_PROXY_NAME} \
  #-e ATL_PROXY_PORT=${ATL_PROXY_PORT} \
