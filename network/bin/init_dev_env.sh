export COMPOSE_PROJECT_NAME=example
export IMAGE_TAG=latest

DIR="$( which $BASH_SOURCE)"
DIR="$(dirname $DIR)"

echo '================ Stoping previous containers ================'
docker stop $(docker ps -a -q)
docker rm $(docker ps -a -q)


echo    '================ Starting the Docker Instances ================'
docker-compose -f ./../devenv/docker-compose.base.yaml up -d
