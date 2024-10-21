#!/usr/bin/env bash

CONATINER_NAME=greyhound
CONATINER_REPO=registry.gitlab.com/asset-sutd/software/wireless-deep-fuzzer/greyhound

start_container(){
	docker run -ti -d --privileged --name $CONATINER_NAME \
	--net=host \
	--sysctl net.ipv4.ip_forward=1 \
	-e USER=$USER -e PROJ_FOLDER=$(pwd) \
	-e DISPLAY=$DISPLAY \
	-v /tmp/.X11-unix:/tmp/.X11-unix \
	-v /etc/passwd:/etc/passwd \
	-v /etc/shadow:/etc/shadow \
	-v /etc/sudoers:/etc/sudoers \
	--mount type=bind,source="$(pwd)"/,target=/root $CONATINER_NAME &> /dev/null
}


if [ "$1" == "build" ]
then
	docker build -t $CONATINER_NAME:latest .
	if [ "$2" == "release" ]
	then
		echo "Saving compressed image to release/$CONATINER_NAME.tar.gz"
		mkdir -p release
		docker image save $CONATINER_NAME | gzip -9 -c > release/$CONATINER_NAME.tar.gz
		chmod a+rw release/$CONATINER_NAME.tar.gz
		echo "Image release/$CONATINER_NAME.tar.gz created!"
	fi

elif [ "$1" == "push" ]
then
	docker image tag greyhound ${CONATINER_REPO}:latest
	docker push ${CONATINER_REPO}:latest

elif [ "$1" == "greyhound" ]
then
	start_container
	docker exec -ti $CONATINER_NAME scripts/docker_change_to_user.sh sudo ./greyhound.py $2 # Compile library

elif [ "$1" == "shell" ]
then
	start_container
	docker exec -ti $CONATINER_NAME scripts/docker_change_to_user.sh # Start container with bash and mount files

elif [ "$1" == "reshell" ]
then
	docker rm --force $CONATINER_NAME &> /dev/null
	start_container
	docker exec -ti $CONATINER_NAME scripts/docker_change_to_user.sh # Start container with bash and mount files

elif [ "$1" == "load" ]
then
	echo "Loading docker image"
	docker load --input $2

elif [ "$1" == "stop" ]
then
	docker rm --force $CONATINER_NAME

elif [ "$1" == "clean" ]
then
	docker rm --force $CONATINER_NAME
	docker rmi -f $CONATINER_NAME # Remove container image
else
	echo "-------------- HELP ------------------"
	echo "---------  USER Commands -------------"
	echo "sudo ./docker greyhound <model name>      - Start greyhound model at current path"
	echo "sudo ./docker shell                       - Start docker container shell in current folder"
	echo "sudo ./docker reshell                     - Restart docker container and start shell in current folder"
	echo "sudo ./docker stop                        - Stop docker container"
	echo "sudo ./docker clean                       - Stop and remove/clean docker container and image"
	echo "sudo ./docker load <image path>           - Load $CONATINER_NAME docker image (.tar.gz)"
	echo "---------  Dev. Commands -------------"
	echo "sudo ./docker build                       - Build docker container"
	echo "sudo ./docker build release               - Build docker container and create compressed image for release"
fi
