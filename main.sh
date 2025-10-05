if [[ $# -ne 3 ]]; then
	echo 'Usage: ./main.sh services_folder_path username hostname'
	exit 1
fi
services_folder_path=$1
user=$2
hostname=$3
# What? => zips the services folders to /tmp and gives you scp command to download them
# 1st argument: folder path containing the services folders
# 2nd argument: username
# 3rd argument: hostname
infra-automations/auto_zip_and_transfer.sh $services_folder_path $user $hostname
