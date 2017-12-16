#! /bin/sh

#$1 application name, $2 library name, $3 log file 

function usage(){
     echo "sh run.sh app_name lib_path log_path"
     exit;
}
if [ $# -le 2 ]; then
    usage;
fi

>$3
pid=$(ps | grep $1 | cut -d " " -f 4)
echo $pid
./hijack -d -p $pid -l $2


