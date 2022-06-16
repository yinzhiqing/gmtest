# !/bin/sh

privfile="priv.key"
pubfile="pub.key"
privpem="priv.pem"
signfile="sm2.sign"
msgfile="msg.txt"

optname=""
ef() {
    echo $1 $2
}

opt_end() {
    echo '----------------------------- opt: ' $optname  
}

show_files() {
    echo "use file list->
    private file:  $privfile
    pubile:        $pubfile
    priv pem:      $privpem
    sign pem:      $signfile
    msg pem:       $msgfile"
    optname=$FUNCNAME
}

set_privfile() {
    read -p "input private key file($privfile): " filename 
    if [ ! $filename ];then
        filename=$privfile
    else
        privfile=$filename
    fi
    echo "use privkey file name : $filename"
}

set_pubfile() {
    read -p "input pub key file($pubfile): " filename 
    if [ ! $filename ];then
        filename=$pubfile
    else
        pubfile=$filename
    fi
    echo "use pubkey file name : $filename"
}

set_privpemfile() {
    read -p "input priv pem file($privpem): " filename 
    if [ ! $filename ];then
        filename=$privpem
    else
        privpem=$filename
    fi
    echo "use privpem file name : $filename"
}

set_msgfile() {
    read -p "input message file($msgfile): " filename 
    if [ ! $filename ];then
        filename=$msgfile
    else
        msgfile=$filename
    fi
    echo "use msg file name : $filename"
}

set_signfile() {
    read -p "input sign result file($signfile): " filename 
    if [ ! $filename ];then
        filename=$signfile
    else
        priv_pem=$filename
    fi
    echo "use signdata file name : $filename"
}

genkey() {
    set_privfile
    openssl ecparam -genkey -name SM2 -out $privfile
    optname=$FUNCNAME
}

outpub() {
    set_privfile
    set_pubfile
    openssl ec -in $privfile -pubout -out $pubfile
    optname=$FUNCNAME
}

outprivpem() {
    set_privfile
    set_privpemfile
    openssl pkcs8 -topk8 -inform PEM -in $privfile -outform pem -nocrypt -out $privpem
    optname=$FUNCNAME
}

sign() {
    set_privfile
    set_signfile
    set_msgfile
    openssl dgst -sign $privfile -sha1 -out $signfile $msgfile
    optname=$FUNCNAME
}

verify() {
    set_pubfile
    set_signfile
    set_msgfile
    openssl dgst -verify $pubfile -sha1 -signature $signfile $msgfile
    optname=$FUNCNAME
}

while ((1)) 
do
    read -p "input opt index
    q/0: exit
    1: genkey 
    2: outpub 
    3: outprivpem 
    4: sign 
    5: verify 
    6: showfiles): " idx
    case $idx in 
        'q')
            exit
            ;;
        0)
            exit
            ;;
        1)
           genkey 
            ;;
        2)
            outpub
            ;;
        3)
            outprivpem
            ;;
        4)
            sign
            ;;
        5)
            verify
            ;;

        6)
            show_files
            ;;
        *)
            echo "input index='$idx'"
            ;;
    esac
    opt_end

done
