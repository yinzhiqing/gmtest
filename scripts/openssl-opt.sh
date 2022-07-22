# !/bin/sh

privfile="priv.key"
pubfile="pub.key"
privpem="priv.pem"
signfile="sm2.sign"
msgfile="msg.txt"
#get hash method
shx="sm3"
openssl=/opt/openssl304/bin/openssl
#openssl=/usr/bin/openssl

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

set_openssl() {
    read -p "input openssl file($openssl): " filename 
    if [ ! $filename ];then
        filename=$openssl
    else
        openssl=$filename
    fi
    echo "use openssl link : $filename"
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
        signfile=$filename
    fi
    echo "use signdata file name : $filename"
}

set_shx() {
    read -p "input sha ($shx): " shxtype
    if [ ! $shxtype ];then
        shxtype=$shx
    else
        shx=$shxtype
    fi
    echo "use shx name : $shxtype"
}

genkey() {
    set_privfile
    $openssl ecparam -genkey -name SM2 -out $privfile
    optname=$FUNCNAME
}

outpub() {
    set_privfile
    set_pubfile
    $openssl ec -in $privfile -pubout -out $pubfile
    optname=$FUNCNAME
}

outprivpem() {
    set_privfile
    set_privpemfile
    $openssl pkcs8 -topk8 -inform PEM -in $privfile -outform pem -nocrypt -out $privpem
    optname=$FUNCNAME
}

sum() {
    set_shx
    set_msgfile
    $openssl dgst -$shx $msgfile
    optname=$FUNCNAME
}

sign() {
    set_shx
    set_privfile
    set_signfile
    set_msgfile
    $openssl dgst -sign $privfile -$shx -out $signfile $msgfile
    optname=$FUNCNAME
}

verify() {
    set_shx
    set_pubfile
    set_signfile
    set_msgfile
    $openssl dgst -verify $pubfile -$shx -signature $signfile $msgfile
    optname=$FUNCNAME
}

version() {
    $openssl version
    optname=$FUNCNAME
}

lnopenssl() {
    set_openssl
    optname=$FUNCNAME
}

while ((1)) 
do
    read -p "input opt index
    q/0: exit
    v: version
    l: lnopenssl
    1: genkey 
    2: outpub 
    3: outprivpem 
    4: sign 
    5: verify 
    6: sum
    7: showfiles): " idx
    case $idx in 
        'q')
            exit
            ;;
        'v')
            version
            ;;
        'l')
            lnopenssl
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
           sum 
            ;;
        7)
            show_files
            ;;
        *)
            echo "input index='$idx'"
            ;;
    esac
    opt_end

done
