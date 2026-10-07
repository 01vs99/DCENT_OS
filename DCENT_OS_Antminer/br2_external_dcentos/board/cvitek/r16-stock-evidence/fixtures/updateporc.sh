#!/bin/sh
# for CV183X platform update, file description:
# BOOT.bin --------> minerfs.gz ---> /dev/mmcblk0p3
# devicetree.dtb --> sig.bin    ---> /dev/mmcblk0p4
# uImage ----------> boot.emmc  ---> /dev/mmcblk0p1

pemSel='/etc/bitmain.pub'
srcFile="$1"
subtype=""

getAllType() {
    FILE=$1
    if [ -f $FILE ]; then
        type_result=$(/www/pages/cgi-bin/miner_type.cgi)
        miner_type=$(echo $type_result | jq ".miner_type")
        miner_type=$(echo $miner_type | sed 's/\"//g')
        subtype=$(echo $type_result | jq ".subtype")
        subtype=$(echo $subtype | sed 's/\"//g')
        return 0
    else
        return 44
    fi
}

chkPemFile() {
    /usr/bin/FileParser -f "$subtype" $1 /etc/bitmain.pub
    res=$?
    if [ $res -ne 0 ]; then
        /usr/bin/FileParser -f "$subtype" $1 /etc/bitmain-release.pub
        res=$?
        if [ $res -ne 0 ]; then
            echo "Check Pem Failed!"
            return $res
        fi
        echo "Using Release Public Key!"
        pemSel="/etc/bitmain-release.pub"
        return 0
    fi
    echo "Using Debug Public Key!"
    pemSel="/etc/bitmain.pub"
    return 0 
}

spliteFile() {
    rm -rf /tmp/tmpfw
    mkdir -p /tmp/tmpfw

    chkPemFile $1
    res=$?
    if [ $res -ne 0 ]; then
        echo "Check Pem Failed!"
        return $res
    fi

    /usr/bin/FileParser -s "$subtype" $1 ${pemSel}
    res=$?
    if [ $res -ne 0 ]; then
        echo "Check Bmu Failed!"
        return $res
    fi

    mv /tmp/tmpfw/BOOT.bin /tmp/tmpfw/minerfs.gz
    mv /tmp/tmpfw/BOOT.bin.sig /tmp/tmpfw/minerfs.gz.sig
    mv /tmp/tmpfw/devicetree.dtb /tmp/tmpfw/sig.bin
    mv /tmp/tmpfw/devicetree.dtb.sig /tmp/tmpfw/sig.bin.sig
    mv /tmp/tmpfw/uImage /tmp/tmpfw/boot.emmc
    mv /tmp/tmpfw/uImage.sig /tmp/tmpfw/boot.emmc.sig

    return $res
}

checkFile() {
    cd /tmp/tmpfw || exit

    if [ ! -f miner.pem ]; then
        echo "Cannot Find Miner!"
        return 1
    fi
    if [ ! -f miner.pem.sig ]; then
        echo "Cannot Find Miner Signature!"
        return 2
    fi

    openssl dgst -sha256 -verify ${pemSel} -signature miner.pem.sig miner.pem > /dev/null
    res=$?
    if [ $res -ne 0 ]; then
        echo "Check Miner Signature Failed!"
        return 3
    fi

    srcFile="minerfs.gz boot.emmc sig.bin"
    for file in ${srcFile}; do
        sigFile="${file}.sig"
        if [ -f ${file} ]; then
            if [ ! -f ${sigFile} ]; then
                echo "Cannot Find ${sigFile}!"
                return 1
            else
                openssl dgst -sha256 -verify miner.pem -signature ${sigFile} ${file} > /dev/null
                res=$?
                if [ $res -ne 0 ]; then
                    echo "Check ${file} Signature Failed!"
                    return 2
                fi
            fi
        fi
    done
}

writeToEmmc() {
    cd /tmp/tmpfw/ || exit

    if [ -f boot.emmc ]; then
        echo "write boot file to emmc"
        blkdiscard /dev/mmcblk0p1
        dd if=boot.emmc of=/dev/mmcblk0p1
    fi

    if [ -f sig.bin ]; then
        echo "write sig file to emmc"
        blkdiscard /dev/mmcblk0p4
        dd if=sig.bin of=/dev/mmcblk0p4
    fi

    if [ -f minerfs.gz ]; then
        echo "write miner fs to emmc"
        blkdiscard /dev/mmcblk0p3
        dd if=minerfs.gz of=/dev/mmcblk0p3
    fi
    
    sleep 3
    sync
    echo "----------write all update files over---------------"
}


# Split Update File
if [ -z ${srcFile} ]; then
    echo "Wrong Param"
    return 9
fi

getAllType ${srcFile}
res=$?
if [ $res -ne 0 ]; then
    echo "Get Type error! res=$res"
    return $res
fi

spliteFile ${srcFile}
res=$?
if [ $res -ne 0 ]; then
    echo "Splite Bmu Failed! res=$res"
    return $res
fi

# Check Splited Data
checkFile
res=$?
if [ $res -ne 0 ]; then
    echo "Check Data Failed! res=$res"
    return $res
fi

# Write Each Part To Emmc
writeToEmmc
res=$?
if [ $res -ne 0 ]; then
    return $res
fi
