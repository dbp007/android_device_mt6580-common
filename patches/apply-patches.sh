#!/bin/bash

PATCH=$PWD/mtk-diff
TOP=../../../.. # device/walton/vsun6580_we_m/patches

function apply() {
 echo [$1 - $2];
 (cd $TOP/$2; git apply -v $PATCH/$1);
 echo;
}

echo TOP            = $(cd $TOP; pwd);
echo Patches folder = $(cd $PATCH; pwd);
echo;

# -                  ---PATCH FILE---                      ---FOLDER---
apply external_wpa_supplicant_8/0001-Ignore-NVRAM-ERROR.patch external/wpa_supplicant_8
