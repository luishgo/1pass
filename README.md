# 1pass

[![Build Status](https://travis-ci.org/luishgo/1pass.png?branch=master)](https://travis-ci.org/luishgo/1pass)

Another command-line client for [1Password](https://agilebits.com/onepassword) written in Java

## Usage

`java -jar target/1pass-cli.jar <vault path> list | get <item title>`

## Compiling

`mvn clean package`

## Acknowledgment 

This project was only possible after reading [Dan Sosedoff post](https://sosedoff.com/2015/05/30/exploring-1password-crypto.html) and [Robert Knight Go repository](https://github.com/robertknight/1pass).

## TODO

* Class Item and ItemData as JSONElement or JSONObject
* Create and Save Item and ItemData in a Vault
* Create class Items?