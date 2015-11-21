# RustyKeys

**WIP : not for production use**

## Build Status
[![Build Status](https://travis-ci.org/TGRGIT/RustyKeys.svg?branch=master)](https://travis-ci.org/TGRGIT/RustyKeys)

## What is RustyKeys?
RustyKeys is a GPGme based password manager written in rust


## How Secure is it 
Almost entirely insecure, please do not use to store secure information currently.


## Deps
1. GPG (already configured)
2. GPGme
3. Rust Compiler


## Build
1. cargo build



## Usage
1. pwm -i -l "/home/user/.pstore.asc" -r "user@domain.com"
2. pwm -l "/home/user/.pstore.asc" -r "user@domain.com" -d domain.ie -p uiscebeatha
3. pwm -l "/home/user/.pstore.asc" -f domain.ie

## Notes
Intention is for use with pwgen and xclip, and eventually to incorporate all of these into one.