# RustyKeys
[![Build Status](https://travis-ci.org/TGRGIT/RustyKeys.svg?branch=master)](https://travis-ci.org/TGRGIT/RustyKeys)
**WIP : not for production use**

## What is RustyKeys?
RustyKeys is a GPGme based password manager written in rust


## How Secure is it 
Prabably better than keeping passwords in a text file, but not entirely secure


## Deps
1. GPG (already configured)
2. GPGme
3. Rust Compiler


## Build
1. cargo build


## Usage
1. pwm -i -l "/home/user/.pstore.asc" -r "user@domain.com"
2. pwm -l "/home/user/.pstore.asc" -r "user@domain.com" -d domain.ie -u myusername
3. pwm -l "/home/user/.pstore.asc" -r "user@domain.com" -f domain.ie
