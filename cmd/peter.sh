#!/bin/bash

STARTCOLOR='\[\033[0;32m\]'   
ENDCOLOR="\e[0m"
export PS1="\n\[$STARTCOLOR\]peter \w\n\$ \[$ENDCOLOR\]"
source /etc/environment
source /root/.cargo/env
alias cat='bat -pp'
