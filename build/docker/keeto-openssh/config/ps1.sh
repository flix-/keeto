if [ "${KEETOREALUSER}" ]; then
    PS1="[\u~"${KEETOREALUSER}"@\h \W]\$ "
else
    PS1="[\u@\h \W]\$ "
fi

