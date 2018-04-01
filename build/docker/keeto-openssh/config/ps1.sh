if [ "${KEETO_REAL_USER}" ]; then
    PS1="[\u~"${KEETO_REAL_USER}"@\h \W]\$ "
else
    PS1="[\u@\h \W]\$ "
fi

