#!/bin/bash
gnome-terminal --window -e "bash -c 'printf \"\033]0;TEST1\007\"; ./run_ft;bash'" \
--tab -e "bash -c 'printf \"\033]0;TEST2\007\"; ./sql_ft;bash'" \
--tab -e "bash -c 'printf \"\033]0;TEST3\007\"; ./run_ft2;bash'" \
--tab -e "bash -c 'printf \"\033]0;TEST4\007\"; ./run_ft3;bash'" \
#--tab -e "bash -c 'printf \"\033]0;BACKUP1\007\"; ./recv_b;bash'" \
#--tab -e "bash -c 'printf \"\033]0;BACKUP2\007\"; ./recv_sql2;bash'" \
#--tab -e "bash -c 'printf \"\033]0;BACKUP3\007\"; ./recv_b2;bash'" \
#--tab -e "bash -c 'printf \"\033]0;BACKUP4\007\"; ./recv_b3;bash'"
#--tab -e "bash -c 'printf \"\033]0;TEST4\007\"; ./run_ft3;bash'" \ 




















