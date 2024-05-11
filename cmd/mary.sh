#!/bin/bash

SESSION_NAME="disciples"

if tmux has-session -t $SESSION_NAME 2>/dev/null; then
    tmux attach-session -t $SESSION_NAME
else
    tmux new-session -d -s $SESSION_NAME
    tmux split-window -h
    tmux send-keys -t 0 'cd /root/peter && source prompt' C-m C-l
    tmux send-keys -t 1 'cd /root/paul && source prompt' C-m C-l
    tmux attach-session -t $SESSION_NAME
fi
