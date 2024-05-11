FROM golang:1.22.3

RUN apt update
RUN apt upgrade -y
RUN apt install -y fortune neovim tree curl wget htop neofetch tmux less
RUN apt install -y build-essential
COPY environment /etc/

RUN curl https://sh.rustup.rs -sSf | bash -s -- -y
RUN echo 'source $HOME/.cargo/env' >> $HOME/.bashrc
RUN /root/.cargo/bin/cargo install bat


RUN mkdir -p /root/peter /root/paul
COPY peter.sh /root/peter/prompt
COPY paul.sh /root/paul/prompt
COPY mary.sh /usr/local/bin/disciples
RUN chmod +x /usr/local/bin/disciples

CMD [ "/bin/bash" ]
