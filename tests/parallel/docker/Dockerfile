FROM alpine:3.16

ARG USERNAME
ARG PASSWORD


RUN apk add --update --no-cache sudo openssh python3 \
 && cd /etc/ssh && ssh-keygen -A \
 && echo "PubkeyAuthentication yes" >> /etc/ssh/sshd_config \
 && echo "PermitRootLogin no" >> /etc/ssh/sshd_config \
 && echo "PasswordAuthentication no" >> /etc/ssh/sshd_config \
 && echo '%wheel ALL=(ALL) ALL' > /etc/sudoers.d/wheel

RUN adduser -D $USERNAME -G wheel \
    && echo $USERNAME:$PASSWORD | chpasswd \
    && mkdir -p /home/$USERNAME/.ssh  \
    && chmod go-w /home/$USERNAME  \
    && chmod 700 /home/$USERNAME/.ssh \
    && chown $USERNAME -R /home/$USERNAME/.ssh

COPY --chmod=600 --chown=$USERNAME .ssh/id_ed25519.pub /home/$USERNAME/.ssh/authorized_keys

EXPOSE 22

CMD ["/usr/sbin/sshd", "-D"]