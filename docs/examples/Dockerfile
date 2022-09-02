FROM alpine:3.16

RUN apk add --update --no-cache sudo openssh openssl \
 && cd /etc/ssh && ssh-keygen -A \
 && echo "PubkeyAuthentication yes" >> /etc/ssh/sshd_config \
 && mkdir -p /root/.ssh && chmod go-w /root && chmod 700 /root/.ssh

COPY --chmod=600 .ssh/id_ed25519.pub /root/.ssh/authorized_keys

EXPOSE 22

CMD ["/usr/sbin/sshd", "-D"]