# setupvps

Script setup VPS Ubuntu/Debian co menu tuong tac de update he thong, cai Docker,
cau hinh firewall, tao user, cai SSH key va harden SSH login.

## Yeu cau

- Chay bang root hoac sudo.
- Nen chay trong mot SSH session dang on dinh.
- Distro nen co `apt`, `systemd`, `sshd`, `ufw`.
- Neu muon harden SSH, hay cai SSH key cho user sudo truoc.

## Cach chay

```bash
sudo bash setup.sh
```

Sau khi chay xong mot option, script se dung lai cho ban doc output. Bam Enter
de clear man hinh va quay lai menu.

## Flow de xuat

1. Chay option `1` de update he thong va cai package co ban.
2. Chay option `4` de tao user moi neu can.
3. Chay option `5` de dam bao user co sudo.
4. Tao file `authorized_keys` trong folder repo nay.
5. Chay option `8` de cai SSH key cho user.
6. Mo terminal moi, thu SSH vao user do bang key.
7. Chay option `9` de tat password login va chan root login.

## Menu

```text
1) Cap nhat he thong va cai dat goi can thiet
2) Cai dat Docker
3) Cau hinh firewall (ufw)
4) Tao user moi
5) Tao/cap quyen sudo cho user
6) Cau hinh tat ca (1-3)
7) Help
8) Cai authorized_keys cho user
9) Harden SSH login
10) Go user khoi group sudo
0) Thoat
```

## authorized_keys

Option `8` doc file `authorized_keys` nam cung folder voi `setup.sh`.

Script se:

- Kiem tra file ton tai.
- Tu choi file rong hoac sai cau truc key SSH.
- Kiem tra user ton tai.
- Tao `~user/.ssh`.
- Set quyen folder `.ssh` la `700`.
- Copy file vao `~user/.ssh/authorized_keys`.
- Set quyen file `authorized_keys` la `600`.
- `chown` folder `.ssh` ve user.
- Xoa file `authorized_keys` trong repo neu cai thanh cong.

## Harden SSH

Option `9` ghi config vao:

```text
/etc/ssh/sshd_config.d/99-setupvps-hardening.conf
```

Config se:

```sshconfig
PubkeyAuthentication yes
PasswordAuthentication no
KbdInteractiveAuthentication no
ChallengeResponseAuthentication no
PermitRootLogin no
```

Truoc khi reload SSH, script se:

- Canh bao neu ban dang login bang username/password hoac SSH truc tiep root.
- Kiem tra user se dung SSH key co ton tai.
- Kiem tra `~user/.ssh/authorized_keys` ton tai va hop le.
- Chay `sshd -t`.
- Schedule rollback guard bang `systemd-run` trong 60 giay.
- Reload SSH, khong restart, de tranh cat session hien tai.

Sau khi reload, hay mo terminal moi va thu SSH lai bang user/key da kiem tra.

- Bam `y` trong 52 giay neu dang nhap lai duoc: giu config moi.
- Bam `n`: rollback config SSH roi quay lai menu.
- Het 52 giay khong xac nhan: tu rollback config SSH va thoat script.
- Neu SSH session hien tai bi mat, systemd rollback guard van tu rollback sau 60 giay.

Gioi han: neu server reboot trong cua so rollback 60 giay, transient systemd
timer va state trong `/run/setupvps` se mat. Truong hop nay hiem trong flow test
thu cong, nhung can biet.

## Go sudo

Option `10` go user khoi group `sudo`.

Script se:

- Kiem tra user ton tai.
- Kiem tra group `sudo` ton tai.
- Kiem tra user co dang nam trong group `sudo` hay khong.
- Neu co, go user khoi group bang `gpasswd -d user sudo` hoac `deluser user sudo`.

Hay can than khi go sudo cua user dang dung de quan tri server.
