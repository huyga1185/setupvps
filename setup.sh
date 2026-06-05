#!/bin/bash

set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
HELP_FILE="$SCRIPT_DIR/help.txt"
AUTHORIZED_KEYS_FILE="$SCRIPT_DIR/authorized_keys"
SSHD_CONFIG_FILE="/etc/ssh/sshd_config"
SSHD_HARDENING_FILE="/etc/ssh/sshd_config.d/99-setupvps-hardening.conf"
SSH_ROLLBACK_TIMEOUT=60
SSH_ROLLBACK_CONFIRM_GRACE=8
SSH_ROLLBACK_CONFIRM_TIMEOUT=$((SSH_ROLLBACK_TIMEOUT > SSH_ROLLBACK_CONFIRM_GRACE ? SSH_ROLLBACK_TIMEOUT - SSH_ROLLBACK_CONFIRM_GRACE : 1))
SSH_ROLLBACK_STATE_DIR="/run/setupvps"

# kiem tra quyen root
if [[ $EUID -ne 0 ]]; then
	echo "Chay bang sudo: sudo bash $0" >&2
	exit 1
fi

# Related: option 1, option 6
# Does: Update apt metadata, upgrade packages, and install base VPS packages.
update_system() {
	export DEBIAN_FRONTEND=noninteractive
    apt-get update -y && apt-get upgrade -y
    apt-get install -y ufw ca-certificates curl gnupg
    echo ">> Update + packages xong"
}

# Related: option 2, option 6
# Does: Add Docker apt repository and install Docker Engine/Compose plugin.
install_docker() {
	if command -v docker &>/dev/null; then echo ">> Docker da co"; else
        apt update -y
        apt install ca-certificates curl -y
        install -m 0755 -d /etc/apt/keyrings
        curl -fsSL https://download.docker.com/linux/ubuntu/gpg -o /etc/apt/keyrings/docker.asc
        chmod a+r /etc/apt/keyrings/docker.asc

        # Add the repository to Apt sources:
		. /etc/os-release
		docker_codename="${UBUNTU_CODENAME:-${VERSION_CODENAME:-}}"
		if [[ -z "$docker_codename" ]]; then
			echo "Khong xac dinh duoc Ubuntu codename tu /etc/os-release" >&2
			exit 1
		fi

		tee /etc/apt/sources.list.d/docker.sources >/dev/null <<EOF
Types: deb
URIs: https://download.docker.com/linux/ubuntu
Suites: $docker_codename
Components: stable
Architectures: $(dpkg --print-architecture)
Signed-By: /etc/apt/keyrings/docker.asc
EOF

        apt update -y

        apt install docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin -y
    fi
}

# Related: option 3, option 6
# Does: Configure UFW for SSH, HTTP, and HTTPS traffic.
ufw_setup() {
	ufw limit OpenSSH
	ufw allow 80/tcp
	ufw allow 443/tcp
	ufw --force enable
}

# Related: option 4, option 5
# Does: Prompt for a non-empty password twice and apply it with chpasswd.
set_user_password() {
	local username="$1"
	local password password_confirm

	while true; do
		read -rsp "Nhap password cho user $username: " password
		echo

		if [[ -z "$password" ]]; then
			echo "Password khong duoc de trong"
			continue
		fi

		if [[ "$password" == *:* ]]; then
			echo "Password khong duoc chua dau ':'"
			continue
		fi

		read -rsp "Nhap lai password: " password_confirm
		echo

		if [[ "$password" != "$password_confirm" ]]; then
			echo "Password khong khop, vui long nhap lai"
			continue
		fi

		printf '%s:%s\n' "$username" "$password" | chpasswd
		unset password password_confirm
		break
	done
}

# Related: option 5
# Does: Check /etc/shadow to confirm the user password is not empty or locked.
user_has_password() {
	local username="$1"
	local shadow_entry password_hash

	shadow_entry="$(getent shadow "$username" || true)"
	password_hash="${shadow_entry#*:}"
	password_hash="${password_hash%%:*}"

	[[ -n "$password_hash" && "$password_hash" != "!"* && "$password_hash" != "*"* ]]
}

# Related: option 4, option 5, option 8, option 9, option 10
# Does: Check whether a local passwd entry exists for a username.
user_exists() {
	local username="$1"

	getent passwd "$username" >/dev/null
}

# Related: option 10
# Does: Check whether a user belongs to a specific group.
user_in_group() {
	local username="$1"
	local group_name="$2"
	local current_group

	for current_group in $(id -nG "$username"); do
		if [[ "$current_group" == "$group_name" ]]; then
			return 0
		fi
	done

	return 1
}

# Related: option 8, option 9
# Does: Read the user's home directory from the passwd database.
get_user_home() {
	local username="$1"
	local passwd_entry home_dir

	passwd_entry="$(getent passwd "$username")"
	IFS=: read -r _ _ _ _ _ home_dir _ <<<"$passwd_entry"
	printf '%s\n' "$home_dir"
}

# Related: option 8, option 9
# Does: Reject empty authorized_keys files and malformed SSH public key lines.
validate_authorized_keys() {
	local file_path="$1"

	awk '
	function is_key_type(value) {
		return value == "ssh-rsa" ||
			value == "ssh-dss" ||
			value == "ssh-ed25519" ||
			value == "ssh-rsa-cert-v01@openssh.com" ||
			value == "ssh-dss-cert-v01@openssh.com" ||
			value == "ssh-ed25519-cert-v01@openssh.com" ||
			value == "ecdsa-sha2-nistp256" ||
			value == "ecdsa-sha2-nistp384" ||
			value == "ecdsa-sha2-nistp521" ||
			value == "ecdsa-sha2-nistp256-cert-v01@openssh.com" ||
			value == "ecdsa-sha2-nistp384-cert-v01@openssh.com" ||
			value == "ecdsa-sha2-nistp521-cert-v01@openssh.com" ||
			value == "sk-ecdsa-sha2-nistp256@openssh.com" ||
			value == "sk-ssh-ed25519@openssh.com"
	}

	function is_key_blob(value) {
		return length(value) > 20 && value ~ /^[A-Za-z0-9+\/=]+$/
	}

	{
		line = $0
		sub(/\r$/, "", line)
		gsub(/^[[:space:]]+|[[:space:]]+$/, "", line)

		if (line == "" || line ~ /^#/) {
			next
		}

		key_lines++
		field_count = split(line, fields, /[[:space:]]+/)
		valid_line = 0

		for (i = 1; i < field_count; i++) {
			if (is_key_type(fields[i]) && is_key_blob(fields[i + 1])) {
				valid_line = 1
				valid_keys++
				break
			}
		}

		if (!valid_line) {
			printf "Dong authorized_keys khong hop le: %d\n", NR > "/dev/stderr"
			invalid = 1
		}
	}

	END {
		if (key_lines == 0) {
			print "File authorized_keys rong hoac khong co key hop le" > "/dev/stderr"
			exit 1
		}

		if (invalid || valid_keys == 0) {
			exit 1
		}
	}
	' "$file_path"
}

# Related: option 4
# Does: Create a new user with home directory, bash shell, and password.
create_user() {
	local username

	read -rp "Nhap username can tao: " username
	if [[ -z "$username" ]]; then
		echo "Username khong duoc de trong" >&2
		return 1
	fi

	echo ">> Kiem tra user $username..."
	if user_exists "$username"; then
		echo "User $username da ton tai" >&2
		return 1
	fi

	useradd -m -s /bin/bash "$username"
	set_user_password "$username"
	echo ">> Da tao user $username"
}

# Related: option 5
# Does: Ensure a user exists, has a valid password, and is in the sudo group.
add_sudoer() {
	local username

	read -rp "Nhap username can cap quyen sudo: " username
	if [[ -z "$username" ]]; then
		echo "Username khong duoc de trong" >&2
		return 1
	fi

	if ! command -v sudo &>/dev/null; then
		apt-get update -y
		apt-get install -y sudo
	fi

	if ! getent group sudo >/dev/null; then
		groupadd sudo
	fi

	echo ">> Kiem tra user $username..."
	if user_exists "$username"; then
		echo ">> User $username da ton tai"
	else
		useradd -m -s /bin/bash "$username"
		set_user_password "$username"
		echo ">> Da tao user $username"
	fi

	if ! user_has_password "$username"; then
		echo ">> User $username chua co password hop le, can dat password"
		set_user_password "$username"
	fi

	usermod -aG sudo "$username"
	echo ">> Da them user $username vao group sudo"
}

# Related: option 10
# Does: Remove an existing user from the sudo group.
remove_sudoer() {
	local username

	read -rp "Nhap username can go khoi group sudo: " username
	if [[ -z "$username" ]]; then
		echo "Username khong duoc de trong" >&2
		return 1
	fi

	echo ">> Kiem tra user $username..."
	if ! user_exists "$username"; then
		echo "User $username khong ton tai" >&2
		return 1
	fi

	if ! getent group sudo >/dev/null; then
		echo "Group sudo khong ton tai" >&2
		return 1
	fi

	if ! user_in_group "$username" sudo; then
		echo ">> User $username khong nam trong group sudo"
		return 0
	fi

	if command -v gpasswd &>/dev/null; then
		gpasswd -d "$username" sudo
	elif command -v deluser &>/dev/null; then
		deluser "$username" sudo
	else
		echo "Khong tim thay gpasswd hoac deluser de go user khoi group sudo" >&2
		return 1
	fi

	echo ">> Da go user $username khoi group sudo"
}

# Related: option 8
# Does: Copy repo authorized_keys into an existing user's .ssh and remove source.
setup_authorized_keys() {
	local username home_dir ssh_dir

	if [[ ! -f "$AUTHORIZED_KEYS_FILE" ]]; then
		echo "Khong tim thay file authorized_keys tai: $AUTHORIZED_KEYS_FILE" >&2
		return 1
	fi

	if ! validate_authorized_keys "$AUTHORIZED_KEYS_FILE"; then
		echo "Tu choi cai authorized_keys vi file rong hoac sai cau truc" >&2
		return 1
	fi

	read -rp "Nhap username can cai authorized_keys: " username
	if [[ -z "$username" ]]; then
		echo "Username khong duoc de trong" >&2
		return 1
	fi

	echo ">> Kiem tra user $username..."
	if ! user_exists "$username"; then
		echo "User $username khong ton tai" >&2
		return 1
	fi

	home_dir="$(get_user_home "$username")"
	if [[ -z "$home_dir" || ! -d "$home_dir" ]]; then
		echo "Home directory cua user $username khong ton tai: $home_dir" >&2
		return 1
	fi

	ssh_dir="$home_dir/.ssh"
	mkdir -p "$ssh_dir"
	chmod 700 "$ssh_dir"

	cp "$AUTHORIZED_KEYS_FILE" "$ssh_dir/authorized_keys"
	chmod 600 "$ssh_dir/authorized_keys"
	chown -R "$username:" "$ssh_dir"
	rm -f "$AUTHORIZED_KEYS_FILE"

	echo ">> Da cai authorized_keys cho user $username"
	echo ">> Da xoa file authorized_keys trong repo"
}

# Related: option 9
# Does: Validate the current sshd configuration with sshd -t.
test_sshd_config() {
	if command -v sshd &>/dev/null; then
		sshd -t
	elif [[ -x /usr/sbin/sshd ]]; then
		/usr/sbin/sshd -t
	else
		echo "Khong tim thay lenh sshd de kiem tra config" >&2
		return 1
	fi
}

# Related: option 9
# Does: Print effective sshd config with sshd -T.
get_sshd_effective_config() {
	if command -v sshd &>/dev/null; then
		sshd -T
	elif [[ -x /usr/sbin/sshd ]]; then
		/usr/sbin/sshd -T
	else
		echo "Khong tim thay lenh sshd de doc effective config" >&2
		return 1
	fi
}

# Related: option 9
# Does: Ensure sshd_config includes drop-ins before other active directives.
ensure_sshd_dropin_include() {
	local tmp_file

	if [[ ! -f "$SSHD_CONFIG_FILE" ]]; then
		echo "Khong tim thay file sshd_config tai: $SSHD_CONFIG_FILE" >&2
		return 1
	fi

	tmp_file="$(mktemp)"
	awk '
		/^[[:space:]]*Include[[:space:]]+\/etc\/ssh\/sshd_config\.d\/\*\.conf([[:space:]]|$)/ {
			next
		}

		{
			print
		}
	' "$SSHD_CONFIG_FILE" >"$tmp_file"

	{
		echo "Include /etc/ssh/sshd_config.d/*.conf"
		cat "$tmp_file"
	} >"$SSHD_CONFIG_FILE"
	rm -f "$tmp_file"
}

# Related: option 9
# Does: Verify hardening values are active in sshd -T output.
verify_sshd_hardening_effective() {
	local effective_config

	if ! effective_config="$(get_sshd_effective_config)"; then
		return 1
	fi

	if ! printf '%s\n' "$effective_config" | grep -qi '^pubkeyauthentication yes$' ||
		! printf '%s\n' "$effective_config" | grep -qi '^passwordauthentication no$' ||
		! printf '%s\n' "$effective_config" | grep -qi '^kbdinteractiveauthentication no$' ||
		! printf '%s\n' "$effective_config" | grep -qi '^permitrootlogin no$'; then
		echo "Effective sshd config chua apply dung hardening:" >&2
		printf '%s\n' "$effective_config" |
			awk '/^(pubkeyauthentication|passwordauthentication|kbdinteractiveauthentication|permitrootlogin) /' >&2
		return 1
	fi
}

# Related: option 9
# Does: Reload the SSH service without restarting the current SSH session.
restart_ssh_service() {
	if command -v systemctl &>/dev/null; then
		if systemctl reload ssh; then
			return 0
		fi

		if systemctl reload sshd; then
			return 0
		fi
	fi

	if command -v service &>/dev/null; then
		if service ssh reload; then
			return 0
		fi

		if service sshd reload; then
			return 0
		fi
	fi

	echo "Khong reload duoc SSH service, khong restart de tranh kill session hien tai" >&2
	return 1
}

# Related: option 9
# Does: Restore the previous SSH hardening/main config and reload SSH.
rollback_ssh_hardening() {
	local hardening_backup_file="$1"
	local sshd_config_backup_file="${2:-}"

	if [[ -n "$hardening_backup_file" ]]; then
		cp -a "$hardening_backup_file" "$SSHD_HARDENING_FILE"
	else
		rm -f "$SSHD_HARDENING_FILE"
	fi

	if [[ -n "$sshd_config_backup_file" ]]; then
		cp -a "$sshd_config_backup_file" "$SSHD_CONFIG_FILE"
	fi

	if ! test_sshd_config; then
		echo "Rollback SSH config bi loi, can kiem tra thu cong" >&2
		return 1
	fi

	if ! restart_ssh_service; then
		echo "Rollback SSH config xong nhung reload SSH that bai, can kiem tra thu cong" >&2
		return 1
	fi

	echo ">> Da rollback SSH config va reload SSH"
}

# Related: option 9
# Does: Stop the pending systemd rollback and remove rollback state files.
cancel_ssh_rollback_guard() {
	local marker_file="$1"
	local guard_script="$2"
	local rollback_unit="$3"

	if [[ -n "$rollback_unit" ]] && command -v systemctl &>/dev/null; then
		systemctl stop "$rollback_unit.timer" "$rollback_unit.service" >/dev/null 2>&1 || true
		systemctl reset-failed "$rollback_unit.timer" "$rollback_unit.service" >/dev/null 2>&1 || true
	fi

	if [[ -n "$marker_file" ]]; then
		rm -f "$marker_file"
	fi

	if [[ -n "$guard_script" ]]; then
		rm -f "$guard_script"
	fi
}

# Related: option 9
# Does: Create a systemd transient timer that rolls back SSH config after timeout.
start_ssh_rollback_guard() {
	local hardening_backup_file="$1"
	local sshd_config_backup_file="$2"
	local marker_file="$3"
	local guard_script="$4"
	local rollback_unit="$5"

	if ! command -v systemd-run &>/dev/null || ! command -v systemctl &>/dev/null; then
		rm -f "$marker_file" "$guard_script"
		echo "Khong co systemd-run/systemctl de giu rollback guard" >&2
		return 1
	fi

	install -d -m 0700 "$SSH_ROLLBACK_STATE_DIR"

	cat >"$guard_script" <<'EOF'
#!/bin/bash
set -u

hardening_backup_file="$1"
sshd_config_backup_file="$2"
marker_file="$3"
hardening_file="$4"
sshd_config_file="$5"

# Related: option 9
# Does: Systemd rollback guard validates restored SSH config.
test_sshd_config() {
	if command -v sshd >/dev/null 2>&1; then
		sshd -t
	elif [[ -x /usr/sbin/sshd ]]; then
		/usr/sbin/sshd -t
	else
		return 1
	fi
}

# Related: option 9
# Does: Systemd rollback guard reloads SSH after restoring config.
reload_ssh_service() {
	run_reload() {
		if command -v timeout >/dev/null 2>&1; then
			timeout 10 "$@"
		else
			"$@"
		fi
	}

	if command -v systemctl >/dev/null 2>&1; then
		run_reload systemctl reload ssh >/dev/null 2>&1 && return 0
		run_reload systemctl reload sshd >/dev/null 2>&1 && return 0
	fi

	if command -v service >/dev/null 2>&1; then
		run_reload service ssh reload >/dev/null 2>&1 && return 0
		run_reload service sshd reload >/dev/null 2>&1 && return 0
	fi

	return 1
}

if [[ ! -f "$marker_file" ]]; then
	rm -f "$0"
	exit 0
fi

if [[ -n "$hardening_backup_file" && -f "$hardening_backup_file" ]]; then
	cp -a "$hardening_backup_file" "$hardening_file"
else
	rm -f "$hardening_file"
fi

if [[ -n "$sshd_config_backup_file" && -f "$sshd_config_backup_file" ]]; then
	cp -a "$sshd_config_backup_file" "$sshd_config_file"
fi

if test_sshd_config; then
	reload_ssh_service
fi

rm -f "$marker_file" "$0"
exit 0
EOF

	chmod 700 "$guard_script"
	: >"$marker_file"

	if ! systemd-run \
		--quiet \
		--unit="$rollback_unit" \
		--on-active="${SSH_ROLLBACK_TIMEOUT}s" \
		--property=Type=oneshot \
		"$guard_script" "$hardening_backup_file" "$sshd_config_backup_file" "$marker_file" "$SSHD_HARDENING_FILE" "$SSHD_CONFIG_FILE"; then
		rm -f "$marker_file" "$guard_script"
		echo "Khong schedule duoc rollback guard bang systemd" >&2
		return 1
	fi

	echo ">> Systemd rollback guard da duoc bat trong $SSH_ROLLBACK_TIMEOUT giay"
}

# Related: option 9
# Does: Ask the user to verify SSH login; manual no returns to menu, timeout exits after rollback.
confirm_ssh_login_or_rollback() {
	local hardening_backup_file="$1"
	local sshd_config_backup_file="$2"
	local marker_file="$3"
	local guard_script="$4"
	local rollback_unit="$5"
	local confirm

	echo ">> Hay mo terminal moi va thu dang nhap SSH bang user/key vua kiem tra."
	echo ">> Neu dang nhap duoc, nhap y de giu config moi."
	echo ">> Neu nhap n, script se rollback SSH config roi quay lai menu."
	echo ">> Neu het $SSH_ROLLBACK_CONFIRM_TIMEOUT giay khong xac nhan, script se tu rollback SSH config roi thoat."

	if read -r -t "$SSH_ROLLBACK_CONFIRM_TIMEOUT" -p "Dang nhap SSH lai duoc? (y/n, timeout ${SSH_ROLLBACK_CONFIRM_TIMEOUT}s rollback): " confirm; then
		echo
		case "$confirm" in
			y|Y|yes|YES)
				echo ">> Xac nhan SSH login thanh cong, giu config moi"
				cancel_ssh_rollback_guard "$marker_file" "$guard_script" "$rollback_unit"
				return 0
				;;
			n|N|no|NO)
				echo ">> Ban chon rollback SSH config, sau do quay lai menu"
				if rollback_ssh_hardening "$hardening_backup_file" "$sshd_config_backup_file"; then
					cancel_ssh_rollback_guard "$marker_file" "$guard_script" "$rollback_unit"
				fi
				return 1
				;;
			*)
				echo "Lua chon khong hop le, rollback SSH config" >&2
				if rollback_ssh_hardening "$hardening_backup_file" "$sshd_config_backup_file"; then
					cancel_ssh_rollback_guard "$marker_file" "$guard_script" "$rollback_unit"
				fi
				return 1
				;;
		esac
	fi

	echo
	echo "Het $SSH_ROLLBACK_CONFIRM_TIMEOUT giay chua xac nhan, tu rollback SSH config va thoat script"
	if rollback_ssh_hardening "$hardening_backup_file" "$sshd_config_backup_file"; then
		cancel_ssh_rollback_guard "$marker_file" "$guard_script" "$rollback_unit"
	fi
	exit 1
}

# Related: option 9
# Does: Disable password/root SSH login with validation and guarded rollback.
setup_ssh_hardening() {
	local hardening_backup_file="" sshd_config_backup_file="" rollback_marker="" rollback_guard_script="" rollback_unit="" confirm username home_dir user_authorized_keys

	echo "CANH BAO: Neu ban dang login bang username/password hoac dang SSH truc tiep vao root,"
	echo "viec chay function nay se khien viec vao lai server la khong the."
	echo "CANH BAO: Sau khi chay function nay, ban co the phai dang nhap lai SSH."
	while true; do
		read -rp "Tiep tuc harden SSH? (yes/no): " confirm
		case "$confirm" in
			yes|YES|y|Y)
				break
				;;
			no|NO|n|N)
				echo "Da huy harden SSH, quay lai menu"
				return 1
				;;
			*)
				echo "Vui long nhap yes hoac no"
				;;
		esac
	done

	read -rp "Nhap username se dung SSH key de dang nhap: " username
	if [[ -z "$username" ]]; then
		echo "Username khong duoc de trong" >&2
		return 1
	fi

	echo ">> Kiem tra user $username..."
	if ! user_exists "$username"; then
		echo "User $username khong ton tai" >&2
		return 1
	fi

	home_dir="$(get_user_home "$username")"
	if [[ -z "$home_dir" || ! -d "$home_dir" ]]; then
		echo "Home directory cua user $username khong ton tai: $home_dir" >&2
		return 1
	fi

	user_authorized_keys="$home_dir/.ssh/authorized_keys"
	if [[ ! -f "$user_authorized_keys" ]]; then
		echo "Khong tim thay authorized_keys cua user $username tai: $user_authorized_keys" >&2
		return 1
	fi

	if ! validate_authorized_keys "$user_authorized_keys"; then
		echo "authorized_keys cua user $username khong hop le, khong reload SSH" >&2
		return 1
	fi

	if [[ -f "$SSHD_HARDENING_FILE" ]]; then
		hardening_backup_file="$SSHD_HARDENING_FILE.bak.$(date +%Y%m%d%H%M%S)"
		cp -a "$SSHD_HARDENING_FILE" "$hardening_backup_file"
	fi

	if [[ -f "$SSHD_CONFIG_FILE" ]]; then
		sshd_config_backup_file="$SSHD_CONFIG_FILE.bak.$(date +%Y%m%d%H%M%S)"
		cp -a "$SSHD_CONFIG_FILE" "$sshd_config_backup_file"
	fi

	install -d -m 0755 "$(dirname "$SSHD_HARDENING_FILE")"
	tee "$SSHD_HARDENING_FILE" >/dev/null <<EOF
# Managed by setupvps/setup.sh
PubkeyAuthentication yes
PasswordAuthentication no
KbdInteractiveAuthentication no
ChallengeResponseAuthentication no
PermitRootLogin no
EOF

	if ! ensure_sshd_dropin_include; then
		echo "Khong dam bao duoc Include cua sshd_config, rollback..." >&2
		rollback_ssh_hardening "$hardening_backup_file" "$sshd_config_backup_file"
		return 1
	fi

	if ! test_sshd_config; then
		echo "Config SSH khong hop le, rollback..." >&2
		rollback_ssh_hardening "$hardening_backup_file" "$sshd_config_backup_file"
		return 1
	fi

	if ! verify_sshd_hardening_effective; then
		echo "Hardening SSH chua co hieu luc trong sshd -T, rollback..." >&2
		rollback_ssh_hardening "$hardening_backup_file" "$sshd_config_backup_file"
		return 1
	fi

	install -d -m 0700 "$SSH_ROLLBACK_STATE_DIR"
	rollback_marker="$(mktemp "$SSH_ROLLBACK_STATE_DIR/ssh-rollback-marker.XXXXXX")"
	rollback_guard_script="$(mktemp "$SSH_ROLLBACK_STATE_DIR/ssh-rollback.XXXXXX")"
	rollback_unit="setupvps-ssh-rollback-$(date +%Y%m%d%H%M%S)-$$"
	if ! start_ssh_rollback_guard "$hardening_backup_file" "$sshd_config_backup_file" "$rollback_marker" "$rollback_guard_script" "$rollback_unit"; then
		echo "Khong co systemd rollback guard, rollback va huy harden SSH..." >&2
		rollback_ssh_hardening "$hardening_backup_file" "$sshd_config_backup_file"
		cancel_ssh_rollback_guard "$rollback_marker" "$rollback_guard_script" "$rollback_unit"
		return 1
	fi

	if ! restart_ssh_service; then
		echo "Reload SSH that bai, rollback..." >&2
		if rollback_ssh_hardening "$hardening_backup_file" "$sshd_config_backup_file"; then
			cancel_ssh_rollback_guard "$rollback_marker" "$rollback_guard_script" "$rollback_unit"
		fi
		return 1
	fi

	echo ">> Da tat login bang username/password"
	echo ">> Da block login vao root qua SSH"
	echo ">> SSH da reload thanh cong"

	if ! confirm_ssh_login_or_rollback "$hardening_backup_file" "$sshd_config_backup_file" "$rollback_marker" "$rollback_guard_script" "$rollback_unit"; then
		return 1
	fi

	echo ">> Giu SSH config moi, quay lai menu"
}

# Related: option 6
# Does: Run update, Docker install, and firewall setup in sequence.
setup() {
	update_system
	install_docker
	ufw_setup
}

# Related: option 7
# Does: Print the repo help.txt file.
show_help() {
	cat "$HELP_FILE"
}

# Related: menu loop
# Does: Clear the terminal screen before displaying the menu.
clear_screen() {
	printf '\033[H\033[2J'
}

# Related: menu loop
# Does: Wait for Enter after an option and then clear the screen.
pause_then_clear() {
	local ignored

	read -rp "Nhan Enter de quay lai menu..." ignored
	clear_screen
}

# Related: menu loop
# Does: Run one menu action, report result, and return to the menu.
run_option() {
	local option_name="$1"
	shift

	if "$@"; then
		echo ">> $option_name xong"
	else
		echo ">> $option_name chua hoan tat" >&2
	fi

	pause_then_clear
}

clear_screen

while true; do
	echo
	echo "Chon chuc nang:"
	echo "1) Cap nhat he thong va cai dat goi can thiet"
	echo "2) Cai dat Docker"
	echo "3) Cau hinh firewall (ufw)"
	echo "4) Tao user moi"
	echo "5) Tao/cap quyen sudo cho user"
	echo "6) Cau hinh tat ca (1-3)"
		echo "7) Help"
		echo "8) Cai authorized_keys cho user"
		echo "9) Harden SSH login"
		echo "10) Go user khoi group sudo"
		echo "0) Thoat"

		read -rp "Lua chon (0-10): " choice
		case $choice in
			1) run_option "Cap nhat he thong va cai dat goi can thiet" update_system ;;
			2) run_option "Cai dat Docker" install_docker ;;
		3) run_option "Cau hinh firewall" ufw_setup ;;
		4) run_option "Tao user moi" create_user ;;
		5) run_option "Tao/cap quyen sudo cho user" add_sudoer ;;
		6) run_option "Cau hinh co ban 1-3" setup ;;
			7) run_option "Help" show_help ;;
			8) run_option "Cai authorized_keys cho user" setup_authorized_keys ;;
			9) run_option "Harden SSH login" setup_ssh_hardening ;;
			10) run_option "Go user khoi group sudo" remove_sudoer ;;
			0) echo "Thoat..."; exit 0 ;;
		*)
			echo "Lua chon khong hop le. Vui long chon lai."
			pause_then_clear
			;;
	esac
done
