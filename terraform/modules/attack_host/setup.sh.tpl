# uses https://github.com/redcanaryco/atomic-red-team
#!/bin/bash
set -euo pipefail
exec > /var/log/attack-host-setup.log 2>&1

export DEBIAN_FRONTEND=noninteractive
ELASTIC_HOST="${elastic_host}"
ELASTIC_PASSWORD="${elastic_password}"

apt-get update -y
apt-get install -y curl jq git unzip python3-pip awscli powershell apt-transport-https ca-certificates

# elastic agent
ELASTIC_VERSION="8.15.0"
curl -L -o /tmp/elastic-agent.tar.gz \
  "https://artifacts.elastic.co/downloads/beats/elastic-agent/elastic-agent-$ELASTIC_VERSION-linux-x86_64.tar.gz"
tar xzf /tmp/elastic-agent.tar.gz -C /opt/
mv /opt/elastic-agent-* /opt/elastic-agent

# atomic red team
pwsh -Command "
  Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
  Install-Module -Name invoke-atomicredteam -Scope CurrentUser -Force
  Install-Module -Name powershell-yaml -Scope CurrentUser -Force
  Import-Module invoke-atomicredteam
  Invoke-AtomicRedTeam -InstallPath /opt/atomic-red-team -Force
"
git clone --depth 1 https://github.com/redcanaryco/atomic-red-team.git /opt/atomic-red-team-repo 2>/dev/null || true

# attack scripts that map to our detection rules
mkdir -p /opt/attack-scripts

cat > /opt/attack-scripts/run_mapped_attacks.sh <<'SCRIPT'
#!/bin/bash
echo "running attack simulations mapped to detection rules"
echo ""

# T1078.004 - cred enumeration (maps to AWS-001)
echo "[*] T1078.004 - enumerating IAM credentials"
aws sts get-caller-identity
aws iam list-users 2>/dev/null || true

# T1098 - persistence via admin user (maps to AWS-002)
echo "[*] T1098 - creating test admin user"
TEST_USER="atomic-test-$(date +%s)"
aws iam create-user --user-name "$TEST_USER" 2>/dev/null || true
aws iam attach-user-policy --user-name "$TEST_USER" \
  --policy-arn "arn:aws:iam::aws:policy/AdministratorAccess" 2>/dev/null || true
sleep 5
aws iam detach-user-policy --user-name "$TEST_USER" \
  --policy-arn "arn:aws:iam::aws:policy/AdministratorAccess" 2>/dev/null || true
aws iam delete-user --user-name "$TEST_USER" 2>/dev/null || true
echo "  cleaned up $TEST_USER"

# T1552.005 - secrets enumeration (maps to AWS-005)
echo "[*] T1552.005 - listing secrets"
aws secretsmanager list-secrets 2>/dev/null || true

# T1087.004 - account discovery
echo "[*] T1087.004 - cloud account discovery"
aws iam list-roles --max-items 10 2>/dev/null || true

# T1580 - infra discovery
echo "[*] T1580 - infrastructure discovery"
aws ec2 describe-instances --max-items 5 2>/dev/null || true
aws ec2 describe-security-groups --max-items 5 2>/dev/null || true
aws s3 ls 2>/dev/null || true

echo ""
echo "done — check kibana security > alerts"
SCRIPT
chmod +x /opt/attack-scripts/run_mapped_attacks.sh

cat > /opt/attack-scripts/run_atomic.sh <<'SCRIPT'
#!/bin/bash
if [ -z "$1" ]; then
  echo "usage: $0 <technique-id>"
  echo "example: $0 T1078.004"
  exit 1
fi
pwsh -Command "
  Import-Module invoke-atomicredteam
  Invoke-AtomicTest $1 -PathToAtomicsFolder /opt/atomic-red-team-repo/atomics
"
SCRIPT
chmod +x /opt/attack-scripts/run_atomic.sh

# continuous sim via cron - picks 3 random API calls every 15min
cat > /opt/attack-scripts/continuous_sim.sh <<'SCRIPT'
#!/bin/bash
CMDS=("sts:get-caller-identity" "iam:list-users" "iam:list-roles" "s3:ls"
      "secretsmanager:list-secrets" "ec2:describe-instances"
      "ec2:describe-security-groups" "iam:list-access-keys"
      "cloudtrail:describe-trails")
for i in $(shuf -i 0-$((${#CMDS[@]}-1)) -n 3); do
  SVC=$(echo "${CMDS[$i]}" | cut -d: -f1)
  ACT=$(echo "${CMDS[$i]}" | cut -d: -f2)
  aws $SVC $ACT 2>/dev/null || true
  sleep $((RANDOM % 10 + 2))
done
SCRIPT
chmod +x /opt/attack-scripts/continuous_sim.sh

echo "*/15 * * * * root /opt/attack-scripts/continuous_sim.sh >> /var/log/attack-sim.log 2>&1" > /etc/cron.d/attack-sim

echo "attack host ready"
