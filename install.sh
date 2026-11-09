#!/usr/bin/env bash
set -e
mkdir -p /opt/cfast
cp challenge /opt/cfast/challenge && chmod +x /opt/cfast/challenge
cp profile_fast.json /opt/cfast/ && cp -r profile_fast /opt/cfast/
cp solver_api.py /opt/cfast/
cp cfast.service /etc/systemd/system/
systemctl daemon-reload && systemctl enable --now cfast
sleep 2
curl -s localhost:8810/health && echo " — cfast live"
