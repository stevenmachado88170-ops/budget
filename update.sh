#!/bin/sh
# Met à jour l'appli depuis GitHub puis la relance.
set -e
cd /opt/budget
git pull --ff-only
systemctl restart budget
echo "Budget mis à jour."
