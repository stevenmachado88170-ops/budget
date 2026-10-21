#!/bin/sh
# Met l'appli à jour depuis GitHub (suit toujours origin/main, même si l'historique est réécrit).
# Le bloc { } est lu en entier avant exécution : le script peut donc se remplacer lui-même sans risque.
{
set -e
cd /opt/budget
git fetch --quiet origin
git reset --hard origin/main
chown -R budget: /opt/budget
systemctl restart budget
echo "Budget mis à jour."
exit
}
