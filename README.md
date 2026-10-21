# Budget (LXC, sans Docker)

Page web + serveur Node sans dépendance. Chaque personne a son profil (identifiant
et mot de passe) :
- ses données personnelles (revenu, fixes, variables, crédits, épargne) sont à elle ;
- l'onglet **Commun** (apports et dépenses du compte commun) est partagé entre les profils.

## 1. Pousser sur GitHub
```
git add . && git commit -m "Budget" && git push
```
(`data/` est ignoré : tes chiffres et mots de passe ne partent jamais sur GitHub.)

## 2. Installer dans un LXC Debian 12
```
apt update && apt install -y git nodejs
useradd --system --home /opt/budget budget
git clone git@github.com:TON_COMPTE/budget.git /opt/budget
chown -R budget: /opt/budget
cp /opt/budget/budget.service /etc/systemd/system/
systemctl daemon-reload && systemctl enable --now budget
```

## 3. Créer les profils
Le **premier** profil créé récupère les données déjà présentes (ancien format).
Crée donc le tien en premier :
```
runuser -u budget -- env DATA_DIR=/var/lib/budget node /opt/budget/server.js adduser User User User@exemple.fr
runuser -u budget -- env DATA_DIR=/var/lib/budget node /opt/budget/server.js adduser User User User@exemple.fr
```
L'adresse e-mail (3e argument) sert à la récupération du mot de passe. Pour l'ajouter ou la changer plus tard :
```
runuser -u budget -- env DATA_DIR=/var/lib/budget node /opt/budget/server.js setemail User User@exemple.fr
```
Le mot de passe est demandé deux fois (8 caractères minimum).
Mot de passe oublié : relance la même commande avec `passwd` à la place de `adduser`.

## 4. Caddy (HTTPS)
```
budget.exemple.fr {
    reverse_proxy IP_DU_LXC:3000
}
```
La connexion est gérée par l'appli (cookie de session 90 jours, 8 essais ratés
par 10 minutes maximum). Le HTTPS est important pour protéger les mots de passe :
n'ouvre pas le port 3000 hors de ton réseau.

## 5. Mot de passe oublié (e-mail)
Sur la page de connexion, « Mot de passe oublié ? » envoie un lien par e-mail.
- Lien valable 30 minutes, **à usage unique**, jamais stocké en clair (seule son empreinte l'est).
- Réponse identique que le profil existe ou non (on ne révèle rien), 3 e-mails par heure au maximum par profil.
- Après un changement, toutes les sessions ouvertes sont déconnectées et un e-mail de confirmation est envoyé.

Configuration (adresse SMTP de ton fournisseur, ou un compte dédié) :
```
cp /opt/budget/budget.env.example /etc/budget.env
nano /etc/budget.env          # BASE_URL, SMTP_HOST, SMTP_USER, SMTP_PASS…
chmod 600 /etc/budget.env
systemctl restart budget
```
`BASE_URL` est obligatoire : les liens sont construits avec elle, jamais avec l'adresse reçue dans la requête.
Port 465 = TLS direct, port 587 = STARTTLS (le port 25 sans chiffrement n'est pas géré).
Sans SMTP configuré, le lien est simplement écrit dans le journal (`journalctl -u budget`) pour l'administrateur.

## 6. Mises à jour
`/opt/budget/update.sh`

## Sauvegarde
Dossier `/var/lib/budget` (budget.json, users.json, secret.key), déjà couvert par une
sauvegarde vzdump du LXC. Supprimer `secret.key` déconnecte tout le monde.

## Notes
- Dernière écriture gagnante si vous modifiez la même ligne du compte commun en même temps.
- La page se resynchronise toute seule toutes les 5 s.
