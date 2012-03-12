=========================================
MLVPN - Multi-Link Virtual Public Network
=========================================

author: Laurent Coustet <ed arobase zehome.com>

Introduction
============
MLVPN a pour but de fournir un tunnel entre 2 routeurs,
en utilisant plusieurs liens, dans le but de fournir:
  * Aggrégation du débit montant/descendant
  * Maintenir une latence faible
  * Redondance importante

Quick install
=============

Build from source
-----------------
```sh
$ ./autogen.sh
$ ./configure
$ make
$ make install
```

Build debian package
--------------------
```sh
$ dpkg-buildpackage -us -uc -rfakeroot
OR
# dpkg-buildpackage -us -uc
```
Fonctionnalités
===============
  * Aggératation de lien
  * Contrôle fin de la bande passante
  * File d'émission "haute performance" sans limitation de débit (QoS)
  * Haute-Disponibilité (supporte la perte de liens)
  * Sécurité par séparation des privilèges
  * Authentification du client

Fonctions non supportées
========================
MLVPN ne cherche pas a faire de la sécurité au niveau des paquets qu'il traite.

Il n'y a **pas** de chiffrement, ni de compression, 
ni de vérification des paquets qu'il relaye.

Il conviens donc de faire attention à la mise en place de ce système
en mettant en place les protections indispensables au niveau du noyau
des machines hôtes. (iptables, pf, ...)

Principe de fonctionnement
==========================
MLVPN commence par créer deux processus, un disposant de droits root,
et l'autre des droits d'un simple utilisateur.

Une interface tuntap est ouverte pour permettre la communication entre le noyau
et l'espace utilisateur.

Ensuite, des sockets établissent la connexion entre 
le routeur A et le routeur B.

Aggrégation du débit
--------------------
Une fois les sockets connectées, tout parquet reçu sur l'interface tuntap
est relayée en Round-Robin sur chacune des sockets.

Qualité de service
------------------
Si un paquet IP dipose du champ TOS positioné sur 0x10, ou qu'il sagit d'un
paquet ICMP, alors MLVPN utilise une queue particulière sur chaque socket
pour une émission immédiate sans limitation de débit.

La qualité de service ne peut être assurée que si la file d'attente au niveau
de l'opérateur reste vide ou très peu chargée.
Il conviens donc d'ajuster correctement la limitation du débit.

Limitation de débit
-------------------
La limitation de débit est contrôlé par le fichier de configuration de MLVPN.
La limitation se fait en ajustant le temps nécessaire entre l'envoi de deux
paquets, via un calcul savant.

Ainsi on évite la file d'attente au niveau de l'opérateur, ce qui permet de 
garantir une latence faible.

Authentification
----------------
Ce système permet de gérer correctement les timeout. Il n'a pas pour but
d'améliorer la sécurité du système.

Un mot de passe partagé entre les 2 parties est stocké dans le fichier de configuration.

Le client ne relaye les paquets qu'il reçoit que si la communication a été
authentifié via ce mot de passe.

Le principe est (trop) simple:
  - client envoie un challenge aléatoire
  - serveur reçoit le challenge, y contatene le mot de passe
  - serveur renvoie un hash sha1 du motdepasse+challenge
  - client vérifie que le hash correspond a ce qu'il a lui même calculé


Compatiblité
============
Linux seulement.

D'autre systèmes UNIX viendrons s'ajouter a la liste, comme FreeBSD ou OpenBSD.
Le portage n'est pas une priorité pour ce projet dans l'immédiat.

Contributeurs au projet
=======================
Laurent Coustet, auteur et mainteneur du projet.

Philippe Pepiot, contributeur (séparation de privilèges, bugfixes, ...)

Ghislain Lévèque, contributeur

LICENCE
=======
Voir le fichier LICENCE.

BUGS
====
Le système de décapsulation des paquets n'est pas fonctionnel sur la plateforme i386.

Documentation
=============
La documentation est écrite au format restructuredtext.
La page de manuel est aussi écrite en markdown. La conversion est réalisée grace a l'outil
ronn (http://rtomayko.github.com/ronn/).
