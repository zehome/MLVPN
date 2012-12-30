=========================================
MLVPN - Multi-Link Virtual Public Network
=========================================

author: Laurent Coustet <ed arobase zehome.com>

Introduction
============
MLVPN a pour but de fournir un tunnel entre 2 routeurs,
en utilisant plusieurs liens, dans le but de fournir:
  * Aggr�gation du d�bit montant/descendant
  * Maintenir une latence faible
  * Redondance importante

Checkout documentation on ReadTheDocs.org: http://mlvpn.readthedocs.org/en/latest/

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

Fonctionnalit�s
===============
  * Agg�ratation de lien
  * Contr�le fin de la bande passante
  * File d'�mission "haute performance" sans limitation de d�bit (QoS)
  * Haute-Disponibilit� (supporte la perte de liens)
  * S�curit� par s�paration des privil�ges
  * Authentification du client

Fonctions non support�es
========================
MLVPN ne cherche pas a faire de la s�curit� au niveau des paquets qu'il traite.

Il n'y a **pas** de chiffrement, ni de compression,
ni de v�rification des paquets qu'il relaye.

Il conviens donc de faire attention � la mise en place de ce syst�me
en mettant en place les protections indispensables au niveau du noyau
des machines h�tes. (iptables, pf, ...)

Principe de fonctionnement
==========================
MLVPN commence par cr�er deux processus, un disposant de droits root,
et l'autre des droits d'un simple utilisateur.

Une interface tuntap est ouverte pour permettre la communication entre le noyau
et l'espace utilisateur.

Ensuite, des sockets �tablissent la connexion entre
le routeur A et le routeur B.

Aggr�gation du d�bit
--------------------
Une fois les sockets connect�es, tout parquet re�u sur l'interface tuntap
est relay�e en Round-Robin sur chacune des sockets.

Qualit� de service
------------------
Si un paquet IP dipose du champ TOS position� sur 0x10, ou qu'il sagit d'un
paquet ICMP, alors MLVPN utilise une queue particuli�re sur chaque socket
pour une �mission imm�diate sans limitation de d�bit.

La qualit� de service ne peut �tre assur�e que si la file d'attente au niveau
de l'op�rateur reste vide ou tr�s peu charg�e.
Il conviens donc d'ajuster correctement la limitation du d�bit.

Limitation de d�bit
-------------------
La limitation de d�bit est contr�l� par le fichier de configuration de MLVPN.
La limitation se fait en ajustant le temps n�cessaire entre l'envoi de deux
paquets, via un calcul savant.

Ainsi on �vite la file d'attente au niveau de l'op�rateur, ce qui permet de
garantir une latence faible.

Authentification
----------------
Ce syst�me permet de g�rer correctement les timeout. Il n'a pas pour but
d'am�liorer la s�curit� du syst�me.

Un mot de passe partag� entre les 2 parties est stock� dans le fichier de configuration.

Le client ne relaye les paquets qu'il re�oit que si la communication a �t�
authentifi� via ce mot de passe.

Le principe est (trop) simple:
  - client envoie un challenge al�atoire
  - serveur re�oit le challenge, y contatene le mot de passe
  - serveur renvoie un hash sha1 du motdepasse+challenge
  - client v�rifie que le hash correspond a ce qu'il a lui m�me calcul�


Compatiblit�
============
Linux, OpenBSD, FreeBSD (untested)

*NO* windows support.

Contributeurs au projet
=======================
Laurent Coustet, auteur et mainteneur du projet.

Philippe Pepiot, contributeur (s�paration de privil�ges, bugfixes, ...)

Ghislain L�v�que, contributeur

Fabien Dupont, bugfix!

LICENCE
=======
Voir le fichier LICENCE.

BUGS
====
Le syst�me de d�capsulation des paquets n'est pas fonctionnel sur la plateforme i386.

Documentation
=============
La documentation est �crite au format restructuredtext.
La page de manuel est aussi �crite en markdown. La conversion est r�alis�e grace a l'outil
ronn (http://rtomayko.github.com/ronn/).
