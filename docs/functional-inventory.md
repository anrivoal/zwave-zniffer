# Inventaire fonctionnel de migration : Zniffer et PC Controller

Cet inventaire est une liste de contrôle **par fonction utilisateur et service métier**. Il couvre les commandes, vues et services observables dans les dépôts C# au 30 septembre 2026. Il ne transforme pas chaque méthode interne ni chaque classe de commande Z-Wave en entrée distincte : ces éléments sont couverts par les fonctions de protocole et les tests de compatibilité ci-dessous. Une commande présente dans le code mais masquée dans l'interface est indiquée explicitement. Chaque entrée est à reprendre avec ses paramètres, états, erreurs et effets persistants, sauf décision produit ultérieure.

Références principales : [commandes Zniffer](../.repos/zw-sqa-tools/z-wave-pc-zniffer/ZWaveZniffer/Commands), [interface Zniffer](../.repos/zw-sqa-tools/z-wave-pc-zniffer/ZWaveZnifferUI/MainWindow.xaml), [commandes Controller](../.repos/zw-sqa-tools/z-wave-pc-controller/ZWaveController/Commands), [vues Controller](../.repos/zw-sqa-tools/z-wave-pc-controller/ZWaveControllerUI/Views), [bibliothèque partagée](../.repos/zw-sqa-tools/z-wave-tools-core).

## Zniffer

### Sources, sessions et capture

- [ ] Barre d'onglets de sources indépendantes, bouton `+`, popup « ouvrir ZLF/ZWLF », « appareil IP », « appareil série » ; sélection, fermeture, état et erreurs propres à chaque onglet. **Nouvelle exigence produit** : les onglets actuels sont des fenêtres de surveillance, pas des documents indépendants. [Architecture](zniffer-cross-platform-architecture.md#source-tabs-and-the-add-source-popup).
- [ ] Détection et nouveau balayage des modules Zniffer série ; choix du port, ajout manuel et affichage des informations/version de la source.
- [ ] Découverte des appareils IP/J-Link et ajout manuel d'une adresse IPv4 et d'un port ; connexion PTI sur TCP, avec gestion des erreurs et déconnexion.
- [ ] Sélection des fréquences/régions radio et de la configuration de canal Long Range disponibles sur le module ; lecture de l'état courant et application du choix.
- [ ] Sélection du port de débogage et écoute des données de diagnostic réseau lorsque la source le permet.
- [ ] Démarrage, pause, reprise/redémarrage et arrêt de capture ; annulation d'une opération en cours, conservation des captures des autres onglets.
- [ ] Gestion des générations de protocole Zniffer 3.x et 4.x, et des flux PTI ; validation de version, débit série et tramage.
- [ ] Capture UDP/J-Link prise en charge par le code existant, distincte du PTI/TCP. Déterminer son accès dans la popup IP lors de l'implémentation. [Services](../.repos/zw-sqa-tools/z-wave-pc-zniffer/ZWaveZniffer/Services).
- [ ] Capture via ligne de commande : source série, fréquence, débit, version et aide. [CLI](../.repos/zw-sqa-tools/z-wave-pc-zniffer/ZWaveZniffer/CommandLineValidationHelper.cs).

### Traces et fichiers

- [ ] Créer une trace vide ; ouvrir plusieurs fichiers ZLF/ZWLF simultanément ; lire les en-têtes, blocs de données, pièces jointes, commentaires et métadonnées sans perdre les données à l'ouverture suivante.
- [ ] Lecture paginée/indexée des grands fichiers, progression et annulation ; isolation des erreurs de fichier par onglet.
- [ ] Enregistrer une trace et ses commentaires/métadonnées dans un format compatible avec l'existant ; gérer le nom de fichier et les modifications non enregistrées.
- [ ] Enregistrer un fragment correspondant aux lignes sélectionnées ou aux lignes filtrées.
- [ ] Capture directe vers fichier et découpage automatique selon limite de taille ou durée, avec suffixe temporel. [Réglages de capture](../.repos/zw-sqa-tools/z-wave-pc-zniffer/ZWaveZnifferUI/Views/CaptureSettingsView.xaml).
- [ ] Commentaire de trace ; commentaires et pièces jointes liés aux trames lorsqu'ils existent dans le format.
- [ ] Export du graphe réseau GML : commande codée mais entrée de menu masquée dans l'interface actuelle. À conserver dans l'inventaire de parité, avec décision explicite sur son exposition. [Code](../.repos/zw-sqa-tools/z-wave-pc-zniffer/ZWaveZniffer/Commands/ExportGmlCommand.cs).

### Analyse et présentation des trames

- [ ] Décoder les trames Zniffer 3.x/4.x et PTI : horodatage, numéro de ligne, vitesse, RSSI, canal, delta, Home ID, source, destination, sauts, statut, données brutes et charge applicative.
- [ ] Décoder en-têtes Z-Wave, command classes, commandes, versions et champs via les définitions XML partagées ; recharger le XML sans redémarrer.
- [ ] Afficher la liste de trames, détails d'en-tête, détails applicatifs, octets hexadécimaux et erreurs de décodage ; choix d'orientation et affichage de toutes les versions de command class.
- [ ] Afficher la charge réseau/trames par seconde.
- [ ] Rechercher, rechercher l'occurrence suivante et aller à un numéro de ligne.
- [ ] Copier les données affichées et sélectionner toutes les lignes.
- [ ] Trier, redimensionner automatiquement et afficher/masquer les colonnes ; grille, couleurs de trames et thème sombre.
- [ ] Contrôler le défilement automatique et la sélection automatique de la dernière trame.
- [ ] Filtrer par vitesse, RSSI, source, destination, sauts, nœud, Home ID, type de données, application et hexadécimal ; modes afficher/masquer, motifs avec joker `?`, valeurs multiples séparées par `;`, filtres de colonne, activation/désactivation, remise à zéro et compteur de lignes filtrées. [Vue filtre](../.repos/zw-sqa-tools/z-wave-pc-zniffer/ZWaveZnifferUI/Views/FilterView.xaml).
- [ ] Filtrer directement le nœud ou Home ID sélectionné depuis la grille ; retirer ces filtres contextuels.
- [ ] Surligner par source, destination, paire source/destination, command class, commande et fil de générations SPAN ; retirer le surlignage.
- [ ] Ajouter et gérer les « watch » actuelles ; préciser leur place dans les nouveaux onglets de sources afin de conserver leur fonction de surveillance.
- [ ] Afficher les types de trame étendus et les informations de transport/segmentation lorsque disponibles.

### Sécurité et préférences

- [ ] Charger les clés réseau, les valider et les conserver selon le comportement existant ; transférer les clés au moteur de décodage.
- [ ] Déchiffrer les charges S0/S2 prises en charge, afficher l'état du déchiffrement et les erreurs sans exposer les clés dans les journaux. [Sécurité Zniffer](../.repos/zw-sqa-tools/z-wave-tools-core/ZnifferApplication/Security).
- [ ] Conserver les préférences de vue, de colonnes, de filtres, de capture et les réglages des sources pertinents ; informations « About »/version.

## PC Controller

### Sources, sessions et interface générale

- [ ] Barre d'onglets de contrôleurs indépendants avec bouton `+` et popup « appareil IP » ou « appareil série » uniquement ; connexion, état, commandes, journaux et fermeture par session. **Nouvelle exigence produit**. [Architecture](pc-controller-cross-platform-architecture.md#controller-connection-tabs).
- [ ] Détection et actualisation des ports série, lecture de version/capacités ; connexion et déconnexion Serial API.
- [ ] Découverte des contrôleurs TCP/J-Link et des passerelles ZIP ; ajout manuel d'adresse/port ; sélection de l'adresse IP locale lorsque nécessaire.
- [ ] Connexion ZIP avec DTLS/PSK et configuration du point de destination des messages non sollicités, primaire/secondaire. [Sources](../.repos/zw-sqa-tools/z-wave-pc-controller/ZWaveController/Services/SourcesInfoService.cs), [commandes ZIP](../.repos/zw-sqa-tools/z-wave-pc-controller/ZWaveController/Commands/Zip).
- [ ] Isolation des sessions contrôleur, de l'état réseau, des files de commandes et des opérations longues ; reconnexion, annulation et libération des ressources. [Sessions](../.repos/zw-sqa-tools/z-wave-pc-controller/ZWaveController/ControllerSessionsContainer.cs).
- [ ] Écran principal, liste et détails des nœuds, journal des événements/trames et file de commandes : état, ordre, progression, annulation et nettoyage du journal.
- [ ] Paramètres applicatifs, sources enregistrées, préférences de journal/capture, informations de version et aide.

### Réseau et nœuds

- [ ] Afficher Home ID, Node ID contrôleur, rôle, capacités Serial API, versions, nœuds connus, nœuds virtuels, types, endpoints, classes de commande et sécurité accordée.
- [ ] Inclusion normale, Network Wide Inclusion et inclusion avec réglages personnalisés ; exclusion normale et Network Wide Exclusion.
- [ ] Démarrer le learn mode, changer/transférer le contrôleur, apprendre un appareil virtuel, ajouter et supprimer un nœud virtuel.
- [ ] Tester, retirer ou remplacer un nœud défaillant ; demander la mise à jour réseau ; demander les informations et les voisins d'un nœud.
- [ ] Envoyer les informations de nœud ; configurer les informations de nœud du contrôleur, son type générique/spécifique, ses classes de commande et ses options d'appareil.
- [ ] Configurer SUC/SIS, mode réception RF et mode veille ; réinitialiser le contrôleur avec les garde-fous de l'existant.
- [ ] Afficher les informations détaillées d'un nœud, ses endpoints et ses capacités ; déclencher les interrogations nécessaires.
- [ ] Gérer le réveil des nœuds endormis, notifications Wake Up, intervalle de réveil et commandes différées.
- [ ] Envoyer NOP, Basic Get/Set, Switch All, Indicator Set et Version Get.
- [ ] Gérer les associations : groupes, noms, informations de groupe, membres, commandes annoncées, ajout et suppression de membres. [Commandes](../.repos/zw-sqa-tools/z-wave-pc-controller/ZWaveController/Commands/Basic/Association).
- [ ] Lire et écrire les paramètres Configuration, y compris formats et tailles, listes et informations/noms de paramètres.

### Commandes, sécurité et SmartStart

- [ ] Composer/envoyer des commandes Z-Wave brutes ou décodées, choisir les nœuds/endpoints, émission simple ou multiple et options de transmission ; interpréter réponses et délais.
- [ ] Gérer l'historique des envois et les groupes de charges utiles prédéfinies : créer, copier, renommer, réordonner, supprimer, charger, sauvegarder et exécuter groupe ou commande.
- [ ] Recharger les définitions XML des command classes ; prendre en charge leurs versions, paramètres et conversions binaires/texte.
- [ ] Configurer les options d'envoi : débit, sécurité, substitutions/encapsulations, options RF et règles de répétition pertinentes.
- [ ] Inclusion sécurisée S0 et S2 : clés, classes accordées, DSK/PIN, KEX, confirmation, callbacks et erreurs ; sécurité des nœuds et des échanges multicast. [Bibliothèque sécurité](../.repos/zw-sqa-tools/z-wave-tools-core/BasicApplication/Security).
- [ ] Chiffrer et déchiffrer manuellement des messages S0/S2 ; copier la clé S0 courante ; appliquer les réglages de sécurité et gérer le tableau MPAN.
- [ ] Fonctions de test sécurité : paramètres, trames et extensions S2 personnalisés, ajout/modification/suppression/remise à zéro, ainsi que vue KEX Set Confirm.
- [ ] SmartStart : lire, ajouter, modifier, supprimer et vider la liste de provisioning ; consulter un DSK individuel.
- [ ] Scanner un QR code/DSK par caméra ou saisie ; importer et exporter les DSK ; gérer métadonnées nom/emplacement, clés accordées, options Long Range/Network Wide et retrait automatique sur reset local. [Vue](../.repos/zw-sqa-tools/z-wave-pc-controller/ZWaveControllerUI/Views/SmartStartView.xaml).

### Routage, diagnostics et tests réseau

- [ ] Assigner et supprimer les routes de retour, lire et fixer les routes prioritaires, y compris routes SUC et répéteurs/vitesse.
- [ ] Afficher carte et matrice de topologie ; rafraîchir, réorganiser et conserver disposition et image de fond.
- [ ] IMA : ping, voisinage, informations de routage, version, request node info, redécouverte, power-level test, santé d'un nœud et réseau complet ; résultats et représentation graphique. [Commandes IMA](../.repos/zw-sqa-tools/z-wave-pc-controller/ZWaveController/Commands/Basic/IMA).
- [ ] ERTT : lancer/arrêter les répétitions/tests, options d'émission, compteurs, états, temps et erreurs par nœud.
- [ ] Polling : configurer nœud, type de requête, intervalle et timeout ; démarrer/arrêter ; afficher nombres de requêtes, échecs, absences et temps moyen/maximal.
- [ ] Statistiques réseau : lire/effacer compteurs, lire/effacer timers d'émission, RSSI de fond et démarrer/arrêter la détection de brouillage.
- [ ] Outil UL : surveiller types de notifications, événements et compteurs. [Vue](../.repos/zw-sqa-tools/z-wave-pc-controller/ZWaveControllerUI/Views/ULMonitorView.xaml).

### Radio, sauvegarde et firmware

- [ ] Réglages radio : région RF, puissance TX normale/mesurée, puissance TX Long Range maximale, canal LR, mode DCDC et PTI radio ; lire la valeur courante et écrire les nouvelles valeurs.
- [ ] Sauvegarder et restaurer la NVM avec sélection du fichier, progression, validation et contrôle des erreurs.
- [ ] Firmware OTA : interroger cible/version, choisir image, transférer, activer, télécharger/sauvegarder et annuler ; gérer les variantes de protocole V1 à V5 et la reprise/erreur.
- [ ] Firmware local OTW/XMODEM pour contrôleur compatible ; progression, échec et récupération.
- [ ] Capture de traces du contrôleur, journal des commandes reçues/envoyées, événements de sécurité, erreurs et avertissements ; réglages de rétention des traces. [TraceCaptureModel](../.repos/zw-sqa-tools/z-wave-pc-controller/ZWaveController/Models/TraceCaptureModel.cs).

## Socle technique partagé et critères de parité

- [ ] Ports série Windows/macOS/Linux, TCP, UDP/PTI et ZIP/DTLS selon les flux réellement utilisés ; découverte de matériel et gestion de débranchement.
- [ ] Serial API : tramage, accusés, retransmissions, timeouts, commandes simultanées, ordre de file et annulation.
- [ ] Moteur Z-Wave : versions des command classes utilisées, encapsulations, Multi Channel, Security S0/S2, Transport Service, Supervision, Long Range et événements asynchrones.
- [ ] Lecture/écriture ZLF/ZWLF avec métadonnées, pièces jointes et compatibilité des fichiers historiques ; compatibilité des fichiers NVM, firmware, configuration, DSK et préférences lorsque concernés.
- [ ] API WebSocket locale versionnée : identification de session/document sur chaque commande, réponse et événement ; authentification locale, reprise après rafraîchissement de la WebView et contrôle de flux des grandes traces.
- [ ] Tests de parité par fonction : même entrée et même matériel/fichier, résultat équivalent à l'application C#, y compris refus, annulation, progression, reconnexion et cas d'erreur. Les tests d'intégration C# existants servent de base pour Controller. [Tests](../.repos/zw-sqa-tools/z-wave-pc-controller/IntegrationTests).

## Points à confirmer avant de déclarer la parité complète

- La visibilité produit de l'export GML, aujourd'hui masqué, et des fonctions de capture UDP/J-Link et de port de débogage Zniffer.
- Les formats exacts et variantes ZLF/ZWLF rencontrés dans les fichiers utilisateurs, en particulier commentaires et pièces jointes.
- Les modules/protocoles réellement utilisés dans les déploiements PC Controller, ainsi que les fonctions de certification/test à exposer dans la nouvelle interface.
- Les capacités matérielles par plateforme : certains réglages et opérations ne sont proposés que si le contrôleur ou le module les annonce.
