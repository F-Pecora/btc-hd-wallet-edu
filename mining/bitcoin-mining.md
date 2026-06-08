# Bitcoin Mining — Fonctionnement précis et histoire

---

## Sommaire

1. [Qu'est-ce que miner ?](#1-quest-ce-que-miner-)
2. [La blockchain et les blocs](#2-la-blockchain-et-les-blocs)
3. [SHA256 — le cœur du mining](#3-sha256--le-cœur-du-mining)
4. [La preuve de travail (Proof of Work)](#4-la-preuve-de-travail-proof-of-work)
5. [La cible et la difficulté](#5-la-cible-et-la-difficulté)
6. [L'ajustement automatique de difficulté](#6-lajustement-automatique-de-difficulté)
7. [Le halving](#7-le-halving)
8. [Histoire du mining : CPU → GPU → FPGA → ASIC](#8-histoire-du-mining--cpu--gpu--fpga--asic)
9. [Les pools de mining](#9-les-pools-de-mining)
10. [Le mempool et la sélection des transactions](#10-le-mempool-et-la-sélection-des-transactions)
11. [Que se passe-t-il en 2140 ?](#11-que-se-passe-t-il-en-2140-)

---

## 1. Qu'est-ce que miner ?

Miner du Bitcoin c'est **valider des transactions et les inscrire définitivement dans la blockchain**, en échange d'une récompense en BTC.

Mais pourquoi appelle-t-on ça "miner" ? Par analogie avec l'extraction minière : comme l'or, le Bitcoin est rare, difficile à extraire, et l'effort fourni est réel et coûteux. La difficulté est calibrée pour que de nouveaux BTC apparaissent à un rythme contrôlé et prévisible — exactement comme un gisement d'or qui s'épuise progressivement.

Concrètement, un mineur fait une seule chose en boucle, des milliards de fois par seconde :

```
SHA256(SHA256(entête_du_bloc + nonce)) → comparer au résultat à la cible
```

Si le résultat est inférieur à la cible → bloc trouvé → récompense.
Sinon → incrémenter le nonce → recommencer.

C'est un travail purement probabiliste. Il n'y a pas de "raisonnement", pas d'intelligence — juste de la force brute computationnelle. Le premier mineur qui trouve un hash valide gagne.

---

## 2. La blockchain et les blocs

La blockchain est une **chaîne de blocs liés cryptographiquement**. Chaque bloc contient :

```
┌────────────────────────────────────────────┐
│                 ENTÊTE DU BLOC             │
│                                            │
│  version          : version du protocole   │
│  prev_block_hash  : hash du bloc précédent │
│  merkle_root      : empreinte des tx       │
│  timestamp        : horodatage Unix        │
│  bits             : cible encodée          │
│  nonce            : le nombre qu'on cherche│
└────────────────────────────────────────────┘
│                                            │
│           LISTE DES TRANSACTIONS           │
│  tx_0 : transaction coinbase (récompense)  │
│  tx_1 : Alice → Bob 0.5 BTC                │
│  tx_2 : Carol → Dave 1.2 BTC               │
│  ...  : jusqu'à ~3000 transactions         │
└────────────────────────────────────────────┘
```

Le champ `prev_block_hash` est crucial : il contient le hash du bloc précédent. Si quelqu'un modifie un ancien bloc, son hash change, ce qui invalide tous les blocs suivants. C'est ce qui rend la blockchain **immuable** — réécrire l'histoire exigerait de refaire la preuve de travail de tous les blocs suivants, plus vite que tous les autres mineurs réunis.

### Le Merkle Tree

Les transactions ne sont pas listées brutes dans l'entête — elles sont condensées en une seule empreinte de 32 bytes appelée **Merkle Root**.

```
        Merkle Root
           /    \
        H(AB)  H(CD)
        / \    / \
      H(A) H(B) H(C) H(D)
       |    |    |    |
      tx_A tx_B tx_C tx_D
```

On hash chaque transaction, puis on hash les hashs deux par deux, jusqu'à obtenir un seul hash racine. Si une seule transaction est modifiée, le Merkle Root change entièrement — et l'entête du bloc devient invalide.

---

## 3. SHA256 — le cœur du mining

SHA256 (Secure Hash Algorithm 256 bits) est la fonction de hachage utilisée par Bitcoin. Elle prend n'importe quelle entrée et produit toujours exactement **32 bytes = 256 bits** en sortie.

Ses propriétés fondamentales :

**Déterministe** — la même entrée donne toujours la même sortie.
```
SHA256("Bitcoin") = b4056df6691f8dc72e56302ddad345d65fead3ead9299609a826e2344eb63aa
```

**Effet avalanche** — un seul bit différent en entrée change ~50% des bits en sortie.
```
SHA256("Bitcoin")  = b4056df669...
SHA256("bitcoin")  = 6b88c087247aa2f07ee1c5956b8e1a9f4c7f892a70e324f1bb3d161e05ca107
```

**Irréversible** — impossible de retrouver l'entrée depuis la sortie. Aucun algorithme connu ne peut inverser SHA256.

**Résistant aux collisions** — trouver deux entrées différentes donnant le même hash est computationnellement impossible (2¹²⁸ opérations en moyenne).

Bitcoin applique SHA256 **deux fois** (SHA256d) pour se protéger contre certaines attaques théoriques sur les fonctions de hachage à longueur variable.

---

## 4. La preuve de travail (Proof of Work)

La preuve de travail (PoW) est le mécanisme qui force les mineurs à dépenser de l'énergie réelle pour valider des blocs. C'est la réponse de Satoshi au problème fondamental des systèmes distribués : **comment se mettre d'accord sans autorité centrale ?**

### Le problème des généraux byzantins

Imagine plusieurs généraux qui doivent coordonner une attaque par messages, sachant que certains messagers peuvent être traîtres et transmettre de fausses informations. Comment se mettre d'accord de manière fiable ?

Bitcoin résout ce problème en rendant le vote **coûteux physiquement**. Un mineur malhonnête qui voudrait réécrire la blockchain devrait dépenser plus d'énergie que tous les mineurs honnêtes réunis — ce qui est économiquement suicidaire.

### Le nonce

L'entête du bloc contient un champ de 32 bits appelé **nonce** (Number used ONCE). Le mineur l'incrémente de 0 à 4 294 967 295 (2³²) en cherchant un hash valide.

```
nonce = 0        → SHA256d(entête) = 9f3a... → trop grand, invalide
nonce = 1        → SHA256d(entête) = 2b7c... → trop grand, invalide
nonce = 2        → SHA256d(entête) = f1a9... → trop grand, invalide
...
nonce = 2083236893 → SHA256d(entête) = 0000000000000000... → valide ✓
```

Si les 4 milliards de valeurs de nonce sont épuisées sans trouver de hash valide (ça arrive), le mineur modifie le champ `extraNonce` dans la transaction coinbase, ce qui change le Merkle Root, ce qui change l'entête — et recommence avec un nouvel espace de 4 milliards de nonces.

---

## 5. La cible et la difficulté

La **cible** est un nombre de 256 bits. Un hash est valide si et seulement si :

```
SHA256d(entête) < cible
```

Plus la cible est petite, plus c'est difficile — il y a moins de hashs valides dans l'espace des possibles (2²⁵⁶).

En pratique la cible s'exprime par le nombre de **zéros en tête** du hash :

```
Cible haute (facile)  : 0x00ff... → hash doit commencer par 00
Cible basse (difficile): 0x000000000000... → hash doit commencer par 000000000000
```

Bloc genesis (janvier 2009) :
```
hash = 000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f
       ──────────────── 10 zéros en tête ────────────────
```

Bloc récent (2024) :
```
hash = 00000000000000000001a3b4c5d6e7f8...
       ──────────────────── 19 zéros en tête ────────────────────
```

Chaque zéro supplémentaire multiplie la difficulté par 16 (base hexadécimale). 19 zéros vs 10 zéros = 16⁹ ≈ 68 milliards de fois plus difficile.

---

## 6. L'ajustement automatique de difficulté

C'est le mécanisme le plus élégant de Bitcoin. Toutes les **2016 blocs** (environ 2 semaines si les blocs arrivent toutes les 10 minutes), le réseau recalcule automatiquement la cible.

### Le calcul

```
temps_réel    = timestamp(bloc 2016) - timestamp(bloc 1)
temps_attendu = 2016 × 10 minutes = 20 160 minutes

nouvelle_cible = ancienne_cible × (temps_réel / temps_attendu)
```

Si les 2016 blocs ont été trouvés en 1 semaine au lieu de 2 :
```
temps_réel / temps_attendu = 0.5
nouvelle_cible = ancienne_cible × 0.5  → cible divisée par 2 → difficulté × 2
```

Un garde-fou existe : la difficulté ne peut pas varier de plus d'un facteur 4 en un seul ajustement, pour éviter les oscillations trop brutales.

### Pourquoi 10 minutes ?

Satoshi a choisi 10 minutes comme compromis entre deux contraintes :

**Trop rapide (ex: 1 minute)** — les blocs se propagent sur le réseau mondial en ~1-2 secondes. Si les blocs arrivent toutes les minutes, deux mineurs trouvent souvent un bloc valide presque simultanément. Ces conflits (forks temporaires) fragilisent la sécurité du réseau.

**Trop lent (ex: 1 heure)** — les transactions mettent trop longtemps à être confirmées. Inutilisable en pratique.

10 minutes est arbitraire mais s'est avéré être un bon équilibre depuis 15 ans.

---

## 7. Le halving

Toutes les **210 000 blocs** (~4 ans), la récompense par bloc est divisée par deux. C'est inscrit dans le code source de Bitcoin depuis l'origine — personne ne peut le modifier sans consensus du réseau entier.

```
Période       Blocs           Récompense    Année approximative
──────────────────────────────────────────────────────────────
Genèse        0 → 209 999     50 BTC        2009 → 2012
Halving 1     210 000         25 BTC        2012 → 2016
Halving 2     420 000         12.5 BTC      2016 → 2020
Halving 3     630 000         6.25 BTC      2020 → 2024
Halving 4     840 000         3.125 BTC     2024 → 2028  ← maintenant
Halving 5     1 050 000       1.5625 BTC    2028 → 2032
...
~Halving 33   ~6 930 000      ~0 BTC        ~2140
```

Le supply total de Bitcoin est donc mathématiquement plafonné à **21 millions de BTC** — c'est la somme de la série géométrique :

```
210 000 × (50 + 25 + 12.5 + 6.25 + ...) = 210 000 × 100 = 21 000 000 BTC
```

### Impact du halving sur le mining

Chaque halving divise par deux les revenus des mineurs du jour au lendemain. Pour rester rentables, ils ont besoin que :
- Le prix du BTC double (compense la baisse de récompense), ou
- Le coût de l'énergie baisse suffisamment, ou
- Leur matériel devienne deux fois plus efficace.

Historiquement, le prix du BTC a toujours fini par monter significativement dans les mois suivant un halving — l'offre nouvellement émise diminue alors que la demande continue de croître.

---

## 8. Histoire du mining : CPU → GPU → FPGA → ASIC

### 2009 — CPU

Satoshi lui-même minait sur son CPU. La difficulté était tellement basse qu'un processeur ordinaire suffisait. Hal Finney, premier destinataire de BTC (10 BTC de Satoshi, 12 janvier 2009), faisait tourner le client Bitcoin sur son PC personnel.

À cette époque, miner quelques blocs par jour était possible avec n'importe quelle machine. Les 50 BTC de récompense ne valaient rien — ou plutôt, personne ne savait encore ce qu'ils valaient.

**22 mai 2010 — Bitcoin Pizza Day**

Laszlo Hanyecz paye 10 000 BTC pour deux pizzas Papa John's sur le forum BitcoinTalk. C'est la première transaction commerciale Bitcoin de l'histoire. Ces 10 000 BTC valent aujourd'hui environ un milliard de dollars.

### 2010-2011 — GPU

Un utilisateur du forum BitcoinTalk publie en juillet 2010 un client de mining utilisant le GPU via OpenCL. Les GPU sont massivement parallèles — là où un CPU a 4 à 16 cœurs, un GPU en a des milliers. Pour du SHA256 en boucle, c'est une révolution.

Un GPU de l'époque (ATI Radeon 5870) était environ **100x plus efficace** qu'un CPU pour miner. En quelques mois, miner sur CPU devient économiquement absurde.

La difficulté monte rapidement. Le réseau commence à ressembler à une course aux armements.

### 2011-2012 — FPGA

Les FPGA (Field-Programmable Gate Array) sont des circuits électroniques reconfigurables. On peut les programmer pour faire exactement et uniquement SHA256d, sans les circuits inutiles d'un GPU généraliste.

Résultat : meilleure efficacité énergétique que le GPU (plus de hash par watt), mais coût matériel élevé et programmation complexe. Étape de transition courte.

### 2013 — ASIC : la rupture définitive

Les ASIC (Application-Specific Integrated Circuit) sont des puces conçues **exclusivement** pour calculer SHA256d, et rien d'autre. Aucun circuit superflu. Efficacité maximale.

Butterfly Labs et Avalon lancent les premiers ASIC Bitcoin en 2013. L'impact est brutal :

```
CPU    : ~10 MH/s      (mégahashes par seconde)
GPU    : ~800 MH/s
FPGA   : ~1 000 MH/s
ASIC   : ~1 000 000 MH/s  dès 2013
```

En quelques mois, CPU et GPU deviennent complètement obsolètes pour le mining. La difficulté explose.

Aujourd'hui les meilleurs ASIC (Bitmain Antminer S21 Pro, 2024) atteignent **234 TH/s** (térahashes par seconde) avec une consommation de ~3500W. Un CPU moderne produit ~100 MH/s. L'ASIC est **2 340 000 fois plus rapide**.

### 2013-2014 — La Chine domine

Les grandes fermes de mining s'installent en Chine, attirées par :
- L'électricité bon marché (centrales hydrauliques du Sichuan et du Yunnan)
- La proximité des fabricants d'ASIC (Bitmain est chinois)
- La réglementation peu contraignante à l'époque

À son pic, la Chine représentait ~65% du hashrate mondial.

### 2021 — Le ban chinois

En mai-juin 2021, la Chine interdit le mining de cryptomonnaies. Le hashrate mondial s'effondre de ~55% en quelques semaines — la plus grande chute de difficulté de l'histoire de Bitcoin.

Les mineurs déplacent leurs machines : États-Unis (Texas, Wyoming), Kazakhstan, Russie, Canada. Le hashrate remonte et dépasse son niveau d'avant le ban en moins d'un an.

---

## 9. Les pools de mining

### Le problème de la variance

Avec un ASIC moderne à 100 TH/s, quelle est la probabilité de trouver un bloc seul ?

```
Hashrate réseau total (2024)  ≈ 600 000 000 TH/s
Hashrate d'un ASIC            ≈ 100 TH/s
Probabilité par bloc          ≈ 100 / 600 000 000 000 ≈ 1 sur 6 milliards
```

À 10 minutes par bloc, un ASIC solo trouverait un bloc en moyenne tous les **~114 000 ans**. Personne ne peut attendre ça.

### La solution : les pools

Une pool de mining regroupe des milliers de mineurs qui combinent leur puissance de calcul. Quand la pool trouve un bloc, la récompense est distribuée proportionnellement au travail fourni par chaque mineur.

```
Pool à 10 000 ASIC de 100 TH/s = 1 000 000 TH/s de hashrate combiné
Probabilité de trouver un bloc ≈ 1 sur 600 000
→ Un bloc toutes les ~4 jours en moyenne
→ Chaque mineur reçoit 1/10000 de la récompense toutes les 4 jours
→ Revenus réguliers et prévisibles
```

### Comment la pool mesure le travail ?

Le mineur ne peut pas prétendre avoir fait plus de travail qu'il n'en a fait. La pool lui demande de soumettre des **shares** — des hashes qui satisfont une cible plus facile que la vraie cible réseau. Statistiquement, le nombre de shares soumis est proportionnel au travail réel fourni.

```
Vraie cible réseau    : hash < 0x000000000000000000...  (très difficile)
Cible de share pool   : hash < 0x000000000001000000...  (beaucoup plus facile)

Le mineur soumet toutes ses shares à la pool.
Si une share satisfait aussi la vraie cible → bloc trouvé → tout le monde gagne.
```

### Les grandes pools en 2024

```
Foundry USA     ~30% du hashrate mondial
AntPool         ~17%
F2Pool          ~12%
ViaBTC          ~10%
Binance Pool    ~8%
...
```

La concentration des pools est une préoccupation légitime pour la décentralisation de Bitcoin. Si une entité contrôle >50% du hashrate, elle pourrait théoriquement réécrire des blocs récents (attaque 51%).

---

## 10. Le mempool et la sélection des transactions

### Le mempool

Quand tu envoies une transaction Bitcoin, elle n'est pas immédiatement dans la blockchain. Elle entre d'abord dans le **mempool** (memory pool) — une zone d'attente présente sur chaque nœud du réseau.

```
Tu envoies une tx → propagation sur le réseau → mempool de chaque nœud
                                                      ↓
                                              Mineur sélectionne
                                                      ↓
                                              Bloc miné → tx confirmée
                                                      ↓
                                              Tx retirée du mempool
```

### Comment le mineur choisit les transactions ?

Un bloc Bitcoin est limité à **~1 MB** (environ 2000-3000 transactions simples). Quand le mempool contient plus de transactions que ce qu'un bloc peut contenir, le mineur choisit les transactions qui maximisent sa récompense.

Le critère principal : **les frais par byte** (sat/vB — satoshis par virtual byte).

```
Transaction A : 500 bytes, frais = 10 000 sat → 20 sat/vB
Transaction B : 200 bytes, frais = 6 000 sat  → 30 sat/vB
Transaction C : 1000 bytes, frais = 5 000 sat → 5 sat/vB

Ordre de priorité : B → A → C
```

Le mineur remplit le bloc comme un sac à dos — il maximise les frais totaux dans la limite de 1 MB.

### Pourquoi les frais varient autant ?

```
Mempool vide    → peu de concurrence → frais bas (1-2 sat/vB suffisent)
Mempool saturé  → forte concurrence → frais élevés (50-200 sat/vB)
```

En mai 2023, lors du pic des Ordinals (NFT sur Bitcoin), les frais ont atteint 500 sat/vB. Une transaction simple coûtait ~50$.

### La transaction coinbase

La toute première transaction de chaque bloc est spéciale : la **transaction coinbase**. Elle n'a pas d'entrée (elle crée des BTC ex nihilo) et envoie la récompense (nouvelles pièces + frais des transactions du bloc) à l'adresse du mineur.

```
Récompense totale = récompense bloc + somme de tous les frais du bloc
                  = 3.125 BTC + ~0.5 BTC (variable)
                  ≈ 3.625 BTC par bloc en 2024
```

C'est dans l'extraNonce de cette transaction coinbase que le mineur modifie des données quand il a épuisé les 4 milliards de valeurs de nonce.

---

## 11. Que se passe-t-il en 2140 ?

Vers 2140, le dernier satoshi sera miné. La récompense bloc tombera à zéro. Les mineurs ne seront plus rémunérés que par les **frais de transaction**.

C'est le modèle économique long terme de Bitcoin, et il soulève une question ouverte : est-ce que les frais seuls suffiront à rémunérer suffisamment les mineurs pour sécuriser le réseau ?

Deux camps s'affrontent :

**Optimistes** — À mesure que Bitcoin devient une réserve de valeur mondiale et que Lightning Network augmente le volume de transactions, les frais on-chain deviendront suffisamment élevés pour compenser la disparition de la récompense bloc.

**Pessimistes** — Sans subvention des nouvelles pièces, le hashrate pourrait chuter, rendant le réseau plus vulnérable aux attaques 51%. Un problème à résoudre dans 116 ans, mais inscrit dans le protocole depuis le premier jour.

Satoshi était conscient de ce problème. Sa réponse, dans un email de 2010 :

> *"In a few decades when the reward gets too small, transaction fees will become the main compensation for nodes."*

Il anticipait que la valeur par transaction serait suffisamment élevée pour que même de faibles volumes de transactions génèrent des revenus suffisants pour les mineurs.

---

## Récapitulatif

```
Transaction émise
    ↓  propagation réseau
Mempool (file d'attente, triée par sat/vB)
    ↓  sélection par le mineur
Construction du bloc (entête + transactions)
    ↓  mining : SHA256d(entête + nonce) < cible ?
    ↓  NON → incrémenter nonce → recommencer
    ↓  OUI → bloc valide trouvé
Propagation du bloc sur le réseau
    ↓  vérification par tous les nœuds
Bloc ajouté à la blockchain
    ↓  récompense créditée au mineur (coinbase)
    ↓  toutes les 2016 blocs : ajustement de la cible
```

Le mining est donc à la fois :
- Un **mécanisme de consensus** (accord sur l'état de la blockchain sans autorité centrale)
- Un **mécanisme d'émission** (création contrôlée et décroissante de nouveaux BTC)
- Un **mécanisme de sécurité** (réécrire l'histoire coûte plus d'énergie qu'elle n'en rapporte)

Trois fonctions, un seul mécanisme. C'est l'insight central de Satoshi.
