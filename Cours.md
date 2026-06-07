# Bitcoin HD Wallet — Cours ultra-détaillé
### BIP39 · BIP32 · BIP84 · secp256k1 · Bech32
> Basé sur `wallet.py` — script éducatif v2  
> Chaque byte est disséqué. Chaque algo est décortiqué.

---

## Sommaire

1. [Architecture générale — le pipeline complet](#1-architecture-générale--le-pipeline-complet)
2. [Entropie — os.urandom(32)](#2-entropie--osurandom32)
3. [Checksum SHA256 + découpage BIP39 en 24 mots](#3-checksum-sha256--découpage-bip39-en-24-mots)
4. [PBKDF2 — des mots à la graine 512 bits](#4-pbkdf2--des-mots-à-la-graine-512-bits)
5. [HMAC-SHA512 — de la graine à la clé maître](#5-hmac-sha512--de-la-graine-à-la-clé-maître)
6. [Courbe elliptique secp256k1 — clé privée → clé publique](#6-courbe-elliptique-secp256k1--clé-privée--clé-publique)
7. [Dérivation BIP32 — l'arbre infini de clés](#7-dérivation-bip32--larbre-infini-de-clés)
8. [Adresse Native SegWit — hash160 + Bech32](#8-adresse-native-segwit--hash160--bech32)
9. [Récapitulatif et propriétés du système](#9-récapitulatif-et-propriétés-du-système)
10. [Annexe — bibliothèques Python utilisées](#10-annexe--bibliothèques-python-utilisées)

---

## 1. Architecture générale — le pipeline complet

Avant de zoomer sur chaque étape, il faut avoir le schéma d'ensemble en tête. Un Bitcoin HD Wallet (*Hierarchical Deterministic Wallet*) est une machine à dériver : depuis **une seule source de hasard** (32 bytes), on peut produire un **arbre infini d'adresses Bitcoin**, de façon **totalement déterministe** et **irréversible**.

```
os.urandom(32)                     → 256 bits d'entropie pure
    ↓
SHA256(entropie) → checksum 8 bits
entropie + checksum = 264 bits
264 bits ÷ 11 = 24 groupes → 24 mots BIP39
    ↓
PBKDF2-HMAC-SHA512 (2048 itérations)
    ↓
Graine 512 bits (64 bytes)
    ↓
HMAC-SHA512(key="Bitcoin seed", msg=graine)
    ├─ [0:32]  → clé privée maître
    └─ [32:64] → chain code maître
    ↓
Dérivation BIP32 : m/84'/0'/0'/0/index
    → clé privée de l'adresse
    ↓
Multiplication scalaire k × G (secp256k1)
    → clé publique compressée (33 bytes)
    ↓
SHA256 → RIPEMD160 → Bech32
    → adresse bc1q...
```

Chaque flèche est une **fonction à sens unique** : facile dans un sens, computationnellement impossible dans l'autre. C'est le fondement de la sécurité du système.

---

## 2. Entropie — `os.urandom(32)`

### 2.1 Qu'est-ce qu'un bit, un byte ?

Un **bit** est l'unité minimale d'information : il ne peut valoir que `0` ou `1`. C'est une question binaire : oui ou non, courant ou pas courant, nord ou sud.

Un **byte** (octet en français) est un groupe de **8 bits**. Avec 8 bits, on peut représenter `2⁸ = 256` valeurs différentes, de `0` (`00000000` en binaire) à `255` (`11111111`).

```
byte = 8 bits
exemple : 0b10110100 = 0xB4 = 180 décimal
           ┬┬┬┬┬┬┬┬
           │││││││└── bit 0 (poids faible) = 0 × 2⁰ = 0
           ││││││└─── bit 1               = 0 × 2¹ = 0
           │││││└──── bit 2               = 1 × 2² = 4
           ││││└───── bit 3               = 0 × 2³ = 0
           │││└────── bit 4               = 1 × 2⁴ = 16
           ││└──────── bit 5              = 1 × 2⁵ = 32
           │└───────── bit 6              = 0 × 2⁶ = 0
           └────────── bit 7 (poids fort) = 1 × 2⁷ = 128
           Total : 128 + 32 + 16 + 4 = 180 ✓
```

### 2.2 `os.urandom(32)` — ce que fait vraiment l'OS

```python
entropie = os.urandom(32)
```

Cette ligne demande au **noyau du système d'exploitation** de fournir 32 bytes cryptographiquement aléatoires. Ce n'est pas un simple `random.random()` : c'est une source d'entropie **matérielle et système**.

Sur Linux, `os.urandom()` lit dans `/dev/urandom`, alimenté par :

- les délais entre les interruptions matérielles (clavier, réseau, disque)
- les mouvements de la souris
- les variations du bruit thermique des capteurs
- le compteur du CPU (TSC, Time Stamp Counter)
- les données du HWRNG (*Hardware Random Number Generator*) si présent

Tout cela est mixé dans le **kernel entropy pool** (une structure interne du noyau) via des fonctions de hachage. Le résultat est statistiquement indistinguable de l'aléatoire pur — c'est ce qu'on appelle *cryptographiquement sûr* (CSPRNG).

### 2.3 Pourquoi 32 bytes ?

```
32 bytes × 8 = 256 bits
2²⁵⁶ combinaisons possibles
≈ 10⁷⁷
```

Le nombre d'atomes dans l'univers observable est estimé à environ `10⁸⁰`. Tomber **deux fois** sur la même valeur de 256 bits n'est pas seulement improbable — c'est physiquement hors de portée de l'humanité entière, même avec tous les ordinateurs du monde pendant des milliards d'années.

C'est pourquoi cette valeur n'a **jamais besoin d'être cachée une fois générée** de façon aléatoire : personne ne peut la deviner. C'est le secret fondateur de tout le wallet.

### 2.4 Représentations d'un même byte

Le script utilise `afficher_bytes_detail()` pour montrer les données sous plusieurs angles :

```python
def afficher_bytes_detail(label, data, bytes_par_ligne=16):
    # Hexadécimal : base 16, 2 caractères par byte
    hex_part = ' '.join(f'{b:02x}' for b in chunk)
    # Binaire : base 2, 8 caractères par byte (seulement si ≤ 8 bytes)
    print(f"byte {i}: {b:08b} = {b:3d} décimal = 0x{b:02x} hex")
```

Pour un byte valant `180` :
- Décimal : `180`
- Hexadécimal : `0xB4` (B = 11, 4 = 4 → 11×16 + 4 = 180)
- Binaire : `10110100`

Le hex est la notation de choix en cryptographie car 2 caractères hex = exactement 1 byte, ce qui rend les alignements visuellement immédiats.

---

## 3. Checksum SHA256 + découpage BIP39 en 24 mots

### 3.1 Pourquoi un checksum ?

Les 24 mots de la phrase mnémonique sont destinés à être recopiés sur papier, mémorisés, ou gravés sur acier. Les humains font des fautes. Le **checksum** permet de détecter immédiatement si l'un des 24 mots est incorrect lors d'une restauration.

Sans checksum, un wallet restauré avec une faute de frappe produirait silencieusement des **adresses différentes** — une catastrophe si on y a transféré des fonds.

### 3.2 Calcul du checksum

```python
hash_entropie = hashlib.sha256(entropie).digest()
checksum_byte = hash_entropie[0]
checksum_bits = f'{checksum_byte:08b}'
```

**SHA256** (*Secure Hash Algorithm 256*) est une fonction de hachage cryptographique :
- Entrée : n'importe quelle quantité de bytes
- Sortie : toujours **exactement 32 bytes (256 bits)**
- Propriété : changer 1 bit en entrée change ~50% des bits en sortie (effet avalanche)
- Propriété : irréversible — impossible de retrouver l'entrée depuis la sortie

On hache l'entropie avec SHA256. Du résultat (32 bytes), on prend **uniquement le premier byte**, et de ce byte, on prend les **8 premiers bits** = les 8 bits les plus significatifs.

```
entropie (256 bits) ──SHA256──→ hash (256 bits)
                                 └─ [0:8] = checksum (8 bits)
```

Pour une entropie de 256 bits, le BIP39 utilise `256 / 32 = 8` bits de checksum. La règle générale est : `CS = ENT / 32`.

### 3.3 Construction des 264 bits totaux

```python
entropie_bits = ''.join(f'{b:08b}' for b in entropie)    # 256 bits
bits_total    = entropie_bits + checksum_bits              # + 8 bits = 264 bits
```

On concatène les 256 bits d'entropie avec les 8 bits de checksum → 264 bits.

```
[entropie — 256 bits][checksum — 8 bits]
= 264 bits
= 24 × 11 bits exactement
```

### 3.4 Découpage en 24 groupes de 11 bits

```python
for i in range(0, len(bits_total) - 8, 11):
    groupe = bits_total[i:i+11]
    index  = int(groupe, 2)       # conversion binaire → décimal
    mot    = liste_mots[index]    # lookup dans la liste BIP39
```

Chaque groupe de 11 bits représente un entier entre `0` et `2047` (`2¹¹ - 1`). Cet entier est un **index** dans la liste BIP39 de 2048 mots.

Exemple :
```
groupe : 01001110110 = 310 → mot n°310 = "correct"
groupe : 00010110101 = 181 → mot n°181 = "bike"
```

La liste BIP39 anglaise comporte exactement **2048 mots**, triés alphabétiquement, choisis pour être courts, distincts à 4 lettres minimum, et non ambigus à l'oral (pas de mots qui se ressemblent trop). Elle va de `abandon` (index 0) à `zoo` (index 2047).

### 3.5 Vérification à la restauration

Lors de la restauration, on effectue l'opération inverse :
1. On convertit chaque mot en index (0–2047) → 11 bits
2. On concatène les 24 × 11 = 264 bits
3. On sépare les 256 premiers bits (entropie) et les 8 derniers (checksum fourni)
4. On recalcule SHA256(entropie)[0] → checksum attendu
5. Si checksum fourni ≠ checksum attendu → erreur de saisie détectée

```python
mnemo = Mnemonic("english")
mots  = mnemo.to_mnemonic(entropie)   # la bibliothèque fait tout ça
```

La bibliothèque `python-mnemonic` encapsule ces étapes. Le script les expose manuellement pour pédagogie.

---

## 4. PBKDF2 — des mots à la graine 512 bits

### 4.1 Pourquoi pas SHA512(mots) directement ?

C'est la question naturelle. Si on veut 512 bits depuis les mots, pourquoi ne pas juste faire `hashlib.sha512(mots.encode())`?

La réponse : **la vitesse est l'ennemie**.

SHA512 s'exécute en **nanosecondes** sur un CPU moderne. Un attaquant qui veut brute-forcer les 2048²⁴ combinaisons possibles de 24 mots peut tester des **milliards de phrases par seconde** sur un cluster de GPU. Avec une seule passe SHA512, c'est faisable.

Avec **2048 itérations** de HMAC-SHA512, chaque essai prend 2048 fois plus longtemps. La difficulté de brute force est multipliée par 2048, sans rien changer pour l'utilisateur légitime (quelques millisecondes).

### 4.2 PBKDF2 — mécanisme détaillé

PBKDF2 (*Password-Based Key Derivation Function 2*, RFC 2898) est un **algorithme d'étirement de clé**.

```python
graine = hashlib.pbkdf2_hmac(
    hash_name  = "sha512",
    password   = mots.encode("utf-8"),   # les 24 mots, encodés UTF-8
    salt       = b"mnemonic",            # + passphrase optionnelle
    iterations = 2048,
    dklen      = 64                       # 64 bytes de sortie = 512 bits
)
```

En pseudo-code, PBKDF2 fonctionne ainsi :

```
U₁ = HMAC-SHA512(password, salt || 0x00000001)
U₂ = HMAC-SHA512(password, U₁)
U₃ = HMAC-SHA512(password, U₂)
...
U₂₀₄₈ = HMAC-SHA512(password, U₂₀₄₇)

résultat = U₁ XOR U₂ XOR U₃ XOR ... XOR U₂₀₄₈
```

Chaque itération nourrit la suivante. Le XOR final combine toutes les passes. La sortie est **64 bytes = 512 bits** — la *seed*.

### 4.3 Le salt `"mnemonic"`

Le `salt` est une chaîne fixe définie par le standard BIP39 : `b"mnemonic"`.

Il sert à deux choses :
1. **Empêcher les rainbow tables** — des tables précalculées de hashes. Sans salt, un attaquant pourrait précalculer PBKDF2 pour tous les mnémoniques courants et stocker les résultats. Avec un salt, les calculs sont spécifiques à ce salt.
2. **Permettre une passphrase optionnelle** — le BIP39 prévoit que l'utilisateur peut ajouter un 25ème mot secret. Dans ce cas, le salt devient `b"mnemonic" + passphrase`. Cela crée un wallet complètement différent depuis les mêmes 24 mots.

### 4.4 L'expansion apparente de 256 à 512 bits

```
Entrée  : 256 bits d'entropie (via les 24 mots)
Sortie  : 512 bits de graine
```

On n'a pas *créé* de l'entropie — c'est impossible. La graine de 512 bits contient toujours **exactement 256 bits d'information** utile. Les 512 bits sont une représentation plus longue de la même information, optimisée pour alimenter l'algorithme BIP32 qui suit.

---

## 5. HMAC-SHA512 — de la graine à la clé maître

### 5.1 Qu'est-ce que HMAC ?

HMAC (*Hash-based Message Authentication Code*) est une construction qui utilise une fonction de hachage avec une **clé secrète**.

```
HMAC-SHA512(clé, message) = SHA512(clé ⊕ opad || SHA512(clé ⊕ ipad || message))
```

Où `opad = 0x5c5c...5c` et `ipad = 0x3636...36` sont des masques fixes. Cette double structure garantit qu'un attaquant ne peut pas forger un HMAC sans connaître la clé, même s'il connaît le message.

Ici, HMAC-SHA512 est utilisé **non pas pour l'authentification**, mais comme une **fonction de dérivation pseudo-aléatoire** (PRF). C'est une utilisation standard en cryptographie.

### 5.2 Calcul de la clé maître

```python
resultat_hmac = hmac.new(
    key      = b"Bitcoin seed",   # clé littérale, fixée par le standard BIP32
    msg      = graine,            # les 64 bytes de PBKDF2
    digestmod = hashlib.sha512
).digest()                        # → 64 bytes

cle_privee = resultat_hmac[:32]   # 32 bytes gauche = clé privée maître
chain_code = resultat_hmac[32:]   # 32 bytes droite = chain code maître
```

La clé littérale `"Bitcoin seed"` est définie dans le BIP32 comme la clé HMAC racine. Tout wallet Bitcoin BIP32 dans le monde utilise cette même clé. C'est un sel global qui garantit l'interopérabilité.

### 5.3 Le chain code — un secret auxiliaire indispensable

Le **chain code** est la moitié droite du HMAC-SHA512. C'est un secret de 32 bytes qui accompagne chaque clé privée dans l'arbre de dérivation.

Sans le chain code parent, il est **impossible de dériver les clés enfants**, même en connaissant la clé privée parent. C'est une couche de sécurité supplémentaire.

Conséquence pratique :
- `clé privée maître` seule → ne suffit pas à reconstituer le wallet
- `clé privée maître + chain code maître` → suffit à reconstituer l'arbre entier
- La paire `(clé_privée, chain_code)` s'appelle une **clé étendue** (*extended key*)

### 5.4 Validation de la clé privée

```python
N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
k = int.from_bytes(cle_privee, "big")
print(f"0 < k < n ? = {0 < k < N}")
```

`N` est l'**ordre du groupe** de la courbe secp256k1 — le nombre de points distincts sur la courbe. Une clé privée valide doit être dans l'intervalle `[1, N-1]`.

La probabilité qu'une clé privée aléatoire de 256 bits soit invalide (= 0 ou ≥ N) est astronomiquement faible :

```
N ≈ 1.158 × 10⁷⁷
2²⁵⁶ ≈ 1.158 × 10⁷⁷ (presque identiques)
probabilité d'invalidité ≈ 1 sur 10³⁸
```

Le script vérifie quand même, par rigueur.

---

## 6. Courbe elliptique secp256k1 — clé privée → clé publique

### 6.1 Qu'est-ce qu'une courbe elliptique ?

Une courbe elliptique est définie par l'équation générale de Weierstrass :

```
y² = x³ + ax + b
```

Pour **secp256k1** (la courbe de Bitcoin) : `a = 0`, `b = 7`, donc :

```
y² = x³ + 7
```

**Attention** : ce n'est pas une courbe sur les réels. C'est une courbe sur un **corps fini** `𝔽_p`, c'est-à-dire que toutes les opérations sont effectuées **modulo p**, où :

```
p = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
  = 2²⁵⁶ - 2³² - 977
```

Ce `p` est un nombre premier de 256 bits. Travailler modulo `p` signifie que les résultats sont toujours ramenés dans l'intervalle `[0, p-1]`. La courbe n'est plus une courbe lisse mais un **nuage fini de points** dans un espace discret.

### 6.2 Addition de points

L'opération fondamentale est l'**addition de deux points** sur la courbe. Géométriquement (sur les réels, pour l'intuition) :

```
Pour additionner A + B :
1. Tracer la droite passant par A et B
2. Elle coupe la courbe en un 3ème point R'
3. Prendre le symétrique de R' par rapport à l'axe x → résultat R = A + B
```

Cas spécial **doublement** (A + A = 2A) :
```
1. Prendre la tangente à la courbe en A
2. Elle coupe la courbe en un autre point R'
3. Prendre le symétrique → R = 2A
```

Sur `𝔽_p`, les formules algébriques remplacent la géométrie, mais la logique est identique :

Pour deux points distincts `P = (x₁, y₁)` et `Q = (x₂, y₂)` :
```
λ = (y₂ - y₁) × (x₂ - x₁)⁻¹  (mod p)
x₃ = λ² - x₁ - x₂              (mod p)
y₃ = λ(x₁ - x₃) - y₁           (mod p)
```

Pour le doublement `P + P = 2P` :
```
λ = (3x₁² + a) × (2y₁)⁻¹       (mod p)   [avec a=0 pour secp256k1]
x₃ = λ² - 2x₁                   (mod p)
y₃ = λ(x₁ - x₃) - y₁            (mod p)
```

L'inverse modulaire `(x₂ - x₁)⁻¹ mod p` est calculé avec l'algorithme d'Euclide étendu — c'est l'équivalent de la division dans un corps fini.

### 6.3 Le point générateur G

```python
Gx = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798
Gy = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8
```

`G = (Gx, Gy)` est le **point générateur** de secp256k1. Ces coordonnées sont définies dans le standard et sont universelles — tout wallet Bitcoin dans le monde utilise exactement ce même point.

`G` a été choisi soigneusement pour générer un sous-groupe d'ordre `N` (le plus grand possible), ce qui maximise la sécurité.

### 6.4 Multiplication scalaire — K = k × G

La clé publique `K` est calculée par **multiplication scalaire** :

```
K = k × G = G + G + G + ... + G  (k fois)
```

On n'additionne évidemment pas `k` fois (k ≈ 2²⁵⁶, impossible). On utilise l'algorithme **double-and-add**, analogue à l'exponentiation rapide.

Exemple avec `k = 13` (binaire : `1101`) :

```
k = 13 → bits = [1, 1, 0, 1]  (du bit de poids fort au faible)

Initialisation : résultat = G  (premier bit = 1)
bit 1 (valeur 1) : résultat = 2 × résultat + G = 2G + G = 3G
bit 0 (valeur 0) : résultat = 2 × résultat     = 6G
bit 1 (valeur 1) : résultat = 2 × résultat + G = 12G + G = 13G ✓
```

Le nombre d'opérations est `O(log₂(k))` — pour k de 256 bits, environ **256 opérations** au lieu de `2²⁵⁶`.

```python
signing_key  = ecdsa.SigningKey.from_string(cle_privee, curve=ecdsa.SECP256k1)
verifying_key = signing_key.get_verifying_key()
Kx = verifying_key.pubkey.point.x()
Ky = verifying_key.pubkey.point.y()
```

La bibliothèque `ecdsa` effectue ce calcul en interne. `K = (Kx, Ky)` est un point sur la courbe — deux entiers de 256 bits chacun.

### 6.5 Irréversibilité — le problème du logarithme discret

Connaître `K` (= k × G) et `G` ne permet pas de retrouver `k`. Il faudrait résoudre :

> *Combien de fois a-t-on additionné G pour obtenir K ?*

C'est le **problème du logarithme discret sur courbe elliptique** (ECDLP). Aucun algorithme classique connu ne peut le résoudre en temps polynomial. Le meilleur algorithme connu (Pollard's rho) nécessite `O(√N)` opérations ≈ `2¹²⁸` — hors de portée pour des millénaires.

Contrairement à RSA (vulnérable aux ordinateurs quantiques via l'algorithme de Shor), l'ECDLP reste difficile même quantiquement — bien que des avancées théoriques existent, aucun ordinateur quantique pratique ne peut attaquer secp256k1 aujourd'hui.

### 6.6 Compression de la clé publique

La clé publique brute `(Kx, Ky)` fait **64 bytes**. Elle peut être compressée à **33 bytes**.

```python
prefixe          = b'\x02' if Ky % 2 == 0 else b'\x03'
cle_pub_compressee = prefixe + Kx.to_bytes(32, "big")
```

**Pourquoi ça marche ?** L'équation de la courbe est `y² = x³ + 7 (mod p)`. Pour un `x` donné, il y a **au plus deux valeurs de y** (symétrie). Ces deux valeurs sont `y` et `p - y`. L'une est paire, l'autre impaire.

Il suffit donc de stocker :
- `Kx` (32 bytes) : la coordonnée x
- `0x02` si `Ky` est pair, `0x03` si `Ky` est impair

Pour reconstruire `Ky` :
```
y² = Kx³ + 7  (mod p)
y  = sqrt(y²) (mod p)
→ deux solutions : y et p - y
→ choisir celle dont la parité correspond au préfixe
```

La clé publique compressée de 33 bytes est le format standard utilisé partout en Bitcoin depuis 2012.

---

## 7. Dérivation BIP32 — l'arbre infini de clés

### 7.1 Concept — pourquoi un arbre ?

Sans BIP32, un wallet devrait générer une nouvelle clé privée aléatoire pour chaque adresse, et sauvegarder chacune séparément. Avec BIP32 :

- Une **seule seed** → un arbre **infini** de clés
- La seed suffit pour tout restaurer
- On peut générer des milliers d'adresses de réception sans jamais réutiliser la même
- Des **comptes** séparés peuvent coexister dans le même wallet

### 7.2 Le chemin de dérivation BIP84

Le script utilise le chemin `m/84'/0'/0'/0/index`, défini par le BIP84 pour les adresses Native SegWit (bc1q).

```
m       → clé maître (racine)
84'     → purpose = BIP84 (Native SegWit), DURCI
0'      → coin_type = 0 = Bitcoin mainnet, DURCI
0'      → account = 0 (premier compte), DURCI
0       → change = 0 (adresses de réception externes), NORMAL
index   → index de l'adresse (0, 1, 2...), NORMAL
```

L'apostrophe `'` indique une **dérivation durcie** (*hardened*). L'absence d'apostrophe indique une dérivation **normale**.

### 7.3 Dérivation normale vs durcie

```python
def deriver_enfant(cle_privee_parent, chain_code_parent, index, durci=False):
    N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141

    if durci:
        # index réel = index + 2³¹ (espace des index durcis : 2³¹ à 2³²-1)
        index_reel = index + 0x80000000
        data = b'\x00' + cle_privee_parent + struct.pack(">I", index_reel)
    else:
        data = cle_pub_compressee + struct.pack(">I", index)

    I  = hmac.new(key=chain_code_parent, msg=data, digestmod=hashlib.sha512).digest()
    IL = I[:32]    # 32 bytes gauche
    IR = I[32:]    # 32 bytes droite → nouveau chain code enfant

    cle_enfant_int = (int.from_bytes(IL, "big") + int.from_bytes(cle_privee_parent, "big")) % N
    return cle_enfant_int.to_bytes(32, "big"), IR
```

**Dérivation normale** (`index < 2³¹`, sans `'`) :
```
data = clé_publique_parent (33 bytes) + index (4 bytes big-endian)
I    = HMAC-SHA512(chain_code_parent, data)
```

Avantage : on peut dériver les clés publiques enfants **sans connaître la clé privée parent** — seulement avec la clé publique parent et le chain code. Cela permet les **wallets watch-only** (observation sans dépense).

Risque : si une clé privée enfant est compromise **ET** le chain code parent est connu, on peut reconstruire la clé privée parent. Pour les niveaux sensibles, on utilise donc la dérivation durcie.

**Dérivation durcie** (`index ≥ 2³¹`, avec `'`) :
```
data = 0x00 (1 byte) + clé_privée_parent (32 bytes) + index (4 bytes big-endian)
I    = HMAC-SHA512(chain_code_parent, data)
```

Le préfixe `0x00` distingue ce cas de la clé publique compressée (qui commence par `0x02` ou `0x03`). La **clé privée parent est obligatoire**.

Avantage : compromettre une clé enfant n'expose **jamais** la clé privée parent ni les clés sœurs.

C'est pourquoi les niveaux `purpose`, `coin_type` et `account` sont toujours durcis.

### 7.4 Calcul de la clé enfant

```
IL = HMAC-SHA512(chain_code_parent, data)[:32]
IR = HMAC-SHA512(chain_code_parent, data)[32:]   → chain code enfant

clé_privée_enfant = (IL + clé_privée_parent) mod N
chain_code_enfant = IR
```

`IL` est interprété comme un entier de 256 bits et **ajouté** (modulo N) à la clé privée parent. Ce n'est pas une concaténation — c'est une **addition arithmétique dans le groupe**.

Le fait d'additionner signifie que la clé enfant est liée algébriquement à la clé parent, mais de façon unidirectionnelle : sans `IL`, impossible de déduire la relation.

### 7.5 Dérivation niveau par niveau

```python
def deriver_chemin(cle, chain, chemin):
    niveaux = chemin.split("/")[1:]        # ["84'", "0'", "0'"]
    for niveau in niveaux:
        durci = niveau.endswith("'")
        index = int(niveau.rstrip("'"))    # "84'" → 84
        cle, chain = deriver_enfant(cle, chain, index, durci)
    return cle, chain
```

Chaque niveau consomme la sortie du précédent. La clé privée et le chain code "descendent" dans l'arbre.

### 7.6 `struct.pack(">I", index)`

```python
struct.pack(">I", index_reel)
```

Cette ligne sérialise l'index (un entier Python) en **4 bytes big-endian**.

- `>` : big-endian (octet de poids fort en premier)
- `I` : unsigned int (entier non signé 32 bits)

Pour `index = 0` → `\x00\x00\x00\x00`  
Pour `index = 1` → `\x00\x00\x00\x01`  
Pour `index = 0x80000000` (premier index durci) → `\x80\x00\x00\x00`

Le big-endian est le standard réseau et cryptographique.

---

## 8. Adresse Native SegWit — hash160 + Bech32

### 8.1 Pourquoi deux fonctions de hachage en cascade ?

```python
sha256   = hashlib.sha256(cle_pub).digest()         # → 32 bytes
ripemd160 = hashlib.new("ripemd160", sha256).digest() # → 20 bytes
```

**SHA256** seul produirait une sortie de 32 bytes (256 bits) — trop long pour une adresse lisible.

**RIPEMD160** (*RACE Integrity Primitives Evaluation Message Digest 160*) compresse à **20 bytes (160 bits)**, produisant des adresses plus courtes.

La cascade SHA256 → RIPEMD160 est appelée **hash160**. Elle est utilisée partout dans Bitcoin. Elle offre :

1. **Défense en profondeur** : si RIPEMD160 était un jour cassé, SHA256 reste une barrière. Et inversement.
2. **Résistance aux extensions de longueur** (*length extension attacks*) : SHA256 seul est vulnérable à cette attaque sur certaines constructions. RIPEMD160 en cascade l'élimine.
3. **Réduction de taille** : 20 bytes vs 32 bytes, sans perte de sécurité significative pour les adresses Bitcoin (160 bits suffisent largement).

### 8.2 Conversion 8 bits → 5 bits pour Bech32

```python
data_5bit = bech32.convertbits(ripemd160, 8, 5)
```

Bech32 utilise un alphabet de **32 caractères** (`2^5 = 32`). Pour encoder des bytes (groupes de 8 bits), il faut les réinterpréteur en groupes de 5 bits.

```
20 bytes × 8 bits = 160 bits
160 bits ÷ 5      = 32 groupes de 5 bits
```

Chaque groupe de 5 bits (valeur 0–31) est mappé à un caractère de l'alphabet Bech32.

Exemple de conversion :
```
byte 0 : 0b10110100 = 8 bits
byte 1 : 0b11001010 = 8 bits

bits concaténés : 1011010011001010
groupes de 5   : 10110 | 10011 | 00101 | 0...
valeurs        : 22    | 19    | 5     | ...
```

### 8.3 Encodage Bech32

```python
adresse = bech32.bech32_encode("bc", [0] + data_5bit)
```

**Bech32** est défini par le BIP173. L'adresse finale a la structure :

```
bc 1 q [39 caractères de données] [6 caractères de checksum]
│  │ │
│  │ └─ witness version 0 encodée en base32 (0 → 'q')
│  └─── séparateur Bech32 (toujours '1')
└────── HRP = Human Readable Part ("bc" = Bitcoin mainnet)
```

L'alphabet Bech32 est soigneusement choisi pour éviter les confusions visuelles :

```
qpzry9x8gf2tvdw0s3jn54khce6mua7l
```

Cet alphabet exclut : `0` (confondu avec `O`), `1` (confondu avec `l`), `b` (confondu avec `6`), `i` (confondu avec `I`). Toutes les lettres sont en minuscules.

### 8.4 Le checksum Bech32

Les 6 derniers caractères de l'adresse sont un **checksum**. Il est calculé via un polynôme BCH (*Bose–Chaudhuri–Hocquenghem*) sur GF(32) :

```python
# Implémenté dans bech32.py (bibliothèque)
def bech32_polymod(values):
    GEN = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3]
    chk = 1
    for v in values:
        b = (chk >> 25)
        chk = (chk & 0x1ffffff) << 5 ^ v
        for i in range(5):
            chk ^= GEN[i] if ((b >> i) & 1) else 0
    return chk
```

Ce checksum peut **détecter** jusqu'à 4 erreurs arbitraires dans l'adresse, et **corriger** certaines combinaisons d'erreurs. En pratique, il est essentiellement impossible d'envoyer accidentellement des bitcoins à une adresse mal saisie.

### 8.5 P2WPKH — ce que l'adresse encode vraiment

Une adresse `bc1q...` est une adresse **P2WPKH** (*Pay to Witness Public Key Hash*). Ce qu'elle encode :

```
[witness version = 0] [hash160(clé_publique_compressée)]
```

Pour dépenser les bitcoins envoyés à cette adresse, le propriétaire doit fournir dans la transaction :
1. La clé publique compressée (prouve qu'il connaît `Kx, Ky`)
2. Une signature ECDSA valide (prouve qu'il connaît `k`)

Le réseau vérifie que `hash160(clé_publique_fournie) == hash160_dans_l'adresse`. C'est le mécanisme SegWit (*Segregated Witness*), introduit en 2017, qui sépare les données de signature (*witness*) du corps de la transaction.

---

## 9. Récapitulatif et propriétés du système

### 9.1 Pipeline complet annoté

```
os.urandom(32)
│   32 bytes = 256 bits depuis l'entropy pool du noyau
│   2²⁵⁶ combinaisons possibles ≈ nombre d'atomes dans l'univers
↓
SHA256(entropie) → checksum 8 bits
│   264 bits totaux
│   24 groupes de 11 bits → 24 index dans [0, 2047]
│   24 index → 24 mots BIP39
↓
PBKDF2-HMAC-SHA512(password=mots, salt="mnemonic", iterations=2048)
│   Étirement de clé : multiplie par 2048 le coût du brute force
│   Sortie : 64 bytes = 512 bits (graine)
↓
HMAC-SHA512(key="Bitcoin seed", msg=graine)
│   64 bytes coupés en deux :
│   [0:32]  → clé privée maître  (entier dans [1, N-1])
│   [32:64] → chain code maître  (entropie auxiliaire)
↓
Dérivation BIP32 : m/84'/0'/0'/0/index
│   Chaque niveau : HMAC-SHA512(chain_parent, data) → IL + IR
│   clé_enfant = (IL + clé_parent) mod N
│   chain_enfant = IR
│   Niveaux durcis (') : data = 0x00 + clé_privée_parent + index
│   Niveaux normaux     : data = clé_publique_parent + index
↓
k × G sur secp256k1  (double-and-add, ~256 opérations)
│   G = point générateur universel
│   K = (Kx, Ky) → clé publique compressée = 0x02/0x03 + Kx (33 bytes)
↓
SHA256(clé_pub) → RIPEMD160 = hash160 (20 bytes)
│   Défense en profondeur, compression 32 → 20 bytes
↓
Bech32(hrp="bc", witness_version=0, data=hash160)
    → bc1q... (adresse Native SegWit P2WPKH)
```

### 9.2 Propriétés fondamentales

**Déterministe** : les mêmes 24 mots produisent toujours exactement les mêmes adresses, sur n'importe quel wallet compatible BIP39/44/84. C'est pour ça que les 24 mots *sont* le wallet.

**Irréversible** : chaque flèche dans le pipeline est une fonction à sens unique. Connaître une adresse ne permet pas de remonter à la clé publique. Connaître la clé publique ne permet pas de retrouver la clé privée (ECDLP). Connaître la clé privée ne permet pas de retrouver la seed.

**Infini** : l'index peut aller de 0 à `2³¹ - 1` (plus de 2 milliards d'adresses) sur la branche normale. En pratique, les wallets utilisent quelques dizaines à quelques centaines.

**Hiérarchique** : plusieurs comptes (`0'`, `1'`, `2'`...) peuvent coexister dans le même wallet, chacun avec son sous-arbre isolé.

**Interopérable** : les standards BIP39, BIP32, BIP44, BIP84 sont ouverts et implémentés par tous les wallets majeurs (Ledger, Trezor, Electrum, Sparrow...).

### 9.3 Ce que le script ne fait pas (à dessein)

Le script est **éducatif**, pas un wallet de production. Il n'implémente pas :

- **WIF** (*Wallet Import Format*) : encodage standardisé de la clé privée pour l'import/export entre wallets
- **xpub / xprv** : format de sérialisation des clés étendues (Base58Check)
- **PSBT** (*Partially Signed Bitcoin Transaction*) : format de transaction moderne
- **Gestion des UTXO** (*Unspent Transaction Outputs*) : suivi du solde
- **Signature de transactions** : le seul usage réel de la clé privée

---

## 10. Annexe — bibliothèques Python utilisées

### `hashlib` (standard library)
Fournit SHA256, SHA512, RIPEMD160, et PBKDF2. Module de la bibliothèque standard Python — pas d'installation requise.

```python
hashlib.sha256(data).digest()             # → 32 bytes
hashlib.sha512(data).digest()             # → 64 bytes
hashlib.new("ripemd160", data).digest()   # → 20 bytes
hashlib.pbkdf2_hmac("sha512", pwd, salt, iters, dklen)
```

### `hmac` (standard library)
HMAC avec n'importe quelle fonction de hachage.

```python
hmac.new(key=b"...", msg=b"...", digestmod=hashlib.sha512).digest()
```

### `struct` (standard library)
Sérialisation de types Python en bytes, selon un format précis.

```python
struct.pack(">I", 42)   # unsigned int 32-bit big-endian → b'\x00\x00\x00\x2a'
```

### `os` (standard library)
`os.urandom(n)` : n bytes cryptographiquement aléatoires depuis l'OS.

### `mnemonic` (`python-mnemonic`)
Bibliothèque de référence BIP39. Fournit la liste de 2048 mots et les conversions.

```bash
pip install mnemonic
```

```python
mnemo = Mnemonic("english")
mots  = mnemo.to_mnemonic(entropie_bytes)   # bytes → phrase
```

### `ecdsa`
Implémentation Python pure des courbes elliptiques ECDSA. Utilisé pour la multiplication scalaire k × G.

```bash
pip install ecdsa
```

```python
sk = ecdsa.SigningKey.from_string(private_key_bytes, curve=ecdsa.SECP256k1)
vk = sk.get_verifying_key()
point = vk.pubkey.point
Kx, Ky = point.x(), point.y()
```

### `bech32`
Implémentation de référence de l'encodage Bech32 (BIP173).

```bash
pip install bech32
```

```python
data_5bit = bech32.convertbits(ripemd160_bytes, 8, 5)   # 8-bit → 5-bit groups
adresse   = bech32.bech32_encode("bc", [0] + data_5bit)  # witness version 0
```

---

> **⚠️ Avertissement de sécurité**  
> Ce script génère de vraies clés privées Bitcoin. Ne jamais l'utiliser pour des fonds réels. Les clés privées affichées à l'écran sont potentiellement visibles dans les logs, l'historique du terminal, ou les yeux indiscrets. Un wallet de production utilise des enclaves sécurisées (Secure Element sur Ledger) qui ne laissent jamais la clé privée quitter le matériel.

---

*Cours généré depuis `wallet.py` — Bitcoin HD Wallet éducatif v2*  
*BIP39 · BIP32 · BIP84 · secp256k1 · Bech32 · P2WPKH*
