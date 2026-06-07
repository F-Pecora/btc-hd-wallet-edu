"""
=============================================================================
  BITCOIN HD WALLET — SCRIPT ÉDUCATIF ULTRA-DÉTAILLÉ v2
  Chaque byte intermédiaire affiché, maths de courbe elliptique expliquées
  BIP39 → BIP32 → BIP84 → adresse Native SegWit (bc1q)
=============================================================================
"""

import hashlib
import hmac
import struct
import os
from mnemonic import Mnemonic
import ecdsa
import bech32


# ════════════════════════════════════════════════════════════════
#  UTILITAIRES D'AFFICHAGE
# ════════════════════════════════════════════════════════════════

def sep(titre):
    print(f"\n{'═' * 68}")
    print(f"  {titre}")
    print(f"{'═' * 68}")

def sous_sep(titre):
    print(f"\n  {'─' * 60}")
    print(f"  {titre}")
    print(f"  {'─' * 60}")

def afficher_bytes_detail(label, data, bytes_par_ligne=16):
    """
    Affiche des bytes de manière pédagogique :
    - En hexadécimal (base 16, 2 chars par byte)
    - En binaire (base 2, 8 chars par byte)
    - Avec le compte total
    """
    print(f"\n  {label}")
    print(f"  Taille : {len(data)} bytes = {len(data) * 8} bits")
    print()

    # Affichage hex groupé par ligne
    print(f"  [HEX]")
    for i in range(0, len(data), bytes_par_ligne):
        chunk = data[i:i+bytes_par_ligne]
        hex_part = ' '.join(f'{b:02x}' for b in chunk)
        print(f"    {i:>3}: {hex_part}")

    # Affichage binaire (seulement pour les petits blocs)
    if len(data) <= 8:
        print(f"\n  [BINAIRE]")
        for i, b in enumerate(data):
            print(f"    byte {i}: {b:08b}  = {b:3d} décimal = 0x{b:02x} hex")


def afficher_bits_groupes(data, taille_groupe, label=""):
    """
    Découpe des bytes en groupes de N bits et affiche chaque groupe.
    Utilisé pour visualiser le découpage BIP39 en groupes de 11 bits.
    """
    # Convertir tous les bytes en une longue chaîne de bits
    bits = ''.join(f'{b:08b}' for b in data)

    print(f"\n  {label}")
    print(f"  Chaîne binaire complète ({len(bits)} bits) :")

    # Afficher la chaîne binaire par morceaux de 44 bits (4 groupes de 11)
    for i in range(0, len(bits), 44):
        chunk = bits[i:i+44]
        # Séparer visuellement les groupes de 11 bits
        groupes = [chunk[j:j+11] for j in range(0, len(chunk), 11)]
        print(f"    {'  |  '.join(groupes)}")

    print(f"\n  Groupes de {taille_groupe} bits → index → mot :")
    for i in range(0, len(bits), taille_groupe):
        groupe = bits[i:i+taille_groupe]
        if len(groupe) < taille_groupe:
            break
        index = int(groupe, 2)
        print(f"    Groupe {i//taille_groupe:>2} : {groupe} = {index:>4} décimal")


# ════════════════════════════════════════════════════════════════
#  ÉTAPE 1 — ENTROPIE : os.urandom(32)
# ════════════════════════════════════════════════════════════════

def etape_entropie():
    sep("ÉTAPE 1 — Génération de l'entropie brute")

    print("""
  Un "bit" = l'unité minimale d'information : 0 ou 1.
  Un "byte" = 8 bits groupés ensemble.
  Un byte peut représenter un nombre de 0 à 255 (2⁸ = 256 valeurs).

  os.urandom(32) demande au noyau du système d'exploitation
  32 bytes aléatoires depuis une source cryptographiquement sûre
  (Linux: /dev/urandom, capteur de bruit matériel + entropy pool).

  32 bytes × 8 bits = 256 bits d'entropie.
  2²⁵⁶ ≈ 10⁷⁷ combinaisons possibles.
  (Le nombre d'atomes dans l'univers observable ≈ 10⁸⁰)
  → Tomber deux fois sur la même valeur est physiquement impossible.
    """)

    entropie = os.urandom(32)
    afficher_bytes_detail("Entropie brute générée (32 bytes = 256 bits) :", entropie)
    return entropie


# ════════════════════════════════════════════════════════════════
#  ÉTAPE 2 — CHECKSUM + DÉCOUPAGE EN 24 MOTS (BIP39)
# ════════════════════════════════════════════════════════════════

def etape_mots(entropie):
    sep("ÉTAPE 2 — Checksum SHA256 + découpage en 24 mots (BIP39)")

    print("""
  Le checksum sert à détecter une erreur de recopie des mots.
  Si tu te trompes sur un mot, le checksum ne colle plus → erreur signalée.

  Calcul :
  1. SHA256(entropie_256bits) → 256 bits de hash
  2. On prend les 8 premiers bits de ce hash → checksum
  3. On concatène : entropie(256 bits) + checksum(8 bits) = 264 bits
  4. On découpe 264 bits en 24 groupes de 11 bits
  5. Chaque groupe (0 à 2047) indexe un mot dans la liste BIP39
    """)

    # Calcul du checksum
    hash_entropie = hashlib.sha256(entropie).digest()

    sous_sep("SHA256 de l'entropie (pour le checksum)")
    afficher_bytes_detail("SHA256(entropie) :", hash_entropie)

    # 8 premiers bits du hash = checksum
    checksum_byte = hash_entropie[0]
    checksum_bits = f'{checksum_byte:08b}'
    print(f"\n  Premier byte du SHA256 : 0x{checksum_byte:02x} = {checksum_bits} (binaire)")
    print(f"  → On prend les 8 premiers bits comme checksum : {checksum_bits}")

    # Concaténation entropie + checksum
    entropie_bits = ''.join(f'{b:08b}' for b in entropie)
    bits_total = entropie_bits + checksum_bits

    print(f"\n  Entropie  : {len(entropie_bits)} bits")
    print(f"  Checksum  : {len(checksum_bits)} bits")
    print(f"  Total     : {len(bits_total)} bits ÷ 11 = {len(bits_total)//11} groupes")

    # Découpage en groupes de 11 bits
    sous_sep("Découpage des 264 bits en 24 groupes de 11 bits")
    afficher_bits_groupes(
        entropie + bytes([checksum_byte]),
        11,
        "264 bits (entropie + checksum) :"
    )

    # Génération des mots via la bibliothèque mnemonic
    mnemo = Mnemonic("english")
    mots = mnemo.to_mnemonic(entropie)
    liste_mots = mots.split()

    print(f"\n  Chaque index → mot dans la liste BIP39 (2048 mots) :")
    print(f"  (index 0='abandon', index 1='ability', ..., index 2047='zoo')\n")

    # Afficher index → mot pour chaque groupe
    for i in range(0, len(bits_total) - 8, 11):
        groupe = bits_total[i:i+11]
        if len(groupe) < 11:
            break
        index = int(groupe, 2)
        mot_num = i // 11
        if mot_num < len(liste_mots):
            print(f"    Groupe {mot_num+1:>2} : {groupe} = {index:>4} → \"{liste_mots[mot_num]}\"")

    print(f"\n  ┌─────────────────────────────────────────┐")
    print(f"  │ Mnémonique final (24 mots) :             │")
    for i, mot in enumerate(liste_mots, 1):
        print(f"  │   {i:>2}. {mot:<35}│")
    print(f"  └─────────────────────────────────────────┘")

    return mots


# ════════════════════════════════════════════════════════════════
#  ÉTAPE 3 — 24 MOTS → GRAINE 512 BITS (PBKDF2)
# ════════════════════════════════════════════════════════════════

def etape_graine(mots):
    sep("ÉTAPE 3 — 24 mots → Graine 512 bits (PBKDF2-HMAC-SHA512)")

    print("""
  PBKDF2 = Password-Based Key Derivation Function 2.
  C'est une fonction d'étirement de clé.

  Pourquoi ne pas juste faire SHA512(mots) directement ?
  → Trop rapide. Un attaquant sur GPU teste des milliards de
    combinaisons/seconde. PBKDF2 force 2048 passes de SHA512,
    ce qui multiplie le temps de brute force par 2048.

  Entrées de PBKDF2 :
  - password : les 24 mots joints par des espaces, encodés UTF-8
  - salt     : la chaîne "mnemonic" + passphrase (vide ici)
  - algo     : HMAC-SHA512
  - rounds   : 2048 itérations
  - output   : 64 bytes = 512 bits

  Ce que fait PBKDF2 en pseudo-code :
    résultat = mots + salt
    Pour i de 1 à 2048 :
        résultat = HMAC-SHA512(clé=mots, message=résultat)
    → 64 bytes de sortie
    """)

    password = mots.encode("utf-8")
    salt = b"mnemonic"

    print(f"  password (UTF-8) : \"{mots[:40]}...\"")
    print(f"  salt             : \"{salt.decode()}\"")
    print(f"  Lancement de 2048 itérations HMAC-SHA512...")

    graine = hashlib.pbkdf2_hmac(
        hash_name="sha512",
        password=password,
        salt=salt,
        iterations=2048,
        dklen=64
    )

    afficher_bytes_detail("Graine résultante (64 bytes = 512 bits) :", graine)

    print(f"""
  Note : on est passé de 256 bits (entropie) à 512 bits (graine).
  L'entropie réelle reste 256 bits — on n'a pas "créé" de l'aléatoire.
  On a juste étiré la sortie pour avoir une graine plus longue
  depuis laquelle dériver un arbre infini de clés (BIP32).
    """)

    return graine


# ════════════════════════════════════════════════════════════════
#  ÉTAPE 4 — GRAINE → CLÉ MAÎTRE + CHAIN CODE (HMAC-SHA512)
# ════════════════════════════════════════════════════════════════

def etape_cle_maitre(graine):
    sep("ÉTAPE 4 — Graine → Clé maître + Chain code (HMAC-SHA512)")

    print("""
  HMAC = Hash-based Message Authentication Code.
  HMAC-SHA512(clé, message) produit 64 bytes depuis deux entrées.

  Ici :
  - clé     : la chaîne littérale "Bitcoin seed" (standard BIP32)
  - message : les 64 bytes de graine

  Les 64 bytes de sortie sont coupés en deux :
  - 32 bytes gauche → clé privée maître
  - 32 bytes droite → chain code maître

  Le chain code est un secret auxiliaire indispensable à la dérivation.
  Sans lui, même en connaissant la clé privée parent, on ne peut pas
  calculer les clés enfants. C'est une couche de sécurité supplémentaire.
    """)

    resultat_hmac = hmac.new(
        key=b"Bitcoin seed",
        msg=graine,
        digestmod=hashlib.sha512
    ).digest()

    sous_sep("Résultat brut HMAC-SHA512 (64 bytes)")
    afficher_bytes_detail("HMAC-SHA512(key='Bitcoin seed', msg=graine) :", resultat_hmac)

    cle_privee = resultat_hmac[:32]
    chain_code = resultat_hmac[32:]

    sous_sep("Découpage en deux moitiés de 32 bytes")
    afficher_bytes_detail("Clé privée maître [bytes 0..31] :", cle_privee)
    afficher_bytes_detail("Chain code maître [bytes 32..63] :", chain_code)

    # Vérification que la clé privée est dans l'intervalle valide
    N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
    k = int.from_bytes(cle_privee, "big")
    print(f"\n  Validation de la clé privée :")
    print(f"  k (entier)     = {k}")
    print(f"  n (ordre courbe) = {N}")
    print(f"  0 < k < n ?    = {0 < k < N}  ← obligatoire pour secp256k1")

    return cle_privee, chain_code


# ════════════════════════════════════════════════════════════════
#  ÉTAPE 5 — COURBE ELLIPTIQUE : CLÉ PRIVÉE → CLÉ PUBLIQUE
# ════════════════════════════════════════════════════════════════

def etape_courbe_elliptique(cle_privee):
    sep("ÉTAPE 5 — Courbe elliptique secp256k1 : clé privée → clé publique")

    print("""
  ┌─────────────────────────────────────────────────────────┐
  │  QU'EST-CE QU'UNE COURBE ELLIPTIQUE ?                   │
  └─────────────────────────────────────────────────────────┘

  Une courbe elliptique est définie par l'équation :
      y² = x³ + ax + b

  Pour secp256k1 (Bitcoin) : a=0, b=7, donc :
      y² = x³ + 7

  Mais attention : pas sur les réels comme au lycée.
  Sur un corps fini modulo p (un très grand nombre premier) :
      y² ≡ x³ + 7  (mod p)

  p = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
    ≈ 2²⁵⁶ - 2³² - 977

  Concrètement : toutes les coordonnées (x, y) sont des entiers
  entre 0 et p-1. La courbe forme un ensemble fini de points.

  ┌─────────────────────────────────────────────────────────┐
  │  ADDITION DE POINTS SUR LA COURBE                       │
  └─────────────────────────────────────────────────────────┘

  On peut "additionner" deux points A et B sur la courbe :
  - On trace la droite qui passe par A et B
  - Elle coupe la courbe en un 3ème point
  - On prend son symétrique par rapport à l'axe x → c'est A + B

  Cas spécial : doubler un point A (A + A) :
  - On prend la tangente à la courbe en A
  - Elle coupe la courbe en un autre point
  - On prend son symétrique → c'est 2A

  ┌─────────────────────────────────────────────────────────┐
  │  MULTIPLICATION SCALAIRE : K = k × G                    │
  └─────────────────────────────────────────────────────────┘

  G = le point générateur (universel, fixé par le standard secp256k1)
  k = ta clé privée (un entier de 256 bits)
  K = ta clé publique (un point (x, y) sur la courbe)

  k × G = G + G + G + ... + G  (k fois)

  En pratique on n'additionne pas k fois (k ≈ 2²⁵⁶, impossible).
  On utilise l'algorithme "double-and-add" (comme l'exponentiation rapide) :

  Exemple avec k=13 (binaire: 1101) :
    k=13 → bits = [1, 1, 0, 1]

    Départ : résultat = G
    bit 1 (deuxième bit) : résultat = 2×résultat + G = 3G
    bit 0              : résultat = 2×résultat     = 6G
    bit 1 (dernier)    : résultat = 2×résultat + G = 13G ✓

  → log₂(k) opérations au lieu de k opérations.
  → Pour k de 256 bits : ~256 opérations au lieu de 2²⁵⁶.

  ┌─────────────────────────────────────────────────────────┐
  │  POURQUOI C'EST IRRÉVERSIBLE ?                          │
  └─────────────────────────────────────────────────────────┘

  Connaître K (= k×G) et G ne permet pas de retrouver k.
  Il faudrait résoudre : "combien de fois a-t-on additionné G ?"
  C'est le "problème du logarithme discret sur courbe elliptique".
  Aucun algorithme connu ne peut le résoudre en temps raisonnable.
  Même un ordinateur quantique ne peut pas le casser efficacement
  (contrairement à RSA).
    """)

    sous_sep("Calcul effectif de K = k × G")

    k_int = int.from_bytes(cle_privee, "big")
    print(f"\n  k (clé privée, entier) :")
    print(f"  {k_int}")

    # Coordonnées du point générateur G
    Gx = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798
    Gy = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8
    print(f"\n  G (point générateur, coordonnées) :")
    print(f"  Gx = {hex(Gx)}")
    print(f"  Gy = {hex(Gy)}")

    # Calcul via ecdsa
    signing_key = ecdsa.SigningKey.from_string(cle_privee, curve=ecdsa.SECP256k1)
    verifying_key = signing_key.get_verifying_key()

    Kx = verifying_key.pubkey.point.x()
    Ky = verifying_key.pubkey.point.y()

    print(f"\n  K = k × G (résultat, coordonnées du point) :")
    print(f"  Kx = {hex(Kx)}")
    print(f"  Ky = {hex(Ky)}")

    # Compression de la clé publique
    print(f"""
  ┌─────────────────────────────────────────────────────────┐
  │  COMPRESSION DE LA CLÉ PUBLIQUE                         │
  └─────────────────────────────────────────────────────────┘

  La clé publique brute = (Kx, Ky) = 64 bytes = 512 bits.
  On peut la compresser à 33 bytes car l'équation y² = x³+7
  donne deux valeurs de y pour chaque x (symétrie axiale).
  Il suffit de stocker x + un bit indiquant si y est pair ou impair.

  Préfixe :
  - 0x02 si Ky est pair
  - 0x03 si Ky est impair

  Clé publique compressée = préfixe (1 byte) + Kx (32 bytes) = 33 bytes
    """)

    prefixe = b'\x02' if Ky % 2 == 0 else b'\x03'
    cle_pub_compressee = prefixe + Kx.to_bytes(32, "big")

    print(f"  Ky est {'pair' if Ky % 2 == 0 else 'impair'} → préfixe = 0x{prefixe.hex()}")
    afficher_bytes_detail("Clé publique compressée (33 bytes) :", cle_pub_compressee)

    return cle_pub_compressee


# ════════════════════════════════════════════════════════════════
#  ÉTAPE 6 — DÉRIVATION BIP32
# ════════════════════════════════════════════════════════════════

def deriver_enfant(cle_privee_parent, chain_code_parent, index, durci=False):
    """Dérive une clé enfant. Retourne (cle_privee, chain_code)."""
    N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141

    signing_key = ecdsa.SigningKey.from_string(cle_privee_parent, curve=ecdsa.SECP256k1)
    cle_pub = signing_key.get_verifying_key()
    Kx = cle_pub.pubkey.point.x()
    Ky = cle_pub.pubkey.point.y()
    prefixe = b'\x02' if Ky % 2 == 0 else b'\x03'
    cle_pub_compressee = prefixe + Kx.to_bytes(32, "big")

    if durci:
        index_reel = index + 0x80000000
        data = b'\x00' + cle_privee_parent + struct.pack(">I", index_reel)
    else:
        data = cle_pub_compressee + struct.pack(">I", index)

    I = hmac.new(key=chain_code_parent, msg=data, digestmod=hashlib.sha512).digest()
    IL, IR = I[:32], I[32:]

    cle_enfant_int = (int.from_bytes(IL, "big") + int.from_bytes(cle_privee_parent, "big")) % N
    return cle_enfant_int.to_bytes(32, "big"), IR


def deriver_chemin(cle, chain, chemin):
    niveaux = chemin.split("/")[1:]
    for niveau in niveaux:
        durci = niveau.endswith("'")
        index = int(niveau.rstrip("'"))
        cle, chain = deriver_enfant(cle, chain, index, durci)
    return cle, chain


def etape_derivation(cle_maitre, chain_maitre):
    sep("ÉTAPE 6 — Dérivation BIP32 : chemin m/84'/0'/0'/0/index")

    print("""
  BIP32 permet de dériver un arbre infini de clés depuis la clé maître.
  Chaque niveau du chemin est une dérivation HMAC-SHA512.

  Le chemin m/84'/0'/0'/0/0 se lit :
  - m       : clé maître (racine de l'arbre)
  - 84'     : BIP84 (Native SegWit), dérivation DURCIE
  - 0'      : coin type 0 = Bitcoin mainnet, dérivation DURCIE
  - 0'      : compte numéro 0, dérivation DURCIE
  - 0       : branche externe (réception), dérivation NORMALE
  - 0,1,2…  : index de l'adresse, dérivation NORMALE

  ┌─────────────────────────────────────────────────────────┐
  │  DÉRIVATION NORMALE vs DURCIE (HARDENED)                │
  └─────────────────────────────────────────────────────────┘

  NORMALE (index < 2³¹, sans apostrophe) :
    data = clé_publique_parent + index
    → Possible de dériver les adresses de réception avec seulement
      la clé publique (xpub). Utile pour les wallets watch-only.
    → Risque : si une clé enfant est compromise ET le chain code
      parent est connu, on peut retrouver la clé privée parent.

  DURCIE (index ≥ 2³¹, avec apostrophe) :
    data = 0x00 + clé_privée_parent + index
    → Nécessite obligatoirement la clé privée parent.
    → Compromis d'une clé enfant n'expose jamais le parent.
    → C'est pour ça que les 3 premiers niveaux sont durcis.

  Dans les deux cas :
    HMAC-SHA512(chain_code_parent, data) → 64 bytes
    32 bytes gauche (IL) + 32 bytes droite (IR = nouveau chain code)
    clé_enfant = (IL + clé_parent) mod n
    """)

    # Dérivation niveau par niveau avec affichage
    niveaux = ["m/84'", "m/84'/0'", "m/84'/0'/0'"]
    cle_courante = cle_maitre
    chain_courant = chain_maitre

    for chemin in niveaux:
        sous_sep(f"Dérivation → {chemin}")
        parties = chemin.split("/")
        dernier = parties[-1]
        durci = dernier.endswith("'")
        index = int(dernier.rstrip("'"))

        cle_courante, chain_courant = deriver_enfant(
            cle_courante, chain_courant, index, durci
        )
        afficher_bytes_detail(f"Clé privée après {chemin} :", cle_courante)
        afficher_bytes_detail(f"Chain code après {chemin} :", chain_courant)

    # Dériver et afficher 3 adresses complètes
    sous_sep("Dérivation des adresses de réception (branche /0/index)")

    cle_compte  = cle_courante
    chain_compte = chain_courant

    for i in range(3):
        chemin_addr = f"m/84'/0'/0'/0/{i}"
        print(f"\n  ── Adresse index {i} : {chemin_addr} ──")

        # Branche externe /0
        cle_ext, chain_ext = deriver_enfant(cle_compte, chain_compte, 0, False)
        # Index final
        cle_addr, _ = deriver_enfant(cle_ext, chain_ext, i, False)

        afficher_bytes_detail(f"Clé privée finale :", cle_addr)

        signing = ecdsa.SigningKey.from_string(cle_addr, curve=ecdsa.SECP256k1)
        vk = signing.get_verifying_key()
        Kx = vk.pubkey.point.x()
        Ky = vk.pubkey.point.y()
        prefixe = b'\x02' if Ky % 2 == 0 else b'\x03'
        cle_pub = prefixe + Kx.to_bytes(32, "big")

        afficher_bytes_detail("Clé publique compressée :", cle_pub)

        # Hash160
        sha = hashlib.sha256(cle_pub).digest()
        ripe = hashlib.new("ripemd160", sha).digest()
        afficher_bytes_detail("SHA256(clé_pub) :", sha)
        afficher_bytes_detail("RIPEMD160(SHA256) = hash160 :", ripe)

        data_5bit = bech32.convertbits(ripe, 8, 5)
        adresse = bech32.bech32_encode("bc", [0] + data_5bit)
        print(f"\n  → Adresse Native SegWit : {adresse}")

    return cle_compte, chain_compte


# ════════════════════════════════════════════════════════════════
#  ÉTAPE 7 — CLÉ PUBLIQUE → ADRESSE NATIVE SEGWIT
# ════════════════════════════════════════════════════════════════

def etape_adresse(cle_pub):
    sep("ÉTAPE 7 — Clé publique → Adresse Native SegWit (Bech32)")

    print("""
  Pipeline de hachage : SHA256 → RIPEMD160 → Bech32

  Pourquoi deux algorithmes de hachage successifs ?
  - SHA256 seul : résistance aux collisions excellente, 32 bytes
  - RIPEMD160   : compresse à 20 bytes (adresse plus courte)
  - Les deux ensemble : si l'un est un jour compromis,
    l'autre protège toujours. Défense en profondeur.

  SHA256(clé_pub) → 32 bytes
  RIPEMD160(résultat) → 20 bytes  (= "pubkey hash" ou "hash160")

  ┌─────────────────────────────────────────────────────────┐
  │  ENCODAGE BECH32                                        │
  └─────────────────────────────────────────────────────────┘

  Bech32 encode les 20 bytes en une chaîne lisible :
  - HRP (Human Readable Part) = "bc" (Bitcoin mainnet)
  - Séparateur = "1"
  - witness version = 0 (P2WPKH = Pay to Witness Public Key Hash)
  - Les 20 bytes convertis de groupes de 8 bits → groupes de 5 bits
  - Checksum intégré (6 caractères finaux)
  - Alphabet sans ambiguïté : pas de 0/O, 1/l, majuscules exclues

  Résultat : bc1q + ~39 caractères
  "bc" = Bitcoin  "1" = séparateur  "q" = witness version 0 en base32
    """)

    sous_sep("Calcul pas à pas")
    afficher_bytes_detail("Clé publique compressée (entrée) :", cle_pub)

    sha256 = hashlib.sha256(cle_pub).digest()
    afficher_bytes_detail("SHA256(clé_pub) :", sha256)

    ripemd160 = hashlib.new("ripemd160", sha256).digest()
    afficher_bytes_detail("RIPEMD160(SHA256) = hash160 :", ripemd160)

    print(f"\n  Conversion en groupes de 5 bits pour Bech32 :")
    bits_20 = ''.join(f'{b:08b}' for b in ripemd160)
    print(f"  160 bits en entrée → 160 ÷ 5 = 32 groupes de 5 bits")
    groupes_5 = [bits_20[i:i+5] for i in range(0, len(bits_20), 5)]
    print(f"  {'  '.join(groupes_5[:8])}")
    print(f"  ... ({len(groupes_5)} groupes au total)")

    data_5bit = bech32.convertbits(ripemd160, 8, 5)
    adresse = bech32.bech32_encode("bc", [0] + data_5bit)

    print(f"\n  ┌────────────────────────────────────────────────┐")
    print(f"  │ Adresse finale : {adresse:<33}│")
    print(f"  └────────────────────────────────────────────────┘")
    print(f"\n  Décomposition :")
    print(f"  'bc'  → Human Readable Part (réseau Bitcoin mainnet)")
    print(f"  '1'   → séparateur Bech32")
    print(f"  'q'   → witness version 0 encodée en base32")
    print(f"  reste → hash160 encodé Bech32 + 6 chars de checksum")

    return adresse


# ════════════════════════════════════════════════════════════════
#  EXÉCUTION PRINCIPALE
# ════════════════════════════════════════════════════════════════

if __name__ == "__main__":

    print("\n" + "█" * 68)
    print("  BITCOIN HD WALLET — DÉMONSTRATION ÉDUCATIVE ULTRA-DÉTAILLÉE")
    print("  BIP39 + BIP32 + BIP84 → adresse Native SegWit bc1q")
    print("  ⚠️  Script éducatif — ne jamais utiliser avec de vrais fonds")
    print("█" * 68)

    # Pipeline complet
    entropie              = etape_entropie()
    mots                  = etape_mots(entropie)
    graine                = etape_graine(mots)
    cle_maitre, chain_m   = etape_cle_maitre(graine)
    cle_pub               = etape_courbe_elliptique(cle_maitre)
    cle_compte, chain_c   = etape_derivation(cle_maitre, chain_m)
    adresse               = etape_adresse(cle_pub)

    sep("RÉCAPITULATIF FINAL")
    print(f"""
  os.urandom(32)
      ↓  256 bits d'entropie (32 bytes aléatoires)
      ↓  + checksum 8 bits (SHA256) = 264 bits
      ↓  → 24 groupes de 11 bits → 24 mots BIP39

  24 mots
      ↓  PBKDF2-HMAC-SHA512 (2048 itérations)
      ↓  password=mots, salt="mnemonic"
  Graine 512 bits (64 bytes)

      ↓  HMAC-SHA512(key="Bitcoin seed", msg=graine)
      ↓  [0:32] = clé privée maître
      ↓  [32:64] = chain code maître
  Clé privée maître (32 bytes) + Chain code (32 bytes)

      ↓  Dérivations BIP32 : m/84'/0'/0'/0/index
      ↓  Chaque niveau : HMAC-SHA512(chain_parent, pub_parent+index)
      ↓  clé_enfant = (IL + clé_parent) mod n
  Clé privée de l'adresse (32 bytes)

      ↓  Multiplication scalaire k × G sur secp256k1
      ↓  G = point générateur universel
      ↓  Algorithme double-and-add (~256 opérations)
  Clé publique = point (Kx, Ky) → compressée (33 bytes)

      ↓  SHA256(clé_pub) → 32 bytes
      ↓  RIPEMD160(résultat) → 20 bytes (hash160)
      ↓  Bech32 encode (witness v0, hrp="bc")
  Adresse Native SegWit ✓  bc1q...

  Propriétés du système :
  • Déterministe  → mêmes 24 mots = mêmes adresses, partout
  • Irréversible  → impossible de remonter à la clé privée
  • Infini        → index illimité = adresses illimitées
  • Hiérarchique  → plusieurs comptes depuis une seule seed
  • Interopérable → standard ouvert, fonctionne sur tout wallet BIP39/44/84
    """)
