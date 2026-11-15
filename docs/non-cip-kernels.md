# Guide d'utilisation de KernelVEX sur un noyau Linux non-CIP

Bien que la source CVE par défaut ([`cip-kernel-sec`](https://gitlab.com/cip-project/cip-kernel/cip-kernel-sec)) soit hébergée par le projet CIP, elle recense **toutes les CVE du noyau Linux** avec leurs commits d'introduction et de correction sur `mainline` et l'ensemble des branches `stable/X.Y` (`kernel.org`).

**KernelVEX** traite n'importe quel noyau Linux non-CIP (mainline, `kernel.org` stable, `linux-yocto`, BSP constructeur ou noyau de distribution) avec **la même CLI et la même image OCI**, sans dupliquer de pipeline.

---

## 1. Fonctionnement du profil `standard` (hors CIP)

La sélection s'effectue automatiquement dès que `--kernel-version` ne contient ni `-cip` ni `-st` et que `--stable-branch` ne commence pas par `cip/` — ou explicitement avec `--profile standard` :

- **Pas de drapeau `--cip` :** `kernelvex` invoque `cve-triage triage` **sans** `--cip`.
- **Filtrage du catalogue :** les CVE exclusivement spécifiques aux branches CIP sont ignorées ; seules les données `mainline` et `stable/<X.Y>` sont évaluées.
- **Déduction de branche :** `--kernel-version 5.15.165` ou `6.1.112-rt43` déduit automatiquement `--stable-branch stable/5.15` ou `stable/6.1` (surchargeable pour `mainline` ou un arbre vendor).
- **Métadonnées OpenVEX :** `meta.profile` vaut `"standard"` et `meta.stable_branch` reflète la branche suivie.

---

## 2. Scénario A — Noyau `kernel.org` `stable` ou `mainline`

### Option 1 : Analyse complète (`mode full`, preuve compile-time `kmax`)

Recommandée pour un produit industriel / CRA. Fournir la version, le `.config` effectif (ou `/proc/config.gz`) et le checkout git complet de l'arbre Linux :

```bash
# 1. Mettre à jour le catalogue cip-kernel-sec (une fois par run CI ou via volume /cache)
kernelvex catalog refresh

# 2. Triage complet sur stable 6.6.y (ou 5.15.y / 6.1.y / mainline)
kernelvex ci pipeline \
  --profile standard \
  --kernel-version "6.6.60" \
  --kernel-config artifacts/.config \
  --kernel-source /src/linux-stable \
  --stable-branch stable/6.6 \
  --mode full \
  --cve-since-year 2024 \
  --author "Product Security Team" \
  --output vex/openvex-6.6.60.json
```

Pour un noyau **mainline** (ex. `v6.12-rc3` ou `6.12`), passez `--stable-branch mainline` :

```bash
kernelvex ci pipeline \
  --profile standard \
  --kernel-version "v6.12" \
  --kernel-config artifacts/.config \
  --kernel-source /src/linux-mainline \
  --stable-branch mainline \
  --mode full \
  --cve-since-year 2024 \
  --output vex/openvex-mainline.json
```

### Option 2 : Analyse rapide sans sources (`mode quick`)

Utile en étape PR rapide ou lorsque le dépôt source complet n'est pas monté sur le runner. Toute CVE dont le symbole Kconfig est actif (ou non exclu par plage de versions) reste prudemment en `under_investigation` :

```bash
kernelvex ci pipeline \
  --profile standard \
  --kernel-version "5.15.165" \
  --kernel-config artifacts/.config \
  --stable-branch stable/5.15 \
  --mode quick \
  --cve-since-year 2024 \
  --output vex/openvex-quick.json
```

---

## 3. Scénario B — Noyau Yocto (`linux-yocto`), BSP constructeur (NXP, TI, ST, Xilinx) ou fork interne

Les noyaux embarqués industriels utilisent souvent des numéros de version personnalisés (`uname -r` du type `6.1.83-ti-rt-g1a2b3c4`, `5.15.148+yocto-standard`) ou des forks git internes.

### Correspondance version, révision git et branche stable

Séparez la version sémantique évaluée dans `cip-kernel-sec` (`--kernel-version`), la révision git exacte de votre arbre (`--kernel-rev`) et la branche stable amont correspondante (`--stable-branch`) :

```bash
kernelvex ci pipeline \
  --profile standard \
  --kernel-version "6.1.83" \
  --kernel-rev "my-bsp-rel-2026.02" \
  --kernel-config build/tmp/work/.../linux-imx/.config \
  --kernel-source /src/linux-imx \
  --stable-branch stable/6.1 \
  --kernel-url "https://git.internal.corp/bsp/linux-imx.git" \
  --product-purl "pkg:yocto/poky/linux-imx@6.1.83?machine=imx8mp-evk" \
  --mode full \
  --cve-since-year 2024 \
  --output vex/openvex-imx8mp.json
```

**Comportement important sur fork BSP :**

- Si votre fork a intégré les correctifs `stable/6.1` par *cherry-pick* ou *merge* tout en conservant les commits d'origine ou une ancestralité git propre, `cve-triage` détecte les commits `fixed-by` présents dans l'historique (`fixed`).
- Si un correctif a été ré-appliqué avec un nouveau SHA sans lien d'ancestralité ni tag, `cve-triage` évalue tout de même si les fichiers touchés sont compilés via `kmax` + `.config` (`not_affected` si non compilés, sinon `under_investigation` afin de ne jamais produire de faux négatif).

### Prérequis Git impératifs en mode `full`

1. **Tags annotés amont présents :** `cve-triage` appelle `git describe --abbrev=0 <rev>` (sans `--tags`). Vérifiez que votre fork contient les tags de version Linux :
   ```bash
   git -C /src/linux-vendor remote add upstream https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux.git
   git -C /src/linux-vendor fetch upstream --tags
   ```
   `kernelvex` valide `git describe --abbrev=0` dès le démarrage et échoue proprement (code `20`) si un tag manque.
2. **Historique de commits complet (pas `--depth 1`) :** l'ancestralité git requiert l'historique des commits.
3. **Montage lecture seule (`:ro`) vs clone partiel (`--filter=blob:none`) :**
   - Avec un clone complet, `/sources` peut être monté en lecture seule (`:ro`) dès le 1er lancement : `kernelvex` bascule automatiquement de `git worktree add` vers `git clone --shared` en répertoire temporaire.
   - Avec un clone partiel `--filter=blob:none` (ex. miroir GitLab/GitHub), le **premier run à froid** peut nécessiter un accès écriture sur `.git` afin que GitPython télécharge à la demande les blobs des commits `introduced-by` avant de monter `:ro` sur les runs suivants.

### Cross-compilation automatique (`arm64`, `arm`, `riscv` ↔ `x86_64`)

En mode `full`, `cve-triage` exécute `make KCONFIG_ALLCONFIG=... alldefconfig`. Si l'architecture du `.config` cible diffère de celle du runner CI (ex. noyau `arm64` analysé sur un runner GitLab `x86_64`, ou noyau `x86_64` analysé via Podman sur Mac Apple Silicon `arm64`), `kernelvex` configure automatiquement `ARCH` puis :

1. Respecte toute variable explicite (`ARCH`, `CROSS_COMPILE`, `CC`, `LLVM`) déjà définie dans l'environnement du runner.
2. Sinon, sélectionne le préfixe GNU installé (`x86_64-linux-gnu-`, `aarch64-linux-gnu-`, `arm-linux-gnueabihf-`, `riscv64-linux-gnu-`, `powerpc64le-linux-gnu-`, `s390x-linux-gnu-`) dès que `<prefix>gcc` est présent (l'image OCI inclut `gcc-x86-64-linux-gnu`, `gcc-aarch64-linux-gnu`, `clang` et `lld`).
3. À défaut de cross-compilateur GNU (ex. `riscv` ou `arm` dans l'image générique), active `LLVM=1` dès que `clang` et `ld.lld` sont disponibles.

---

## 4. Scénario C — Noyau de distribution (Debian, Ubuntu, RHEL) ou audit binaire (`/proc/config.gz`)

Sur un produit livré dont le noyau provient d'une distribution Linux, il n'existe généralement pas d'arbre git avec les SHA exactement alignés sur `cip-kernel-sec` (les correctifs étant appliqués par patches `.deb`/`.rpm` backportés).

1. **Extraction directe de la configuration active :**
   ```bash
   # Depuis une cible Linux ou un artefact de build (/boot/config-*)
   cp /proc/config.gz artifacts/config.gz
   uname -r   # ex: 6.1.0-28-amd64
   ```
2. **Triage conservateur par Kconfig (`analyze quick`) :**
   ```bash
   kernelvex ci pipeline \
     --profile standard \
     --kernel-version "6.1.119" \
     --kernel-config artifacts/config.gz \
     --stable-branch stable/6.1 \
     --mode quick \
     --product-purl "pkg:deb/debian/linux-image-amd64@6.1.119-1?arch=amd64" \
     --cve-since-year 2024 \
     --output vex/openvex-debian.json
   ```
   - Les CVE dont le sous-système Kconfig est désactivé (`CONFIG_*` absent) ou déjà corrigées en amont avant la version de base sont marquées `not_affected` / `fixed`.
   - Les CVE potentiellement concernées restent `under_investigation` et doivent être croisées avec le tracker sécurité de la distribution (Ubuntu USN, Debian Security Tracker).

---

## 5. Liaison PURL / SBOM hors CIP

En profil `standard`, `kernelvex` normalise les URLs `kernel.org` vers un PURL lisible :

```text
pkg:generic/kernel.org/linux@5.15.165?arch=x86_64&config=.config
```

Dès que votre produit possède un SBOM CycloneDX ou SPDX référençant un paquet distro, Yocto ou vendor (`linux-yocto`, `linux-image-*`, `linux-imx`), imposez systématiquement l'identifiant exact via `--product-purl` (voir [docs/sbom-purl-linking.md](sbom-purl-linking.md)).

---

## 6. Exécution avec Podman (macOS & Linux rootless) ou Docker

L'image OCI exécute le conteneur sous l'utilisateur non-root `kernelvex` (`uid=10001`, `gid=10001`).

### Podman rootless (macOS Apple Silicon / Linux rootless)

Utilisez `--userns=keep-id:uid=10001,gid=10001` pour que les répertoires montés appartiennent à `uid=10001` à l'intérieur du conteneur (et utilisez un chemin sous `/private/tmp/...` ou `$PWD/...` sur macOS pour correspondre aux montages VirtioFS de la VM Podman) :

```bash
podman build -t kernelvex:0.1.0 .

mkdir -p "$PWD/cache" "$PWD/out"
podman run --rm \
  --userns=keep-id:uid=10001,gid=10001 \
  -v "$PWD/cache:/cache" \
  -v "$PWD/linux-stable:/sources/linux-stable:ro" \
  -v "$PWD/artifacts:/artifacts:ro" \
  -v "$PWD/out:/out" \
  kernelvex:0.1.0 ci pipeline \
    --profile standard \
    --kernel-version "5.15.165" \
    --kernel-config /artifacts/.config \
    --kernel-source /sources/linux-stable \
    --stable-branch stable/5.15 \
    --mode full \
    --jobs 2 \
    --cve-since-year 2024 \
    --output /out/openvex-standard.json
```

### Docker (CI Linux)

```bash
docker build -t kernelvex:0.1.0 .
docker run --rm \
  -v "$PWD/cache:/cache" \
  -v "$PWD/linux-stable:/sources/linux-stable:ro" \
  -v "$PWD/artifacts:/artifacts:ro" \
  -v "$PWD/out:/out" \
  kernelvex:0.1.0 ci pipeline \
    --profile standard \
    --kernel-version "5.15.165" \
    --kernel-config /artifacts/.config \
    --kernel-source /sources/linux-stable \
    --stable-branch stable/5.15 \
    --mode full \
    --cve-since-year 2024 \
    --output /out/openvex-standard.json
```
