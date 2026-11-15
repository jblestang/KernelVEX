# KernelVEX — Orchestrateur industriel CVE noyau & OpenVEX 0.2.0

**KernelVEX** est une fine couche d'orchestration CI/CD qui compose directement les briques open source éprouvées pour le triage CVE du noyau Linux (profils **CIP SLTS** et **Linux standard/stable/distro**) et la génération d'attestations **OpenVEX v0.2.0** conformes aux exigences **CRA** (*Cyber Resilience Act*).

> **Principe directeur :** *juger le build effectif (`.config` + arbre source exact), pas le numéro de version seul.*

---

## 1. Pile OSS composée (aucune réimplémentation)

Les versions exactes sont épinglées dans [PINS.lock](PINS.lock) :

| Rôle | Brique OSS | Usage dans KernelVEX |
| :--- | :--- | :--- |
| Source de vérité CVE | [`cip-kernel-sec`](https://gitlab.com/cip-project/cip-kernel/cip-kernel-sec) | Clonée/mise à jour via `catalog refresh`, YAML `issues/CVE-*.yml` |
| Moteur de triage | [`kernel-cve-triage`](https://gitlab.com/cip-project/cip-kernel/kernel-cve-triage) (`cve-triage`) | Exécuté en sous-processus pour `triage` (`analyze full`) et `enrich` |
| Analyse Kbuild / compile-time | [`kmax`](https://github.com/paulgazz/kmax) (`kmaxall` / `kreader`) | Appelé **exclusivement via** `cve-triage` avec cache persistant `.kmax` |
| Format conformité | [OpenVEX v0.2.0](https://openvex.dev/) | Validé par JSON Schema (`schemas/openvex_v0.2.0_meta.schema.json`) |

**Hors périmètre / interdit :** aucune réimplémentation de `kmax`, aucun parseur Kbuild maison, aucune base CVE parallèle ni CVE fictive.

---

## 2. Architecture

```text
┌─────────────────────────────────────────────────────────────┐
│  kernelvex CLI / pipeline CI (orchestration & audit trail)  │
├─────────────────────────────────────────────────────────────┤
│  catalog refresh       → git cip-kernel-sec + catalog.json  │
│  catalog merge-enrich  → fusion affected-files / configs    │
│  analyze quick         → version + .config + catalog        │
│  analyze full          → cve-triage triage + cache .kmax    │
│  vex emit              → OpenVEX 0.2.0 + bloc meta CRA      │
│  ci pipeline           → enchaînement + codes sortie CI     │
└─────────────────────────────────────────────────────────────┘
         │                    │                    │
         ▼                    ▼                    ▼
   cip-kernel-sec      kernel-cve-triage         kmax
```

---

## 3. Entrées utilisateur — uniquement du standard

En production, `kernelvex` n'accepte **que des artefacts standards de build** :

| Entrée | Obligatoire | Description |
| :--- | :--- | :--- |
| `--kernel-version` | Toujours | Tag ou version noyau effective (`v5.10.224-cip52`, `5.15.165`, `uname -r`) |
| `--kernel-config` | Toujours | Fichier `.config` effectif du build ou export `/proc/config.gz` (décompressé automatiquement) |
| `--kernel-source` | Mode `full` | Checkout git **complet en historique et tags** à la même révision que le build |
| `--stable-branch` | Recommandé | Branche cible dans `cip-kernel-sec` (`cip/5.10`, `stable/5.15`, déduite par défaut) |

**Jamais en production :** pas de catalogue JSON artisanal maintenu à la main (règles Kconfig ad hoc), pas d'entrées fictives, pas de fixtures synthétiques.

---

## 4. Profils `cip` vs `standard`

La même CLI et la même image OCI supportent les deux cibles sans duplication :

| Critère | Profil `cip` | Profil `standard` |
| :--- | :--- | :--- |
| Détection auto | Tag contenant `*-cip*` ou `*-st*`, ou `--stable-branch cip/*` | Tout autre tag/version |
| Forçage explicite | `--profile cip` | `--profile standard` |
| Drapeau `cve-triage` | Passe `--cip` à `cve-triage triage` | Sans `--cip` |
| Filtrage catalogue | Entrées `mainline`, `stable/*` et `cip/*` | Ignore les entrées exclusivement `cip/*` |
| PURL par défaut | `pkg:gitlab/cip-project/cip-kernel/linux-cip@<ver>` | `pkg:generic/kernel.org/linux@<ver>` |

> Pour l'utilisation détaillée sur des noyaux **non-CIP** (`kernel.org` mainline/stable, `linux-yocto`, BSP constructeur arm64/x86, ou noyaux distro via `/proc/config.gz`), consultez [docs/non-cip-kernels.md](docs/non-cip-kernels.md).

---

## 5. Contrat CLI & Modes d'exécution

```bash
# 1. Synchroniser cip-kernel-sec dans le cache (/cache ou .cache/kernelvex)
kernelvex catalog refresh

# 2. (Optionnel) Enrichir avec les formules Kconfig de cve-triage enrich
kernelvex enrich --kernel-source /src/linux-cip --versions v5.10 --out-dir ./enriched --cve-since-year 2024
kernelvex catalog merge-enrich --enriched-dir ./enriched

# 3a. Triage rapide sans sources noyau (conservateur : CONFIG actif -> under_investigation)
kernelvex analyze quick \
  --kernel-version v5.10.224-cip52 \
  --kernel-config artifacts/.config \
  --cve-since-year 2024 \
  --output report.quick.json

# 3b. Triage complet avec preuve compile-time via cve-triage + kmax
kernelvex analyze full \
  --profile cip \
  --kernel-version v5.10.224-cip52 \
  --kernel-config artifacts/.config \
  --kernel-source /src/linux-cip \
  --stable-branch cip/5.10 \
  --cve-since-year 2024 \
  --output report.full.json

# 4. Émission OpenVEX 0.2.0 validée par schéma
kernelvex vex emit \
  --kernel-version v5.10.224-cip52 \
  --kernel-config artifacts/.config \
  --report report.full.json \
  --author "Product Security Team" \
  --output vex/openvex.json
```

### Exécution CI tout-en-un (`ci pipeline`)

**Profil `cip` :**

```bash
kernelvex ci pipeline \
  --profile cip \
  --kernel-version "${KERNEL_VERSION}" \
  --kernel-config artifacts/.config \
  --kernel-source "${LINUX_SRC}" \
  --stable-branch stable/5.15 \
  --mode full \
  --cve-since-year 2024 \
  --output vex/openvex.json
```

**Profil `standard` (noyau `stable/5.15`, sans `--cip`) :**

```bash
kernelvex ci pipeline \
  --profile standard \
  --kernel-version "5.15.165" \
  --kernel-config artifacts/.config \
  --kernel-source "${LINUX_STABLE_SRC}" \
  --stable-branch stable/5.15 \
  --mode full \
  --cve-since-year 2024 \
  --output vex/openvex-standard.json
```

### Codes de sortie CI

| Code | Signification | Usage CI recommandé |
| :---: | :--- | :--- |
| `0` | Succès, zéro CVE ouverte (`under_investigation` ou `affected`) | Succès strict |
| `10` | Triage ouvert (`>= 1` CVE `under_investigation` ou `affected`, sans violation `--fail-on`) | `allow_failure: exit_codes: [10]` en job consultatif |
| `20` | Échec outil/entrée (fichier manquant, binaire absent, erreur git/kmax, schéma invalide) | Échec bloquant |
| `30` | Politique non respectée (`--fail-on under_investigation` ou `--fail-on affected`) | Porte de release (release gate) |

---

## 6. Performance & Cache `kmax`

La génération initiale des formules `kmaxall` sur l'arbre Linux complet (première exécution pour une révision donnée) est l'étape la plus coûteuse :

- **1er run (cache froid) :** ~15 à 45 minutes selon le CPU et le nombre de cœurs (génère `<cache_dir>/kmax/<profile>-<commit12>-<arch>.kmax`).
- **Runs suivants (cache chaud) :** `cve-triage` réutilise directement le fichier `.kmax` persisté via `--kmax-formulas` (typiquement **5 à 30 secondes** pour un sous-ensemble annuel de CVE).
- **Important :** `--kernel-source` doit contenir les **tags git** (`git fetch --tags`) et l'historique des commits (clone complet ou `--filter=blob:none`, pas `--depth 1`) afin que `git describe` et `git merge-base --is-ancestor` fonctionnent dans `cve-triage`.

---

## 7. Image OCI (non-root) & Installation bare metal

### Image OCI (Docker ou Podman rootless)

```bash
# Avec Docker :
docker build -t kernelvex:0.1.0 .
docker run --rm \
  -v "$PWD/cache:/cache" \
  -v "$PWD/sources:/sources:ro" \
  -v "$PWD/out:/out" \
  kernelvex:0.1.0 ci pipeline \
    --profile standard \
    --kernel-version 5.15.165 \
    --kernel-config /sources/.config \
    --kernel-source /sources/linux-stable \
    --stable-branch stable/5.15 \
    --mode full \
    --output /out/openvex.json

# Avec Podman rootless (Linux ou macOS Podman Machine) :
podman run --rm --userns=keep-id:uid=10001,gid=10001 \
  -v "$PWD/cache:/cache" \
  -v "$PWD/sources:/sources:ro" \
  -v "$PWD/out:/out" \
  kernelvex:0.1.0 ci pipeline \
    --profile cip \
    --kernel-version v5.10.224-cip52 \
    --kernel-config /sources/.config \
    --kernel-source /sources/linux-cip \
    --mode full \
    --output /out/openvex.json
```

L'image s'exécute sous l'utilisateur non-root `kernelvex` (`uid=10001`), inclut `clang`/`lld` et les cross-compilateurs GNU `x86_64`/`arm64`, monte `/cache` pour persister `cip-kernel-sec` et les formules `.kmax`, et fonctionne avec un montage `/sources:ro` (checkout isolé en `tmp` via worktree/shared clone).

### Installation bare metal (runner Linux Ubuntu 24.04)

```bash
sudo apt-get update && sudo apt-get install -y \
  build-essential git clang lld llvm libclang-dev clang-tools flex bison bc libssl-dev libelf-dev python3-venv
python3 -m venv /opt/kernelvex && source /opt/kernelvex/bin/activate
pip install -U "pip>=25.1" "setuptools<82"
printf 'setuptools<82\n' > /tmp/build-constraints.txt
pip install --build-constraint /tmp/build-constraints.txt \
  "kmax==4.10" \
  "git+https://gitlab.com/cip-project/cip-kernel/kernel-cve-triage.git@3aa04484d7b0e58331d3da4b2aef78376f23de55"
pip install .
```

### Exemples CI & documentation complémentaire

- Guide noyaux **non-CIP** (mainline, stable, Yocto, BSP, distro) : [docs/non-cip-kernels.md](docs/non-cip-kernels.md)
- GitLab CI : [ci/gitlab-ci.example.yml](ci/gitlab-ci.example.yml)
- GitHub Actions : [ci/github-actions.example.yml](ci/github-actions.example.yml)
- Liaison PURL / SBOM (CRA) : [docs/sbom-purl-linking.md](docs/sbom-purl-linking.md)
- Vérification `full` sous Linux/OCI (Docker & Podman) : [scripts/verify_full_linux.sh](scripts/verify_full_linux.sh)
