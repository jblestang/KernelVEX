# Liaison du noyau au SBOM produit (CRA & OpenVEX 0.2.0)

Pour satisfaire aux exigences de traçabilité du **Cyber Resilience Act (CRA)**, chaque document `openvex.json` émis par `kernelvex` doit pointer sans ambiguïté vers le composant noyau figurant dans le SBOM (SPDX ou CycloneDX) du firmware, de l'image ou de la VM livrée.

---

## 1. Construction du PURL noyau dans `kernelvex`

Chaque statement OpenVEX inclut un bloc `products` contenant l'identifiant `@id` et `identifiers.purl` :

1. **Par défaut (dérivation automatique) :**
   - Profil `cip` (`https://gitlab.com/cip-project/cip-kernel/linux-cip`) :
     ```text
     pkg:gitlab/cip-project/cip-kernel/linux-cip@v5.10.224-cip52?arch=x86_64&config=cip_merged_defconfig
     ```
   - Profil `standard` (`https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux.git`) :
     ```text
     pkg:generic/kernel.org/linux@5.15.165?arch=x86_64&config=.config
     ```
2. **Surcharge explicite (`--product-purl`) :**
   Utilisez `--product-purl` dès que le SBOM produit utilise un PURL spécifique (distro Debian/Ubuntu, Yocto `linux-yocto`, vendor BSP) afin d'assurer une jointure exacte 1:1 par des outils aval (Dependency-Track, Grype, vexctl, GUAC).

```bash
kernelvex ci pipeline \
  --profile standard \
  --kernel-version 5.15.165 \
  --kernel-config artifacts/.config \
  --kernel-source "${LINUX_SRC}" \
  --product-purl "pkg:yocto/poky/linux-yocto@5.15.165?machine=qemux86-64" \
  --output vex/openvex.json
```

---

## 2. Rattachement à un SBOM CycloneDX ou SPDX

### CycloneDX (1.5 / 1.6)
Dans le SBOM produit, vérifiez que le composant noyau (`type: "operating-system"` ou `"library"`) porte exactement la même valeur `purl` (et idéalement `cpe` si applicable) :

```json
{
  "type": "library",
  "name": "linux-cip",
  "version": "v5.10.224-cip52",
  "purl": "pkg:gitlab/cip-project/cip-kernel/linux-cip@v5.10.224-cip52?arch=x86_64&config=cip_merged_defconfig"
}
```

### SPDX (2.3 / 3.0)
Dans un document SPDX 2.3, alignez l'`externalRefs` `PACKAGE-MANAGER` / `purl` du package noyau (`linux-cip` / `linux-yocto` / `linux-image-*`) avec la valeur passée à `--product-purl`, et référencez la provenance de build (`sec_commit`, `kernel_source_commit`, `kernel_config_sha256`) présente dans le bloc `meta` d'OpenVEX.

---

## 3. Périmètre clair vs `sbom-cve-check` et `vex-kernel-checker`

- **Noyau Linux (`kernelvex` → OpenVEX) :** `kernelvex` évalue uniquement les CVE noyau via `cip-kernel-sec` + `kernel-cve-triage` + `kmax` avec preuves de compilation.
- **Composants userspace (`bootlin/sbom-cve-check`) :** à exécuter séparément sur le SBOM SPDX complet pour les paquets applicatifs/librairies userspace, sans fusionner aveuglément ses statuts noyau non vérifiés par Kbuild/kmax avec les preuves compile-time d'`openvex.json`.
- **Post-traitement optionnel (`Laerdal/vex-kernel-checker`) :** peut être chaîné *après* `kernelvex` si des règles d'enrichissement complémentaires sont nécessaires en aval, sans dupliquer la logique de triage.
