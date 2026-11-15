# Upstream Provenance of Real Test Fixtures

Zero synthetic or fictional CVEs exist anywhere in this directory. Every fixture
was retrieved directly from upstream CIP repositories at pinned commits:

| Artifact | Source Repository | Pinned Commit / Ref |
| :--- | :--- | :--- |
| `sec/issues/CVE-2024-*.yml` | `https://gitlab.com/cip-project/cip-kernel/cip-kernel-sec.git` | `831c5301e4a829957117f47cfd7b388d99037a6a` |
| `configs/5.10.y-cip_x86_cip_merged_defconfig` | `https://gitlab.com/cip-project/cip-kernel/cip-kernel-config.git` | `3df75973c690a4b433e8580e16c175e1fd959b63` |
| `configs/5.15.y_x86_cip_merged_defconfig` | `https://gitlab.com/cip-project/cip-kernel/cip-kernel-config.git` | `3df75973c690a4b433e8580e16c175e1fd959b63` |
| `reports/cve_triage_v5.10.224-cip52_report.json` | Assembled from exact check outputs recorded in `kernel-cve-triage` `tests/data/v5.10.224-cip52/cip_merged_defconfig/` | `3aa04484d7b0e58331d3da4b2aef78376f23de55` |
| Target kernel tag commit (`v5.10.224-cip52`) | `https://gitlab.com/cip-project/cip-kernel/linux-cip.git` | `a73978e16f87d704893e4b3a637be257420d43f3` |
