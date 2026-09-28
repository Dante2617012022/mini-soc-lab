# mini-soc-lab

Mini SOC / Blue Team lab with Wazuh, Suricata, YARA, VirusTotal, MITRE ATT&CK and nftables.

## Objetivo

Construir un laboratorio defensivo, reproducible y auditable que demuestre capacidades prácticas de Security Operations sin confundir un entorno de laboratorio con experiencia SOC de producción.

El proyecto parte de un diseño académico previo y lo convierte en una implementación controlada con gestión de cambios, evidencia verificable y decisiones de arquitectura basadas en riesgo.

## Alcance inicial

La primera versión separa responsabilidades entre máquinas virtuales:

```text
PC Dante / VirtualBox
└── SOC-ENDPOINT-01
    └── Debian 13
        ├── Wazuh Agent
        ├── SSH / authentication telemetry
        ├── File Integrity Monitoring
        ├── sudo / user activity
        └── YARA (fase posterior)

PC hermano / VirtualBox
├── SOC-MGMT-01
│   └── Ubuntu Server 24.04 LTS
│       ├── Wazuh Server
│       ├── Wazuh Indexer
│       └── Wazuh Dashboard
└── SOC-GW-01 (fase posterior)
    └── Debian
        ├── nftables
        ├── Suricata
        └── Wazuh Agent

Servicio externo
└── VirusTotal API (enriquecimiento por hash)
```

## Principios de diseño

- Hosts físicos usados principalmente como hipervisores.
- Wazuh como núcleo de detección, correlación e investigación.
- Suricata como NIDS en un gateway dedicado, no como control decorativo.
- nftables reemplaza el appliance MikroTik del diseño académico para este laboratorio.
- VirusTotal se trata como tercero externo: se priorizan consultas por hash y no se suben archivos privados.
- Detección y validación antes de automatizar bloqueos.
- Secretos, credenciales, PCAP y evidencia cruda no se versionan.
- La evidencia pública debe estar sanitizada y contextualizada.
- Graylog queda fuera de la primera versión para evitar una segunda plataforma de logs sin necesidad demostrada.

## Casos de uso previstos

1. Intentos fallidos de autenticación SSH y password guessing.
2. Cambios sobre archivos críticos mediante FIM.
3. Uso de sudo y cambios de cuentas privilegiadas.
4. Detecciones de red mediante Suricata y EVE JSON.
5. Detección con YARA y enriquecimiento por hash con VirusTotal.
6. Active Response con bloqueo temporal en nftables, únicamente después de validar falsos positivos y rollback.

## Flujo de trabajo

Los cambios se realizan mediante ramas pequeñas y pull requests. GitHub mantiene scripts, configuraciones y documentación; las VMs son el entorno de ejecución y UAT.

```text
objetivo → evaluación de riesgo → cambio mínimo → CI → UAT en VM → evidencia → merge
```

## Estado

**Fase 2 — hardening base y logging de SOC-ENDPOINT-01.**

El provisioning de `SOC-ENDPOINT-01` fue validado y cerrado mediante CHG-002. CHG-003 establece hardening mínimo de SSH y persistencia acotada de logs antes de desplegar el Wazuh Agent.

## Seguridad y uso autorizado

Este repositorio documenta un laboratorio propio y controlado. Las pruebas deben ejecutarse únicamente sobre sistemas y redes autorizados. No se publican secretos, credenciales, datos personales, direcciones internas innecesarias ni capturas sin sanitizar.
