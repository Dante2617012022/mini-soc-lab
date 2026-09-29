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

**Fase 5 — Wazuh central operativo; integración del endpoint pendiente.**

CHG-002 a CHG-004 dejaron `SOC-ENDPOINT-01` provisionado, endurecido y con telemetría real validada. CHG-005 provisionó `SOC-MGMT-01` sobre Ubuntu Server 24.04 LTS y estableció un baseline verificable con rollback. CHG-006 confirmó de forma read-only que el endpoint sigue listo para un despliegue controlado del Wazuh Agent.

CHG-007 instaló y validó Wazuh 4.14.8 en modo all-in-one sobre `SOC-MGMT-01`, con manager, indexer, dashboard y Filebeat operativos. El acceso de UAT al dashboard se realizó mediante un forward temporal restringido a loopback, luego retirado; la credencial inicial de administración fue rotada, el repositorio Wazuh quedó deshabilitado para evitar upgrades accidentales y se creó el snapshot `WAZUH-CENTRAL-READY`.

El próximo cambio conectará `SOC-ENDPOINT-01` con el manager y validará el primer flujo end-to-end de telemetría y detección. La conectividad entre hosts físicos se diseñará explícitamente antes de exponer servicios del manager.

## Seguridad y uso autorizado

Este repositorio documenta un laboratorio propio y controlado. Las pruebas deben ejecutarse únicamente sobre sistemas y redes autorizados. No se publican secretos, credenciales, datos personales, direcciones internas innecesarias ni capturas sin sanitizar.
