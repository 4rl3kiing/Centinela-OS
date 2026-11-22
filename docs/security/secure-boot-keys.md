# Claves de Secure Boot: separacion dev / test / produccion

`scripts/build-iso.sh` selecciona el perfil con `CENTINELA_PROFILE` (por defecto `dev`).

| Perfil | Firma | Claves | Comportamiento |
|---|---|---|---|
| `dev` | opcional | ninguna o de prueba | Sin `SB_SIGNING_KEY`/`SB_SIGNING_CERT` produce imagen sin firmar. |
| `test` | obligatoria | efimeras de `scripts/secure-boot-keys.sh` (CN "TEST") | Falla sin clave/certificado o sin `sbsign`; verifica con `sbverify` si existe. CI usa este perfil. |
| `production` | obligatoria y verificada | solo claves de la propietaria de la release, offline | Falla sin clave, certificado, `sbsign`, `sbverify` u `openssl`; rechaza certificados con "TEST"; verifica todos los EFI firmados (ISO, imagen ESP e instalado). |

Reglas: las claves de prueba nunca firman artefactos de produccion; las privadas de produccion no se guardan en el repositorio ni en CI compartido y se generan y custodian offline; una imagen `dev` no es distribuible.
