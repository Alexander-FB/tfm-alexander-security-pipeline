# Seguridad en contenedores - Pipeline de seguridad

Proyecto desarrollado como parte del Trabajo Fin de Máster de Formación Permanente en Ciberseguridad y Seguridad de la Información de la Universidad de Castilla-La Mancha.

## Descripción

Este repositorio contiene los workflows, scripts y criterios utilizados para automatizar el análisis y hardening de aplicaciones desplegadas mediante Docker y Docker Compose.

La implementación permite analizar una configuración inicial, procesar los resultados obtenidos, aplicar un conjunto definido de medidas de hardening y repetir posteriormente las mismas comprobaciones sobre el entorno reconstruido.

La lógica se mantiene en un repositorio independiente para evitar incluir los scripts y criterios de seguridad dentro de cada aplicación que utilice el pipeline.

## Funcionalidades

El pipeline incluye:

- Generación de SBOM mediante Syft.
- Análisis de vulnerabilidades y configuración mediante Trivy.
- Revisión de Docker Compose mediante DCLint.
- Comprobaciones sobre los contenedores en runtime.
- Evaluación de los resultados mediante una política de seguridad.
- Aplicación automática de remediaciones definidas.
- Reconstrucción y reevaluación del entorno.
- Generación de informes y evidencias.
- Validación final mediante un security gate.
- Revalidación y publicación de releases.

## Flujo de seguridad

El análisis asociado a una pull request se divide en cuatro fases principales:

1. **Baseline Audit**: construye y analiza la configuración recibida.
2. **Apply hardening**: aplica las remediaciones disponibles cuando son necesarias.
3. **Hardened validation**: reconstruye el entorno y repite las comprobaciones.
4. **Security gate**: evalúa las evidencias obtenidas y determina el resultado final.

Si el baseline cumple directamente los criterios definidos, las fases de remediación y reevaluación no son necesarias.

## Política de seguridad

La política utilizada por el pipeline se encuentra en:

```text
.github/actions/container-security/policy/container-security-policy.yml
```

En este fichero se definen tanto algunos de los valores utilizados durante el hardening como los criterios que determinan qué hallazgos deben bloquear una ejecución.

La remediación se limita a cambios definidos previamente. Los problemas que no pueden corregirse automáticamente permanecen registrados en las evidencias generadas.

## Scripts

Los scripts desarrollados en Python se encuentran dentro de:

```text
.github/actions/container-security/scripts
```

Los principales son:

- `assess.py`: evalúa los resultados frente a la política.
- `remediate.py`: aplica las modificaciones de hardening sobre la aplicación y su configuración.
- `remediate_nginx.py`: gestiona los cambios correspondientes a la imagen de Nginx.
- `runtime_checks.py`: realiza comprobaciones sobre los contenedores en ejecución.
- `report.py`: procesa las evidencias y genera el informe de resultados.
- `nginx_report.py`: procesa los resultados específicos de Nginx.

Los pasos comunes utilizados por las distintas fases se agrupan en `action.yml`.

## Workflows

El repositorio contiene dos workflows reutilizables:

- `container-security.yml`: utilizado durante el análisis de pull requests.
- `container-release.yml`: utilizado durante la validación y publicación de releases.

## Release y AWS

Antes de publicar una nueva versión se vuelven a ejecutar las comprobaciones de seguridad sobre el commit integrado.

Si la validación termina correctamente, la imagen se publica en Amazon ECR y las evidencias de la ejecución se almacenan en Amazon S3.

La autenticación con AWS se realiza mediante OIDC, sin necesidad de almacenar credenciales permanentes en los repositorios.

## Estructura del repositorio

```text
tfm-alexander-security-pipeline/
├── .github/
│   ├── actions/
│   │   └── container-security/
│   │       ├── policy/
│   │       │   └── container-security-policy.yml
│   │       ├── scripts/
│   │       │   ├── assess.py
│   │       │   ├── nginx_report.py
│   │       │   ├── remediate.py
│   │       │   ├── remediate_nginx.py
│   │       │   ├── report.py
│   │       │   └── runtime_checks.py
│   │       ├── action.yml
│   │       └── requirements.txt
│   └── workflows/
│       ├── container-release.yml
│       └── container-security.yml
├── .gitignore
└── README.md
```