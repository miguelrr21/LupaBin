# Comprobar una distribución de LupaBin

*English summary at the end.*

## Comprobar la distribución 0.15.0

Este es un procedimiento pendiente de ejecución sobre los artefactos definitivos, no una certificación de resultados. Usa la misma revisión integrada para el host, el wheel, el sdist y la imagen `lupabin-worker:0.15.0`. No reutilices artefactos de otra revisión aunque tengan igual número de versión. Reserva un turno con memoria disponible y ejecuta cada paso secuencialmente; detente si falla. No ejecutes los archivos PE generados por las pruebas.

Desde el repositorio, con Python 3.12 y un entorno de pruebas ya preparado. Las órdenes de pytest usan `--no-sync` para reutilizarlo sin instalar todo el grupo de desarrollo. Los entornos finales de CLI/web solo reciben las dependencias de ejecución exportadas con `--no-dev --extra web`: no necesitan pre-commit ni virtualenv.

```text
uv lock --check --offline --no-build --no-python-downloads
uv run --frozen --no-sync pytest -q tests/test_triage.py tests/test_web_example.py
uv build --out-dir dist/verify-0.15.0
```

La carpeta de salida debe ser nueva. En Bash, comprueba los dos artefactos y sus recursos (lectores de triaje y recursos PE, glosario, YARA, Java de Ghidra y ejemplo web):

```bash
export LUPABIN_DISTRIBUTIONS="$PWD/dist/verify-0.15.0"
uv run --frozen --no-sync --with hatchling==1.27.0 pytest -q tests/test_package.py
uv export --frozen --no-dev --extra web --no-emit-project --format requirements-txt --output-file dist/verify-0.15.0/dependencies.txt
```

Las pruebas que requieren Hatchling o `LUPABIN_DISTRIBUTIONS` no deben quedar omitidas en la verificación definitiva: si aparece un *skip*, falta ese requisito. La construcción del sdist con Hatchling se prueba aparte de la inspección de los artefactos. No se publican paquetes con estos comandos.

Instala después el wheel y el sdist, uno cada vez, en dos entornos nuevos **sin modo editable**, usando las dependencias exportadas del mismo lock. Este ejemplo Bash para Linux/macOS no activa ni sustituye el entorno de desarrollo:

```bash
uv venv --python 3.12 .devin/verify-wheel-015
uv pip sync --python .devin/verify-wheel-015/bin/python --require-hashes dist/verify-0.15.0/dependencies.txt
uv pip install --python .devin/verify-wheel-015/bin/python --no-deps dist/verify-0.15.0/lupabin-0.15.0-py3-none-any.whl
.devin/verify-wheel-015/bin/lupabin --help
.devin/verify-wheel-015/bin/python -I -c "import lupabin, lupabin.web.app, lupabin.evidence.pe_triage, lupabin.evidence.pe_resources; from lupabin.glossary.catalog import load_glossary; from importlib.resources import files; assert lupabin.__version__ == '0.15.0'; load_glossary(); assert files('lupabin.web').joinpath('static/example.json').is_file(); print(lupabin.__file__)"
uv venv --python 3.12 .devin/verify-sdist-015
uv pip sync --python .devin/verify-sdist-015/bin/python --require-hashes dist/verify-0.15.0/dependencies.txt
uv pip install --python .devin/verify-sdist-015/bin/python --no-deps dist/verify-0.15.0/lupabin-0.15.0.tar.gz
.devin/verify-sdist-015/bin/lupabin --help
.devin/verify-sdist-015/bin/python -I -c "import lupabin, lupabin.web.app, lupabin.evidence.pe_triage, lupabin.evidence.pe_resources; from lupabin.glossary.catalog import load_glossary; from importlib.resources import files; assert lupabin.__version__ == '0.15.0'; load_glossary(); assert files('lupabin.web').joinpath('static/example.json').is_file(); print(lupabin.__file__)"
```

En Windows usa `Scripts/python.exe` y `Scripts/lupabin.exe` en lugar de `bin/python` y `bin/lupabin`; en PowerShell, define la carpeta con `$env:LUPABIN_DISTRIBUTIONS = (Resolve-Path dist/verify-0.15.0).Path`. Si uv no está en `PATH`, usa su ruta instalada. `-I` evita importar desde el checkout o desde `PYTHONPATH`: las rutas impresas deben pertenecer al entorno recién creado. El sdist necesita además obtener el constructor fijado en `pyproject.toml`; la instalación inicial de dependencias puede necesitar red. Esto no es red para el worker ni una consulta de muestras.

Con motor Docker Linux disponible, y solo después de terminar los pasos anteriores:

```text
docker compose config --quiet
docker build --load -f docker/Dockerfile -t lupabin-worker:0.15.0 .
uv run --frozen --no-sync pytest -q -m docker tests/integration/test_docker.py -k triage
uv run --frozen --no-sync pytest -q -m docker tests/integration/test_docker.py -k "container_runtime_restrictions or timeout_removes_real_container"
```

Las nuevas regresiones pasan bytes inventados al worker (PE32 y PE32+), comprueban los cuatro tipos de triaje y sus explicaciones, declaran una tabla de certificados malformada y un texto de versión que supera el límite, y alteran cada tipo en la respuesta real para exigir que el host lo rechace y retire el contenedor. No ejecutan el PE. El aislamiento conserva red `none`, UID/GID 65532, raíz de solo lectura, todas las capacidades retiradas, `no-new-privileges`, una CPU, 512 MiB sin swap adicional, 64 procesos y 64 descriptores. Sin Docker o sin la imagen local no se analiza en el host como alternativa.

La revisión visual es distinta de estas pruebas: abre *Ver informe de ejemplo* en la web, recorre citas y práctica y descarga HTML/JSON. Para documentarla, captura realmente ese ejemplo, identificado como sintético; no uses informes privados ni presentes una imagen recreada como captura. Estas comprobaciones de instalación no arrancan otra web ni prueban visualmente el navegador. `deploy/server/install.sh` y `update.sh` sí instalan dependencias y reinician servicios: resérvalos para un despliegue autorizado en un servidor dedicado.

## English summary: verify the 0.15.0 distribution

The Spanish checklist above gives the full sequential build and clean-install procedure for the final wheel and sdist. It is a procedure awaiting execution, not a claim that those artifacts passed. Use one integrated revision for the package, host and `lupabin-worker:0.15.0`; a matching version label alone does not establish matching contents. Build into a new directory and install each artifact in its own fresh environment, with the locked dependencies including the `web` extra. Isolated Python import checks (`-I`) and CLI `--help` must use that environment, not the checkout. These checks do not start or restart the web server.

Once resources are available and the package checks have finished, run these commands one at a time, stopping on any failure. `--no-sync` reuses an already prepared test environment; it does not install the development group. Final CLI/web environments use locked runtime dependencies including `web`, exported with `--no-dev`, and do not need pre-commit or virtualenv:

```text
docker compose config --quiet
docker build --load -f docker/Dockerfile -t lupabin-worker:0.15.0 .
uv run --frozen --no-sync pytest -q -m docker tests/integration/test_docker.py -k triage
uv run --frozen --no-sync pytest -q -m docker tests/integration/test_docker.py -k "container_runtime_restrictions or timeout_removes_real_container"
```

The triage regressions use invented PE32/PE32+ bytes without ever executing them: PDB references, certificate entries, overlay spans and version strings, plus explicit incomplete coverage and rejection of tampered worker output on the host. A certificate entry is not a validated signature, a PDB path does not identify its author, version text is self-declared and overlay bytes do not prove execution or packing. Docker retains network `none`, UID/GID 65532, a read-only root, all capabilities dropped, `no-new-privileges`, one CPU, 512 MiB with no extra swap, 64 processes and 64 file descriptors. Missing Docker or a missing local image is an error, never a fallback to host analysis. None of these commands publishes to a registry.
