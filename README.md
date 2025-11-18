# Firmar APKs (herramienta)

Este proyecto provee un script Python (`main.py`) que firma APKs usando `apksigner` (parte de Android SDK Build-Tools).

Requisitos
- Python 3.8+
- Android SDK Build-Tools (para `apksigner`) y que `apksigner` esté en `PATH` o `ANDROID_SDK_ROOT`/`ANDROID_HOME` configurado.
- (Opcional) Un entorno virtual (`venv`) para instalar dependencias.

Activar `venv` en Windows (recomendado)

```powershell
.\venv\Scripts\activate
```

Instalar dependencias (opcional)

```powershell
python -m pip install -r requirements.txt
```

Uso básico

Firmar todos los APKs dentro de la carpeta `Apk sin encriptar` y guardar firmados en `Apk encriptada`:

```powershell
python main.py --keystore C:\ruta\a\keystore.jks --alias mi_alias
```

Firmar un APK específico y dejar el original:

```powershell
python main.py -i C:\ruta\app.apk -o C:\ruta\out_folder --keystore C:\ruta\keystore.jks --alias mi_alias --keep-original
```

Si no pasas `--password`, el script pedirá la contraseña interactivamente (oculta).

Sobre `apksigner`
 - `apksigner` forma parte de Android SDK Build-Tools. Instálalo desde el SDK Manager o descarga el SDK Command-line tools.
 - Si `apksigner` no está en `PATH`, exporta `ANDROID_SDK_ROOT` o `ANDROID_HOME` apuntando al directorio del SDK.

Crear un `.exe` con `pyinstaller` (Windows)

1. Activar `venv` (recomendado).
2. Instalar `pyinstaller` (ya está en `requirements.txt`).
3. Ejecutar:

```powershell
pyinstaller --onefile --name firmador_apk main.py
```

El ejecutable se encontrará en `dist\firmador_apk.exe`.

¿Necesito tener Python abierto en el `venv`?
- No es necesario tener un IDE abierto, pero sí recomiendo activar el `venv` antes de ejecutar comandos para usar el intérprete y dependencias correctas. Alternativamente puedes usar la ruta absoluta al intérprete dentro de `venv` (por ejemplo, `venv\Scripts\python.exe`).

Notas de seguridad
- No borres APKs originales hasta verificar que los APKs firmados funcionan correctamente.
- Guarda tu `keystore` y contraseñas en un lugar seguro. Considera usar `keyring` si quieres integrarlo para no pasar contraseñas en la línea de comandos.

Si quieres, puedo:
- Añadir integración con `keyring` para leer la contraseña desde el almacén seguro.
- Crear un instalador/ejecutable y probarlo (necesito que confirmes si quieres que ejecute `pyinstaller` aquí o que te entregue la instrucción).
