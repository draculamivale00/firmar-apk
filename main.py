"""Herramienta simple para firmar APKs usando apksigner (Android SDK Build-Tools).

Este script ofrece un CLI que procesa un APK (o todos los APKs en una carpeta)
y llama a `apksigner` para firmarlos. Diseñado para ejecutarse en Windows/PC.
"""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path
import argparse
import getpass
from shutil import which
from typing import Tuple
import secrets
from datetime import datetime
import keyring
import re
import string


def find_apksigner() -> str | None:
    """Buscar `apksigner` en PATH o en ANDROID_SDK_ROOT/ANDROID_HOME build-tools."""
    exe_name = 'apksigner.bat' if os.name == 'nt' else 'apksigner'
    if which('apksigner'):
        return which('apksigner')

    # Buscar en ANDROID_SDK_ROOT/ANDROID_HOME
    for env in ('ANDROID_SDK_ROOT', 'ANDROID_HOME'):
        sdk = os.environ.get(env)
        if not sdk:
            continue
        build_tools = Path(sdk) / 'build-tools'
        if not build_tools.exists():
            continue
        # elegir la versión más reciente disponible
        versions = sorted([p for p in build_tools.iterdir() if p.is_dir()], reverse=True)
        for v in versions:
            candidate = v / exe_name
            if candidate.exists():
                return str(candidate)
    return None


def sign_apk_with_apksigner(apksigner_path: str, apk_path: Path, keystore: Path, alias: str, ks_pass: str | None, out_path: Path | None = None) -> Path:
    """Llama a apksigner para firmar `apk_path`. Devuelve la ruta al APK firmado."""
    if not apk_path.exists():
        raise FileNotFoundError(f"APK no encontrado: {apk_path}")
    if not keystore.exists():
        raise FileNotFoundError(f"Keystore no encontrado: {keystore}")

    if out_path is None:
        out_path = apk_path.with_name(apk_path.stem + '.signed.apk')

    cmd = [apksigner_path, 'sign', '--ks', str(keystore), '--ks-key-alias', alias]
    if ks_pass is not None:
        cmd += ['--ks-pass', f'pass:{ks_pass}']
    cmd += ['--out', str(out_path), str(apk_path)]

    print('Ejecutando:', ' '.join(cmd))
    subprocess.check_call(cmd)
    return out_path


def verify_apk_with_apksigner(apksigner_path: str, apk_path: Path) -> bool:
    """Verifica la firma de `apk_path` usando apksigner. Devuelve True si verifica correctamente."""
    if not apk_path.exists():
        raise FileNotFoundError(f"APK no encontrado para verificar: {apk_path}")

    cmd = [apksigner_path, 'verify', '--print-certs', '--verbose', str(apk_path)]
    print('Verificando:', ' '.join(cmd))
    try:
        subprocess.check_call(cmd)
        return True
    except subprocess.CalledProcessError:
        return False


def install_dependencies(requirements_file: Path) -> None:
    """Instala dependencias listadas en `requirements.txt` usando el intérprete actual."""
    if not requirements_file.exists():
        print('No existe', requirements_file)
        return
    cmd = [sys.executable, '-m', 'pip', 'install', '-r', str(requirements_file)]
    print('Instalando dependencias desde', requirements_file)
    subprocess.check_call(cmd)


def create_keystore_if_missing(keystore: Path, alias: str | None) -> Tuple[Path, str, str | None]:
    """Si `keystore` no existe, preguntar al usuario si desea crearlo.
    Devuelve la tupla (keystore_path, alias_usado).
    """
    if keystore.exists():
        return keystore, alias, None

    print(f"Keystore no encontrado: {keystore}")
    choice = input('¿Deseas crear un keystore nuevo aquí? [y/N]: ').strip().lower()
    if choice not in ('y', 'yes'):
        raise FileNotFoundError(f'Keystore no encontrado y no se creó: {keystore}')

    # pedir alias
    if alias:
        use_alias = alias
    else:
        use_alias = input('Introduce el alias a usar para la clave (por defecto "client"): ').strip() or 'client'

    # Sanear el alias automáticamente (reemplaza caracteres no permitidos por '_')
    def _sanitize(a: str) -> str:
        s = re.sub(r'[^A-Za-z0-9_-]', '_', a)
        # acortar a 30 caracteres para evitar longitudes problemáticas
        return s[:30]

    sanitized = _sanitize(use_alias)
    if sanitized != use_alias:
        print(f"Alias modificado automáticamente: '{use_alias}' -> '{sanitized}' (caracteres inválidos reemplazados)")
        use_alias = sanitized

    # Preguntar si se desea contraseña aleatoria (por defecto Sí)
    auto_choice = input('¿Crear contraseña aleatoria para este keystore? [Y/n]: ').strip().lower()
    if auto_choice in ('n', 'no'):
        # pedir contraseña interactivamente (confirmada)
        while True:
            pw1 = getpass.getpass('Introduce contraseña para el keystore (se ocultará): ')
            pw2 = getpass.getpass('Confirma contraseña: ')
            if pw1 != pw2:
                print('Las contraseñas no coinciden. Intenta de nuevo.')
                continue
            if pw1 == '':
                print('La contraseña no puede estar vacía.')
                continue
            break
        ks_password = pw1
    else:
        # Generar contraseña fuerte y aleatoria para el keystore
        def generate_strong_password(length=32):
            chars = string.ascii_letters + string.digits + string.punctuation
            return ''.join(secrets.choice(chars) for _ in range(length))

        ks_password = generate_strong_password(32)
        print(f"[INFO] Contraseña fuerte generada para el keystore: {ks_password}")
        print("[IMPORTANTE] Guarda esta contraseña en un lugar seguro. No se volverá a mostrar.")
        # guardar contraseña en el keyring del sistema en lugar de texto plano
        try:
            service = 'firmador_apk'
            keyring.set_password(service, str(keystore), ks_password)
            print(f'Contraseña guardada en el keyring del sistema (servicio: {service}).')
        except Exception:
            print('No fue posible guardar la contraseña en el keyring. Asegúrate de guardar la contraseña en un lugar seguro.')

    # comprobar keytool disponible
    keytool_path = which('keytool')
    if not keytool_path:
        raise EnvironmentError('No se encontró `keytool` en PATH; no puedo crear el keystore automáticamente.')
    # Asegurar que el directorio padre exista antes de invocar keytool
    try:
        parent = keystore.parent
        if parent and not parent.exists():
            parent.mkdir(parents=True, exist_ok=True)
    except Exception:
        # si no podemos crear el directorio, seguiremos y dejaremos que keytool falle con mensaje claro
        pass

    cmd = [
        keytool_path, '-genkeypair', '-alias', use_alias, '-keyalg', 'RSA', '-keysize', '2048',
        '-validity', '10000', '-keystore', str(keystore), '-storepass', ks_password, '-keypass', ks_password,
        '-dname', 'CN=Auto, OU=Dev, O=Dev, L=City, S=State, C=US'
    ]
    print('Creando keystore con keytool...')
    try:
        subprocess.check_call(cmd)
    except subprocess.CalledProcessError as e:
        # Si falló, no dejar una entrada inválida en keyring (en caso de que se hubiera creado antes)
        try:
            keyring.delete_password('firmador_apk', str(keystore))
        except Exception:
            pass
        raise RuntimeError(f'Error al crear la keystore con keytool (salida {e.returncode}). Asegúrate de que la ruta existe y tienes permisos.')

    # Solo guardar la contraseña en el keyring si la creación fue exitosa
    try:
        service = 'firmador_apk'
        keyring.set_password(service, str(keystore), ks_password)
        print(f'Contraseña guardada en el keyring del sistema (servicio: {service}).')
    except Exception:
        print('Advertencia: no fue posible guardar la contraseña en el keyring tras crear el keystore.')

    print('Keystore creado en', keystore)
    return keystore, use_alias, ks_password


def process_folder(apksigner_path: str, input_path: Path, output_folder: Path, keystore: Path, alias: str | None, ks_pass: str | None, keep_original: bool) -> None:
    output_folder.mkdir(parents=True, exist_ok=True)
    apks = list(input_path.glob('*.apk'))
    if not apks:
        print('No se encontraron APKs en', input_path)
        return

    import sys
    # Detectar ruta de apkanalyzer
    def find_apkanalyzer():
        exe_name = 'apkanalyzer.bat' if os.name == 'nt' else 'apkanalyzer'
        sdk = os.environ.get('ANDROID_SDK_ROOT') or os.environ.get('ANDROID_HOME')
        if sdk:
            build_tools = Path(sdk) / 'cmdline-tools' / 'latest' / 'bin'
            candidate = build_tools / exe_name
            if candidate.exists():
                return str(candidate)
        if which('apkanalyzer'):
            return which('apkanalyzer')
        return None

    apkanalyzer_path = find_apkanalyzer()
    if not apkanalyzer_path:
        print("No se encontró apkanalyzer. Asegúrate de tenerlo instalado y en el PATH.")
        return

    for apk in apks:
        print('Procesando', apk.name)
        out_apk = output_folder / (apk.stem + '.signed.apk')
        # Alias dinámico basado en el nombre del APK
        def _sanitize(a: str) -> str:
            return re.sub(r'[^A-Za-z0-9_-]', '_', a)[:30]
        use_alias = _sanitize(apk.stem)

        # Modificar el AndroidManifest.xml antes de firmar
        print(f"[INFO] Modificando el AndroidManifest.xml de {apk.name} para robustez Play Store...")
        try:
            subprocess.check_call([
                sys.executable,
                str(Path(__file__).parent / 'modify_manifest.py'),
                '--apk', str(apk),
                '--output', str(apk),
                '--min-sdk', '21',
                '--target-sdk', '34',
                '--apkanalyzer', apkanalyzer_path
            ])
        except Exception as e:
            print(f"[ERROR] No se pudo modificar el manifest de {apk.name}: {e}")
            continue

        # Verificar si el alias existe en el keystore y crearlo si no existe
        def alias_exists_in_keystore(keystore: Path, alias: str, ks_pass: str) -> bool:
            cmd = [
                'keytool', '-list', '-keystore', str(keystore),
                '-storepass', ks_pass, '-alias', alias
            ]
            try:
                subprocess.check_call(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                return True
            except subprocess.CalledProcessError:
                return False

        if not alias_exists_in_keystore(keystore, use_alias, ks_pass):
            print(f"[INFO] Alias '{use_alias}' no encontrado en el keystore. Creando nueva clave...")
            keytool_cmd = [
                'keytool', '-genkeypair', '-alias', use_alias, '-keyalg', 'RSA', '-keysize', '2048',
                '-validity', '10000', '-keystore', str(keystore),
                '-storepass', ks_pass, '-keypass', ks_pass,
                '-dname', 'CN=APKSigner, OU=Dev, O=Company, L=City, S=State, C=US'
            ]
            try:
                subprocess.check_call(keytool_cmd)
                print(f"[OK] Clave creada para alias '{use_alias}'.")
            except Exception as e:
                print(f"[ERROR] No se pudo crear la clave para alias '{use_alias}': {e}")
                continue

        signed = sign_apk_with_apksigner(apksigner_path, apk, keystore, use_alias, ks_pass, out_apk)
        print('Firmado ->', signed)
        # Verificar la firma inmediatamente
        verified = verify_apk_with_apksigner(apksigner_path, signed)
        if not verified:
            print('VERIFICACIÓN FALLIDA para', signed)
            try:
                signed.unlink()
            except Exception:
                pass
            raise RuntimeError(f'Verificación de firma fallida para {signed}')
        if not keep_original:
            apk.unlink()


def process_apk_to_sign(apksigner_path: str, input_path: Path, keystore: Path, alias: str | None) -> Path:
    """Procesa la APK para firmarla."""
    # Verifica que solo haya un archivo .apk en el directorio de entrada
    apks = list(input_path.glob('*.apk'))
    if len(apks) != 1:
        raise ValueError(f"Se esperaba una sola APK en {input_path}, pero se encontraron {len(apks)}.")

    apk_path = apks[0]
    out_apk = input_path / f"{apk_path.stem}.signed.apk"

    # Determina el alias a usar, si no está proporcionado usa el nombre del archivo APK
    if alias is None:
        alias = apk_path.stem

    # Firma la APK y devuelve la ruta al archivo firmado
    return sign_apk_with_apksigner(apksigner_path, apk_path, keystore, alias)


def main(argv: list[str] | None = None) -> int:
    import getpass
    import os
    import subprocess
    print("\n=== Firmador de APKs Automático ===\n")
    # Estructura de carpetas y archivos
    base_dir = Path(os.path.abspath(os.getcwd()))
    input_dir = base_dir / 'Apk sin encriptar'
    output_dir = base_dir / 'Apk encriptada'
    keystore_dir = base_dir / 'keystore_backup'
    keystore_file = keystore_dir / 'my-release-key.jks'
    alias = 'Ternura'
    ks_pass = 'LImite25*'

    # Crear carpetas si no existen
    for folder in [input_dir, output_dir, keystore_dir]:
        folder.mkdir(parents=True, exist_ok=True)

    # Crear keystore si no existe
    if not keystore_file.exists():
        print(f"[INFO] Creando keystore en {keystore_file}")
        keytool_cmd = [
            'keytool', '-genkey', '-v',
            '-keystore', str(keystore_file),
            '-alias', alias,
            '-keyalg', 'RSA',
            '-keysize', '2048',
            '-validity', '10000',
            '-storepass', ks_pass,
            '-keypass', ks_pass,
            '-dname', 'CN=APKSigner, OU=Dev, O=Company, L=City, S=State, C=US'
        ]
        try:
            subprocess.check_call(keytool_cmd)
            print("[OK] Keystore creado correctamente.")
        except Exception as e:
            print(f"[ERROR] No se pudo crear el keystore: {e}")
            return 1
    else:
        print(f"[INFO] Keystore ya existe: {keystore_file}")

    print(f"[INFO] Carpeta de entrada: {input_dir}")
    print(f"[INFO] Carpeta de salida: {output_dir}")
    print(f"[INFO] Keystore: {keystore_file}")
    print(f"[INFO] Alias: {alias}")

    # El resto del script debe usar estas rutas y credenciales
    # Instalar dependencias si existe requirements.txt
    req_file = base_dir / 'requirements.txt'
    if req_file.exists():
        print(f"[INFO] Instalando dependencias desde {req_file}")
        subprocess.call(['pip', 'install', '-r', str(req_file)])

    # Buscar apksigner
    def find_apksigner():
        sdk_path = os.environ.get('ANDROID_HOME') or os.environ.get('ANDROID_SDK_ROOT')
        if sdk_path:
            for root, dirs, files in os.walk(sdk_path):
                for f in files:
                    if f.startswith('apksigner') and (f.endswith('.bat') or f.endswith('.jar')):
                        candidate = os.path.join(root, f)
                        if os.path.isfile(candidate):
                            return candidate
        return None

    apksigner_path = find_apksigner()
    if not apksigner_path:
        print("No se encontró apksigner. Asegúrate de tener instalado el SDK de Android y de que apksigner esté en tu PATH.")
        return 1

    print(f"[INFO] Usando apksigner encontrado: {apksigner_path}")

    # Procesar todos los APKs en la carpeta de entrada
    try:
        process_folder(apksigner_path, input_dir, output_dir, keystore_file, alias, ks_pass, keep_original=True)
    except Exception as e:
        print(f"[ERROR] {e}")
        return 1

    print("\n=== Proceso completado ===")
    return 0


if __name__ == "__main__":
    sys.exit(main())
