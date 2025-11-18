import os
import subprocess
import tempfile
import shutil

def extract_manifest(apk_path, output_dir, apkanalyzer_path):
    """Extracts the AndroidManifest.xml from an APK using the provided apkanalyzer path."""
    try:
        command = [
            apkanalyzer_path,
            "manifest",
            "print",
            apk_path
        ]
        result = subprocess.run(command, capture_output=True, text=True, check=True)
        manifest_path = os.path.join(output_dir, "AndroidManifest.xml")
        with open(manifest_path, "w", encoding="utf-8") as manifest_file:
            manifest_file.write(result.stdout)
        return manifest_path
    except subprocess.CalledProcessError as e:
        print(f"Error extracting manifest: {e.stderr}")
        return None

def modify_manifest(manifest_path, min_sdk=None, target_sdk=None):
    """Modifies the AndroidManifest.xml file."""
    try:
        with open(manifest_path, "r", encoding="utf-8") as file:
            manifest_content = file.read()

        # Example modification: Update minSdkVersion and targetSdkVersion
        if min_sdk:
            manifest_content = manifest_content.replace(
                'android:minSdkVersion="29"', f'android:minSdkVersion="{min_sdk}"'
            )
        if target_sdk:
            manifest_content = manifest_content.replace(
                'android:targetSdkVersion="30"', f'android:targetSdkVersion="{target_sdk}"'
            )

        with open(manifest_path, "w", encoding="utf-8") as file:
            file.write(manifest_content)

        print("Manifest modified successfully.")
    except Exception as e:
        print(f"Error modifying manifest: {e}")

def repackage_apk(apk_path, manifest_path, output_apk):
    """Repackages the APK with the modified AndroidManifest.xml."""
    try:
        temp_dir = tempfile.mkdtemp()
        shutil.copy(apk_path, temp_dir)

        # Use apktool to decompile, replace manifest, and recompile
        decompile_command = ["apktool", "d", apk_path, "-o", temp_dir]
        subprocess.run(decompile_command, check=True)

        shutil.copy(manifest_path, os.path.join(temp_dir, "AndroidManifest.xml"))

        recompile_command = ["apktool", "b", temp_dir, "-o", output_apk]
        subprocess.run(recompile_command, check=True)

        print("APK repackaged successfully.")
    except subprocess.CalledProcessError as e:
        print(f"Error repackaging APK: {e.stderr}")
    finally:
        shutil.rmtree(temp_dir)

def process_apk(apk_path, output_apk, min_sdk=None, target_sdk=None, apkanalyzer_path=None):
    """Extracts, modifies, and repackages an APK."""
    with tempfile.TemporaryDirectory() as temp_dir:
        manifest_path = extract_manifest(apk_path, temp_dir, apkanalyzer_path)
        if manifest_path:
            modify_manifest(manifest_path, min_sdk, target_sdk)
            repackage_apk(apk_path, manifest_path, output_apk)

if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="Modifica el AndroidManifest.xml de un APK antes de firmar")
    parser.add_argument('--apk', required=True, help='Ruta al APK de entrada')
    parser.add_argument('--output', required=True, help='Ruta al APK de salida')
    parser.add_argument('--min-sdk', type=int, default=21, help='minSdkVersion a establecer')
    parser.add_argument('--target-sdk', type=int, default=34, help='targetSdkVersion a establecer')
    parser.add_argument('--apkanalyzer', required=True, help='Ruta al ejecutable apkanalyzer')
    args = parser.parse_args()

    process_apk(args.apk, args.output, min_sdk=args.min_sdk, target_sdk=args.target_sdk, apkanalyzer_path=args.apkanalyzer)