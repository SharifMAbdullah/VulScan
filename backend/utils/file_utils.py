import os
import zipfile
from werkzeug.utils import secure_filename # type: ignore

def handle_zip_file(zip_file):
    """
    Extract C files from a zip file.
    """
    extracted_files = []
    upload_folder = "uploads"
    os.makedirs(upload_folder, exist_ok=True)

    zip_path = os.path.join(upload_folder, secure_filename(zip_file.filename))
    zip_file.save(zip_path)

    with zipfile.ZipFile(zip_path, "r") as z:
        for file_name in z.namelist():
            if file_name.endswith(".c"):
                extracted_path = os.path.join(upload_folder, secure_filename(file_name))
                with open(extracted_path, "wb") as f:
                    f.write(z.read(file_name))
                extracted_files.append(extracted_path)

    return extracted_files
