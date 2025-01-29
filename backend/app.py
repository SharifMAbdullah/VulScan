from utils.generate_pdf import generate_vulnerability_report
from flask import Flask, request, jsonify # type: ignore
from utils.file_utils import handle_zip_file
from utils.analysis_utils import analyze_c_files

app = Flask(__name__)

@app.route("/analyze_zip", methods=["POST"])
def analyze_zip_file():
    try:
        # Receive the uploaded zip file
        zip_file = request.files.get("file")
        if not zip_file:
            return jsonify({"error": "Zip file is required"}), 400

        # Extract C files from the zip
        extracted_files = handle_zip_file(zip_file)
        if not extracted_files:
            return jsonify({"error": "No C files found in the zip"}), 400

        # Analyze all extracted C files
        results = analyze_c_files(extracted_files)

        generate_vulnerability_report(results)
        return jsonify({"results": results}), 200


    except Exception as e:
        return jsonify({"error": str(e)}), 500

if __name__ == "__main__":
    app.run(debug=True)
