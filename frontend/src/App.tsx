import * as React from "react";
import { useState } from "react";
import Header from "./components/header";
import FileUpload from "./components/fileUpload";
import Loader from "./components/loader";
import ScanReportButton from "./components/scanReportButton";

const App: React.FC = () => {
  const [isProcessing, setIsProcessing] = useState<boolean>(false);
  const [isScanComplete, setIsScanComplete] = useState<boolean>(false);
  const [scanResults, setScanResults] = useState<any>(null);
  const [uploadedFile, setUploadedFile] = useState<File | null>(null);

  const handleFileUpload = (file: File): void => {
    setUploadedFile(file);
  };

  const handleScan = async () => {
    if (!uploadedFile) return alert("Please upload a file first!");

    setIsProcessing(true);
    setIsScanComplete(false);

    const formData = new FormData();
    formData.append("file", uploadedFile);

    try {
      const response = await fetch("http://127.0.0.1:5000/analyze_zip", {
        method: "POST",
        body: formData,
      });

      if (!response.ok) {
        throw new Error("Failed to analyze file.");
      }

      const data = await response.json();
      setScanResults(data.results);
      setIsScanComplete(true);
    } catch (error) {
      alert("Error processing file.");
      console.error(error);
    } finally {
      setIsProcessing(false);
    }
  };

  return (
    <div className="min-h-screen bg-gray-100">
      <Header />
      <div className="flex flex-col items-center justify-center py-10">
        {!uploadedFile && <FileUpload handleFileUpload={handleFileUpload} />}
        {isProcessing && <Loader />}
        {uploadedFile && !isProcessing && !isScanComplete && (
          <button
            onClick={handleScan}
            className="bg-blue-600 text-white font-semibold px-4 py-2 rounded mt-4"
          >
            Scan For Vulnerabilities
          </button>
        )}
        {isScanComplete && scanResults && (
          <div className="mt-6">
            <h2 className="text-lg font-bold">Scan Complete!</h2>
            <ScanReportButton />
          </div>
        )}
      </div>
    </div>
  );
};

export default App;
