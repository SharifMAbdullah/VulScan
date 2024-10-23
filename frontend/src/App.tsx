import React, { useState } from 'react';
import Header from './components/Header';
import FileUpload from './components/FileUpload';
import Loader from './components/loader';
import ScanReportButton from './components/scanReportButton';

const App: React.FC = () => {
  const [isFileUploaded, setIsFileUploaded] = useState<boolean>(false);
  const [isProcessing, setIsProcessing] = useState<boolean>(false);
  const [isScanComplete, setIsScanComplete] = useState<boolean>(false);

  const handleFileUpload = (): void => {
    setIsFileUploaded(true);
    setIsProcessing(true);

    // Simulate file processing
    setTimeout(() => {
      setIsProcessing(false);
      setIsScanComplete(true);
    }, 3000); // Simulate a 3-second process
  };

  return (
    <div className="min-h-screen bg-gray-100">
      <Header />
      <div className="flex flex-col items-center justify-center py-10">
        {!isFileUploaded && (
          <FileUpload handleFileUpload={handleFileUpload} />
        )}
        {isProcessing && <Loader />}
        {isFileUploaded && !isProcessing && (
          <button
            onClick={() => alert('Scanning...')}
            className="bg-blue-600 text-white font-semibold px-4 py-2 rounded mt-4"
          >
            Scan For Vulnerabilities
          </button>
        )}
        {isScanComplete && <ScanReportButton />}
      </div>
    </div>
  );
};

export default App;
