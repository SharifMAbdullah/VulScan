import React from 'react';

const ScanReportButton: React.FC = () => {
  const handleDownload = (): void => {
    alert('Downloading scan report...');
  };

  return (
    <button
      onClick={handleDownload}
      className="bg-green-600 text-white font-semibold px-4 py-2 rounded mt-4"
    >
      Download Scan Report
    </button>
  );
};

export default ScanReportButton;
