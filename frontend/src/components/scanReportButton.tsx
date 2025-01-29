import React from "react";

const ScanReportButton: React.FC = () => {
const handleDownload = () => {
  window.open("http://127.0.0.1:5000/download_report", "_blank");
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
