import React from "react";

interface FileUploadProps {
  handleFileUpload: (file: File) => void;
}

const FileUpload: React.FC<FileUploadProps> = ({ handleFileUpload }) => {
  const handleChange = (event: React.ChangeEvent<HTMLInputElement>): void => {
    if (event.target.files && event.target.files.length > 0) {
      handleFileUpload(event.target.files[0]);
    }
  };

  return (
    <div className="bg-yellow-500 p-10 rounded-lg shadow-md text-center w-full max-w-lg">
      <h2 className="text-2xl font-semibold text-white mb-4">
        Upload Your Code As A Zip File
      </h2>
      <input
        type="file"
        id="file-upload"
        accept=".zip"
        className="hidden"
        onChange={handleChange}
      />
      <label
        htmlFor="file-upload"
        className="bg-white text-yellow-500 font-semibold px-6 py-3 rounded cursor-pointer hover:bg-gray-200"
      >
        Choose File
      </label>
    </div>
  );
};

export default FileUpload;
