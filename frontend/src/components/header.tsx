import React from 'react';

const Header: React.FC = () => {
  return (
    <header className="bg-white shadow-md w-full py-4 px-8 flex justify-between items-center">
      <h1 className="text-2xl font-bold text-gray-800">VulScan</h1>
      <p className="text-lg font-light text-gray-600">Catch Vulnerabilities Early, Deploy Confidently</p>
      <div className="bg-gray-300 w-12 h-12 rounded-full flex items-center justify-center">
        {/* Placeholder for logo */}
        <span className="text-gray-800">Logo</span>
      </div>
    </header>
  );
};

export default Header;
