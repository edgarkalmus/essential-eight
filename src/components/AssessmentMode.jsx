import React, { useState } from 'react';
import { useAssessment } from '../contexts/AssessmentContext';

const AssessmentMode = () => {
  const { startAssessment } = useAssessment();
  const [selectedLevel, setSelectedLevel] = useState(1);
  
  const handleStartFullAssessment = () => {
    startAssessment('full');
  };
  
  const handleStartTargetAssessment = () => {
    startAssessment('target', selectedLevel);
  };
  
  return (
    <div className="max-w-4xl mx-auto p-4">
      <h2 className="text-2xl font-bold text-primary mb-6 text-center">Select Assessment Mode</h2>
      
      <div className="grid grid-cols-1 md:grid-cols-2 gap-8 mb-8">
        {/* Full Assessment Option */}
        <div className="bg-white p-6 rounded-lg shadow-md">
          <h3 className="text-xl font-bold text-primary mb-3">Full Assessment</h3>
          <p className="mb-4 text-gray-600">
            Complete assessment of all maturity levels (0-3) across all eight strategies.
          </p>
          <ul className="list-disc pl-5 mb-6 text-gray-600">
            <li>Comprehensive evaluation</li>
            <li>Detailed recommendations</li>
            <li>Complete maturity profile</li>
          </ul>
          <button 
            onClick={handleStartFullAssessment}
            className="w-full px-4 py-2 bg-primary text-white font-bold rounded-lg shadow hover:bg-opacity-90 transition-all"
          >
            Start Full Assessment
          </button>
        </div>
        
        {/* Target Assessment Option */}
        <div className="bg-white p-6 rounded-lg shadow-md">
          <h3 className="text-xl font-bold text-primary mb-3">Maturity Goal Assessment</h3>
          <p className="mb-4 text-gray-600">
            Assessment tailored to your target maturity level.
          </p>
          
          <div className="mb-6">
            <p className="mb-2 font-semibold text-gray-700">Select Target Maturity Level:</p>
            <div className="flex space-x-2">
              {[1, 2, 3].map(level => (
                <button
                  key={level}
                  onClick={() => setSelectedLevel(level)}
                  className={`px-4 py-2 rounded-lg font-medium ${
                    selectedLevel === level 
                      ? `bg-maturity-${level} text-white` 
                      : 'bg-gray-100 text-gray-700 hover:bg-gray-200'
                  }`}
                >
                  Level {level}
                </button>
              ))}
            </div>
          </div>
          
          <button 
            onClick={handleStartTargetAssessment}
            className="w-full px-4 py-2 bg-primary text-white font-bold rounded-lg shadow hover:bg-opacity-90 transition-all"
          >
            Start Goal Assessment
          </button>
        </div>
      </div>
    </div>
  );
};

export default AssessmentMode;