import React, { useState } from 'react';

const DetailedBreakdown = ({ results }) => {
  const strategies = Object.keys(results.strategies);
  const [activeStrategy, setActiveStrategy] = useState(strategies[0]);
  
  // Get the response status icon based on the response value
  const getStatusIcon = (isCompliant) => {
    if (isCompliant) {
      return (
        <span className="inline-flex items-center justify-center w-6 h-6 rounded-full bg-green-100 text-green-600">
          ✓
        </span>
      );
    } else {
      return (
        <span className="inline-flex items-center justify-center w-6 h-6 rounded-full bg-red-100 text-red-600">
          ✗
        </span>
      );
    }
  };

  const getComplianceStatus = (compliancePercent) => {
    if (compliancePercent === 100) {
      return "All requirements met for this level";
    } else if (compliancePercent > 0) {
      return "Requirements partially met for this level";
    } else if (compliancePercent === 0) {
      return "Level not evaluated";
    }
  };
  
  return (
    <div>
      <div className="flex flex-wrap mb-4 gap-2">
        {strategies.map(strategy => (
          <button
            key={strategy}
            onClick={() => setActiveStrategy(strategy)}
            className={`px-3 py-1 rounded-full text-sm font-medium ${
              activeStrategy === strategy
                ? 'bg-primary text-white'
                : 'bg-gray-200 text-gray-700 hover:bg-gray-300'
            }`}
          >
            {strategy}
          </button>
        ))}
      </div>
      
      <div className="space-y-4">
        {[1, 2, 3].map(level => {
          const strategy = results.strategies[activeStrategy];
          const compliancePercent = strategy.compliance[level] || 0;
          const gaps = strategy.gaps[level] || [];
          const isCurrentLevel = strategy.maturityLevel === level;
          const isAchieved = strategy.achievedLevels.has(level);
          
          return (
            <div key={level} className="border rounded-lg overflow-hidden">
              <div className={`p-3 ${isAchieved ? 'bg-green-50' : isCurrentLevel ? 'bg-yellow-50' : 'bg-gray-50'}`}>
                <div className="flex justify-between items-center">
                  <h4 className="font-medium">Level {level}</h4>
                  <div className="flex items-center">
                    <div className="text-sm font-medium mr-2">
                      {Math.round(compliancePercent)}% Compliant
                    </div>
                    <div className={`h-2 w-16 rounded-full ${isAchieved ? 'bg-green-200' : 'bg-gray-200'}`}>
                      <div 
                        className={`h-2 rounded-full ${isAchieved ? 'bg-green-500' : 'bg-primary'}`}
                        style={{ width: `${compliancePercent}%` }}
                      ></div>
                    </div>
                  </div>
                </div>
                {isCurrentLevel && (
                  <div className="mt-1 text-sm text-yellow-600">Current Level</div>
                )}
                {isAchieved && !isCurrentLevel && (
                  <div className="mt-1 text-sm text-green-600">Level Achieved</div>
                )}
              </div>
              
              <div className="p-3 bg-white">
                <div className="space-y-2">
                  {compliancePercent === 100 ? (
                    <div className="text-center text-sm text-green-600 italic py-2">
                      {getComplianceStatus(compliancePercent)}
                    </div>
                  ) : gaps.length > 0 ? (
                    gaps.map((gap, index) => (
                      <div key={index} className="flex">
                        {getStatusIcon(false)}
                        <span className="ml-2 text-sm text-gray-700">{gap}</span>
                      </div>
                    ))
                  ) : (
                    <div className="text-center text-sm text-gray-600 italic py-2">
                      {getComplianceStatus(compliancePercent)}
                    </div>
                  )}
                </div>
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
};

export default DetailedBreakdown;