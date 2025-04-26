import React, { useState } from 'react';

const MaturityTable = ({ results, isPdfExport = false }) => {
  const strategies = Object.keys(results.strategies);
  const [expandedGaps, setExpandedGaps] = useState({});
  
  const toggleGapsExpansion = (strategy, level) => {
    const key = `${strategy}-${level}`;
    setExpandedGaps(prev => ({
      ...prev,
      [key]: !prev[key]
    }));
  };
  
  const getMaturityLevelClass = (level) => {
    switch(level) {
      case 0: return 'bg-maturity-0 text-white';
      case 1: return 'bg-maturity-1 text-white';
      case 2: return 'bg-maturity-2 text-white';
      case 3: return 'bg-maturity-3 text-white';
      default: return 'bg-gray-200';
    }
  };
  
  return (
    <div className="overflow-x-auto">
      <table className="min-w-full bg-white border border-gray-200">
        <thead>
          <tr className="bg-gray-100">
            <th className="py-3 px-4 text-left font-semibold text-gray-700">Strategy</th>
            <th className="py-3 px-4 text-left font-semibold text-gray-700">Maturity Level</th>
            <th className="py-3 px-4 text-left font-semibold text-gray-700">Key Gaps</th>
          </tr>
        </thead>
        <tbody>
          {strategies.map(strategy => {
            const { maturityLevel, gaps } = results.strategies[strategy];
            
            // Find gaps for the next level (if not at level 3)
            const nextLevel = maturityLevel < 3 ? maturityLevel + 1 : null;
            const nextLevelGaps = nextLevel ? gaps[nextLevel] || [] : [];
            
            return (
              <tr key={strategy} className="border-t border-gray-200 hover:bg-gray-50">
                <td className="py-3 px-4">{strategy}</td>
                <td className="py-3 px-4">
                  <span className={`inline-block px-3 py-1 rounded-full text-sm font-medium ${getMaturityLevelClass(maturityLevel)}`}>
                    Level {maturityLevel}
                  </span>
                </td>
                <td className="py-3 px-4">
                  {nextLevelGaps.length > 0 ? (
                    <div>
                      <div className="mb-1">
                        <span className="text-gray-700">For Level {nextLevel}:</span>
                      </div>
                      
                      {/* Show all gaps for PDF export, otherwise show expandable list */}
                      {isPdfExport ? (
                        <div className="space-y-2">
                          {nextLevelGaps.map((gap, index) => (
                            <div key={index} className="text-sm text-gray-600">
                              {gap}
                            </div>
                          ))}
                        </div>
                      ) : (
                        <>
                          <div className="text-sm text-gray-600 mb-1">
                            {nextLevelGaps[0]}
                          </div>
                          
                          {nextLevelGaps.length > 1 && (
                            <>
                              {expandedGaps[`${strategy}-${nextLevel}`] ? (
                                <div className="mt-2">
                                  {nextLevelGaps.slice(1).map((gap, index) => (
                                    <div key={index} className="text-sm text-gray-600 mb-1">
                                      {gap}
                                    </div>
                                  ))}
                                  <button
                                    onClick={() => toggleGapsExpansion(strategy, nextLevel)}
                                    className="text-primary text-sm hover:underline mt-1"
                                  >
                                    Show less
                                  </button>
                                </div>
                              ) : (
                                <button
                                  onClick={() => toggleGapsExpansion(strategy, nextLevel)}
                                  className="text-primary text-sm hover:underline mt-1"
                                >
                                  +{nextLevelGaps.length - 1} more gaps
                                </button>
                              )}
                            </>
                          )}
                        </>
                      )}
                    </div>
                  ) : (
                    <span className="text-gray-500 italic">
                      {maturityLevel === 3 ? "Highest level achieved" : "No gaps for next level"}
                    </span>
                  )}
                </td>
              </tr>
            );
          })}
        </tbody>
      </table>
    </div>
  );
};

export default MaturityTable;