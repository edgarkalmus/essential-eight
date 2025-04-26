import React from 'react';
import { useAssessment } from '../contexts/AssessmentContext';
import MaturityRadar from './MaturityRadar';
import ComplianceChart from './ComplianceChart';
import MaturityTable from './MaturityTable';
import DetailedBreakdown from './DetailedBreakdown';
import Recommendations from './Recommendations';
import { exportToPdf } from '../utils/pdfExport';

const ResultsSection = () => {
  const { results, resetAssessment } = useAssessment();
  
  if (!results) {
    return <div>No results available</div>;
  }
  
  return (
    <div id="assessment-results" className="max-w-6xl mx-auto p-4">
      <h2 className="text-2xl font-bold text-primary mb-6 text-center">Essential Eight Assessment Results</h2>
      
      <div className="grid grid-cols-1 md:grid-cols-3 gap-6 mb-8">
        <div className="bg-white p-6 rounded-lg shadow-md text-center">
          <h3 className="text-lg font-semibold text-gray-700 mb-2">Overall Maturity Level</h3>
          <div className={`text-5xl font-bold text-maturity-${results.overallMaturityLevel}`}>
            {results.overallMaturityLevel}
          </div>
        </div>
        
        <div className="bg-white p-6 rounded-lg shadow-md text-center">
          <h3 className="text-lg font-semibold text-gray-700 mb-2">Strategies at Target</h3>
          <div className="text-5xl font-bold text-primary">
            {results.strategiesAtTarget} <span className="text-lg text-gray-500">/ 8</span>
          </div>
        </div>
        
        <div className="bg-white p-6 rounded-lg shadow-md text-center">
          <h3 className="text-lg font-semibold text-gray-700 mb-2">Overall Compliance</h3>
          <div className="text-5xl font-bold text-primary">
            {Math.round(results.overallCompliancePercentage)}%
          </div>
        </div>
      </div>
      
      <div className="grid grid-cols-1 md:grid-cols-2 gap-8 mb-8">
        <div className="bg-white p-6 rounded-lg shadow-md">
          <h3 className="text-lg font-semibold text-gray-700 mb-4">Maturity Radar</h3>
          <MaturityRadar results={results} />
        </div>
        
        <div className="bg-white p-6 rounded-lg shadow-md">
          <h3 className="text-lg font-semibold text-gray-700 mb-4">Compliance Percentage by Strategy</h3>
          <ComplianceChart results={results} />
        </div>
      </div>
      
      <div id="maturity-table-container" className="bg-white p-6 rounded-lg shadow-md mb-8">
        <h3 className="text-lg font-semibold text-gray-700 mb-4">Strategy-Level Maturity Summary</h3>
        <MaturityTable results={results} isPdfExport={false} />
      </div>
      
      <div id="pdf-content" className="hidden">
        <div id="pdf-table-container">
          <MaturityTable results={results} isPdfExport={true} />
        </div>
      </div>
      
      <div className="bg-white p-6 rounded-lg shadow-md mb-8">
        <h3 className="text-lg font-semibold text-gray-700 mb-4">Strategy-Specific Detailed Breakdown</h3>
        <DetailedBreakdown results={results} />
      </div>
      
      <div className="bg-white p-6 rounded-lg shadow-md mb-8">
        <h3 className="text-lg font-semibold text-gray-700 mb-4">Key Recommendations</h3>
        <Recommendations results={results} />
      </div>
      
      <div className="flex justify-center space-x-4 mb-8 print:hidden">
        <button
          onClick={resetAssessment}
          className="px-6 py-3 bg-gray-600 text-white font-bold rounded-lg shadow-md hover:bg-gray-700 transition-all"
        >
          Start New Assessment
        </button>
        
        <button
          onClick={exportToPdf}
          className="px-6 py-3 bg-primary text-white font-bold rounded-lg shadow-md hover:bg-opacity-90 transition-all"
        >
          Export to PDF
        </button>
      </div>
    </div>
  );
};

export default ResultsSection;