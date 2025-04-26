import React from 'react';
import { AssessmentProvider, useAssessment } from './contexts/AssessmentContext';
import Introduction from './components/Introduction';
import AssessmentMode from './components/AssessmentMode';
import QuestionCard from './components/QuestionCard';
import ResultsSection from './components/ResultsSection';

const AssessmentContent = () => {
  const { assessmentStarted, assessmentMode, assessmentCompleted, startAssessment } = useAssessment();
  
  if (!assessmentStarted) {
    return <Introduction onStartAssessment={() => startAssessment('mode')} />;
  }
  
  if (assessmentMode === 'mode') {
    return <AssessmentMode />;
  }
  
  if (assessmentCompleted) {
    return <ResultsSection />;
  }
  
  return <QuestionCard />;
};

const App = () => {
  return (
    <AssessmentProvider>
      <div className="min-h-screen bg-gray-100">
        <header className="bg-primary text-white py-4 shadow-md">
          <div className="container mx-auto px-4">
            <h1 className="text-2xl font-bold text-center">
              Essential Eight Maturity Self-Assessment Tool
            </h1>
            <p className="text-center text-white opacity-90">
              Based on the Australian Cyber Security Centre (ACSC) Framework
            </p>
          </div>
        </header>
        
        <main className="container mx-auto py-8 px-4">
          <AssessmentContent />
        </main>
        
        <footer className="bg-gray-800 text-white py-4 mt-12">
          <div className="container mx-auto px-4 text-center">
            <p>Based on the <a href="https://www.cyber.gov.au/essential-eight" target="_blank" rel="noopener noreferrer" className="text-blue-300 hover:underline">Australian Cyber Security Centre Essential Eight Framework</a></p>
            <p className="text-gray-400 text-sm mt-2">
              This tool is for self-assessment purposes only. Your responses are saved only in your browser's local storage.
            </p>
          </div>
        </footer>
      </div>
    </AssessmentProvider>
  );
};

export default App;