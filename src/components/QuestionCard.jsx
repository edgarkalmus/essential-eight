import React from 'react';
import { useAssessment } from '../contexts/AssessmentContext';

const QuestionCard = () => {
  const { 
    currentQuestion, 
    currentQuestionIndex, 
    totalQuestions, 
    answerQuestion, 
    progress 
  } = useAssessment();
  
  if (!currentQuestion) {
    return <div className="text-center py-8">Loading question...</div>;
  }
  
  const handleAnswer = (answer) => {
    answerQuestion(currentQuestion.id, answer);
  };
  
  return (
    <div className="max-w-3xl mx-auto p-4">
      <div className="mb-4 flex justify-between items-center">
        <h2 className="text-xl font-bold text-primary">
          Question {currentQuestionIndex + 1} of {totalQuestions}
        </h2>
        <div className="text-lg font-medium text-gray-600">
          {currentQuestion.strategy} - Maturity Level {currentQuestion.level}
        </div>
      </div>
      
      {/* Progress bar */}
      <div className="w-full bg-gray-200 rounded-full h-2.5 mb-6">
        <div 
          className="bg-primary h-2.5 rounded-full" 
          style={{ width: `${progress}%` }}
        ></div>
      </div>
      
      {/* Question text */}
      <div className="bg-white p-6 rounded-lg shadow-md mb-8">
        <p className="text-lg font-medium mb-2">{currentQuestion.text}</p>
        {currentQuestion.info && (
          <p className="text-gray-600 text-sm italic">{currentQuestion.info}</p>
        )}
      </div>
      
      {/* Answer options */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        <button
          onClick={() => handleAnswer('yes')}
          className="flex flex-col items-center bg-green-100 border-2 border-green-500 p-4 rounded-lg hover:bg-green-200 transition-all"
        >
          <span className="text-green-600 font-bold text-lg mb-1">YES</span>
          <span className="text-green-600 text-sm text-center">
            Full implementation across ALL systems and locations as per the ACSC definition
          </span>
        </button>
        
        <button
          onClick={() => handleAnswer('partially')}
          className="flex flex-col items-center bg-yellow-100 border-2 border-yellow-500 p-4 rounded-lg hover:bg-yellow-200 transition-all"
        >
          <span className="text-yellow-600 font-bold text-lg mb-1">PARTIALLY</span>
          <span className="text-yellow-600 text-sm text-center">
            Implemented on SOME systems but not all, or with exceptions to the ACSC requirements
          </span>
        </button>
        
        <button
          onClick={() => handleAnswer('no')}
          className="flex flex-col items-center bg-red-100 border-2 border-red-500 p-4 rounded-lg hover:bg-red-200 transition-all"
        >
          <span className="text-red-600 font-bold text-lg mb-1">NO</span>
          <span className="text-red-600 text-sm text-center">
            Not implemented at all, or with major gaps
          </span>
        </button>
      </div>
    </div>
  );
};

export default QuestionCard;