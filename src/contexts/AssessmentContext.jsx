import React, { createContext, useState, useContext } from 'react';
import questionsData from '../data/questionsData';
import { calculateMaturityLevels } from '../utils/calculations';
import useLocalStorage from '../hooks/useLocalStorage';

const AssessmentContext = createContext();

export const useAssessment = () => useContext(AssessmentContext);

export const AssessmentProvider = ({ children }) => {
  const [responses, setResponses] = useLocalStorage('e8-responses', {});
  const [assessmentMode, setAssessmentMode] = useLocalStorage('e8-assessment-mode', null);
  const [targetLevel, setTargetLevel] = useLocalStorage('e8-target-level', null);
  const [currentQuestionIndex, setCurrentQuestionIndex] = useLocalStorage('e8-current-question', 0);
  const [assessmentStarted, setAssessmentStarted] = useState(false);
  const [assessmentCompleted, setAssessmentCompleted] = useState(false);
  const [activeQuestions, setActiveQuestions] = useState([]);
  const [results, setResults] = useState(null);

  // Initialize or reset the assessment
  const startAssessment = (mode, level = null) => {
    setAssessmentMode(mode);
    setTargetLevel(level);
    
    // Filter questions based on assessment mode
    let questions = [];
    if (mode === 'full') {
      questions = [...questionsData];
    } else if (mode === 'target') {
      // For target assessment, include questions up to and including the target level
      questions = questionsData.filter(q => q.level <= level);
    }
    
    setActiveQuestions(questions);
    setCurrentQuestionIndex(0);
    setAssessmentStarted(true);
    setAssessmentCompleted(false);
  };

  // Record a response to a question
  const answerQuestion = (questionId, answer) => {
    setResponses(prevResponses => {
      const newResponses = { ...prevResponses, [questionId]: answer };
      
      // If this is the last question, calculate results after updating responses
      if (currentQuestionIndex === activeQuestions.length - 1) {
        setTimeout(() => {
          const results = calculateMaturityLevels(newResponses, activeQuestions);
          setResults(results);
          setAssessmentCompleted(true);
        }, 0);
      }
      
      return newResponses;
    });
    
    // Move to next question if not the last one
    if (currentQuestionIndex < activeQuestions.length - 1) {
      setCurrentQuestionIndex(currentQuestionIndex + 1);
    }
  };

  // Calculate and display results
  const completeAssessment = () => {
    const results = calculateMaturityLevels(responses, activeQuestions);
    setResults(results);
    setAssessmentCompleted(true);
  };

  // Reset assessment
  const resetAssessment = () => {
    setResponses({});
    setAssessmentMode(null);
    setTargetLevel(null);
    setCurrentQuestionIndex(0);
    setAssessmentStarted(false);
    setAssessmentCompleted(false);
    setActiveQuestions([]);
    setResults(null);
  };

  const contextValue = {
    responses,
    assessmentMode,
    targetLevel,
    currentQuestionIndex,
    assessmentStarted,
    assessmentCompleted,
    activeQuestions,
    results,
    startAssessment,
    answerQuestion,
    completeAssessment,
    resetAssessment,
    currentQuestion: activeQuestions[currentQuestionIndex] || null,
    totalQuestions: activeQuestions.length,
    progress: activeQuestions.length ? Math.round((currentQuestionIndex / activeQuestions.length) * 100) : 0
  };

  return (
    <AssessmentContext.Provider value={contextValue}>
      {children}
    </AssessmentContext.Provider>
  );
};

export default AssessmentContext;