// Calculate maturity levels for each strategy based on responses
export const calculateMaturityLevels = (responses, questions) => {
  // Group questions by strategy
  const strategiesQuestions = questions.reduce((acc, question) => {
    if (!acc[question.strategy]) {
      acc[question.strategy] = {};
    }
    
    if (!acc[question.strategy][question.level]) {
      acc[question.strategy][question.level] = [];
    }
    
    acc[question.strategy][question.level].push(question);
    return acc;
  }, {});
  
  // Calculate maturity levels for each strategy
  const results = {};
  
  Object.keys(strategiesQuestions).forEach(strategy => {
    results[strategy] = {
      maturityLevel: 0,
      compliance: {},
      gaps: {},
      achievedLevels: new Set()
    };
    
    let allPreviousLevelsAchieved = true;
    
    // Calculate compliance and gaps for each level independently
    for (let level = 1; level <= 3; level++) {
      const levelQuestions = strategiesQuestions[strategy][level] || [];
      const levelResponses = levelQuestions.map(q => responses[q.id]);
      
      // Calculate compliance percentage
      const totalQuestions = levelQuestions.length;
      const positiveResponses = levelResponses.filter(r => r === 'yes').length;
      const compliancePercentage = totalQuestions ? (positiveResponses / totalQuestions) * 100 : 0;
      
      results[strategy].compliance[level] = compliancePercentage;
      
      // Identify gaps (questions not answered with 'yes')
      results[strategy].gaps[level] = levelQuestions
        .filter(q => responses[q.id] !== 'yes')
        .map(q => q.text);
      
      // A level is only achieved if it's 100% compliant AND all previous levels were achieved
      if (compliancePercentage === 100 && allPreviousLevelsAchieved) {
        results[strategy].achievedLevels.add(level);
        results[strategy].maturityLevel = level;
      } else {
        allPreviousLevelsAchieved = false;
      }
    }
  });
  
  // Calculate overall metrics
  const overallMaturityLevel = Math.min(...Object.values(results).map(r => r.maturityLevel));
  const overallCompliancePercentage = Object.values(results).reduce((sum, strategy) => {
    const allLevels = Object.values(strategy.compliance);
    const strategyCompliance = allLevels.reduce((s, c) => s + c, 0) / allLevels.length;
    return sum + strategyCompliance;
  }, 0) / Object.keys(results).length;
  
  return {
    strategies: results,
    overallMaturityLevel,
    overallCompliancePercentage,
    strategiesAtTarget: Object.values(results).filter(s => s.maturityLevel >= 1).length
  };
};