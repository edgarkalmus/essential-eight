import React from 'react';

const Introduction = ({ onStartAssessment }) => {
  return (
    <div className="max-w-4xl mx-auto p-4">
      <h2 className="text-2xl font-bold text-primary mb-4">About the Essential Eight</h2>
      <p className="mb-6">
        The Essential Eight is a set of mitigation strategies developed by the Australian Cyber Security Centre (ACSC) to help organizations protect themselves against various cyber threats. These strategies can be implemented at different maturity levels (0-3), with higher levels providing stronger security posture.
      </p>
      
      <h3 className="text-xl font-bold text-primary mb-3">The Eight Mitigation Strategies</h3>
      <div className="grid grid-cols-1 md:grid-cols-2 gap-4 mb-8">
        {[
          { number: 1, name: "Application Control", desc: "Prevent execution of unapproved/malicious programs" },
          { number: 2, name: "Patch Applications", desc: "Patch/mitigate computer vulnerabilities in applications" },
          { number: 3, name: "Configure MS Office Macros", desc: "Block macros from the Internet and restricting permission" },
          { number: 4, name: "User Application Hardening", desc: "Configure web browsers and other applications securely" },
          { number: 5, name: "Restrict Admin Privileges", desc: "Restrict administrative privileges to operating systems and applications" },
          { number: 6, name: "Patch Operating Systems", desc: "Patch/mitigate computer vulnerabilities in operating systems" },
          { number: 7, name: "Multi-factor Authentication", desc: "Strengthen user authentication with multi-factor authentication" },
          { number: 8, name: "Regular Backups", desc: "Daily backups of important data, software, and configuration settings" }
        ].map(strategy => (
          <div key={strategy.number} className="bg-white p-4 rounded-lg shadow-md">
            <div className="flex items-start">
              <div className="bg-primary text-white rounded-full w-8 h-8 flex items-center justify-center mr-3 flex-shrink-0">
                <span className="font-bold">{strategy.number}</span>
              </div>
              <div>
                <h4 className="font-bold text-primary">{strategy.name}</h4>
                <p className="text-gray-600">{strategy.desc}</p>
              </div>
            </div>
          </div>
        ))}
      </div>
      
      <h3 className="text-xl font-bold text-primary mb-3">Maturity Levels Explained</h3>
      <div className="grid grid-cols-1 md:grid-cols-2 gap-4 mb-8">
        {[
          { level: 0, name: "Maturity Level 0", desc: "Weaknesses in overall cyber security posture that could be exploited." },
          { level: 1, name: "Maturity Level 1", desc: "Provides mitigation against adversaries using commodity capabilities." },
          { level: 2, name: "Maturity Level 2", desc: "Provides mitigation against adversaries using sophisticated capabilities." },
          { level: 3, name: "Maturity Level 3", desc: "Provides mitigation against adversaries using advanced tradecraft and techniques." }
        ].map(level => (
          <div key={level.level} className="bg-white p-4 rounded-lg shadow-md">
            <h4 className={`font-bold text-maturity-${level.level} mb-1`}>Level {level.level}</h4>
            <p className="text-gray-600">{level.desc}</p>
          </div>
        ))}
      </div>
      
      <div className="flex justify-center">
        <button 
          onClick={() => onStartAssessment()}
          className="px-6 py-3 bg-primary text-white font-bold rounded-lg shadow-md hover:bg-opacity-90 transition-all"
        >
          Begin Assessment
        </button>
      </div>
    </div>
  );
};

export default Introduction;