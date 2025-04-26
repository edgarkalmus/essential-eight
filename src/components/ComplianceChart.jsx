import React from 'react';
import { Bar } from 'react-chartjs-2';
import { Chart as ChartJS, CategoryScale, LinearScale, BarElement, Title, Tooltip, Legend } from 'chart.js';

// Register Chart.js components
ChartJS.register(CategoryScale, LinearScale, BarElement, Title, Tooltip, Legend);

const ComplianceChart = ({ results }) => {
  const strategies = Object.keys(results.strategies);
  
  // Calculate average compliance for each strategy across all levels
  const complianceData = strategies.map(strategy => {
    const levels = Object.values(results.strategies[strategy].compliance);
    return levels.reduce((sum, val) => sum + val, 0) / levels.length;
  });
  
  const data = {
    labels: strategies,
    datasets: [
      {
        label: 'Compliance %',
        data: complianceData,
        backgroundColor: 'rgba(59, 130, 246, 0.7)',
        borderColor: 'rgba(59, 130, 246, 1)',
        borderWidth: 1,
      },
    ],
  };
  
  const options = {
    indexAxis: 'y',
    scales: {
      x: {
        beginAtZero: true,
        max: 100,
        title: {
          display: true,
          text: 'Compliance Percentage'
        }
      }
    },
    plugins: {
      legend: {
        display: false
      },
      tooltip: {
        callbacks: {
          label: function(context) {
            return `${Math.round(context.raw)}% compliant`;
          }
        }
      }
    },
    maintainAspectRatio: false
  };
  
  return (
    <div className="h-[300px]">
      <Bar data={data} options={options} />
    </div>
  );
};

export default ComplianceChart;