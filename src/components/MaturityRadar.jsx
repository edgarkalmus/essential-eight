import React from 'react';
import { Radar } from 'react-chartjs-2';
import { Chart as ChartJS, RadialLinearScale, PointElement, LineElement, Filler, Tooltip, Legend } from 'chart.js';

// Register Chart.js components
ChartJS.register(RadialLinearScale, PointElement, LineElement, Filler, Tooltip, Legend);

const MaturityRadar = ({ results }) => {
  const strategies = Object.keys(results.strategies);
  const maturityLevels = strategies.map(strategy => results.strategies[strategy].maturityLevel);
  
  const data = {
    labels: strategies,
    datasets: [
      {
        label: 'Maturity Level',
        data: maturityLevels,
        backgroundColor: 'rgba(59, 130, 246, 0.2)',
        borderColor: 'rgba(59, 130, 246, 1)',
        borderWidth: 2,
        pointBackgroundColor: 'rgba(59, 130, 246, 1)',
        pointBorderColor: '#fff',
        pointHoverBackgroundColor: '#fff',
        pointHoverBorderColor: 'rgba(59, 130, 246, 1)',
      },
    ],
  };
  
  const options = {
    scales: {
      r: {
        angleLines: {
          display: true
        },
        suggestedMin: 0,
        suggestedMax: 3,
        ticks: {
          stepSize: 1,
          callback: function(value) {
            return value;
          }
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
            return `Level: ${context.raw}`;
          }
        }
      }
    },
    maintainAspectRatio: false
  };
  
  return (
    <div className="h-[300px]">
      <Radar data={data} options={options} />
    </div>
  );
};

export default MaturityRadar;