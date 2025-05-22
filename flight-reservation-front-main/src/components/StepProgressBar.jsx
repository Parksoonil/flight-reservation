import React from 'react';
import './StepProgressBar.css';

function StepProgressBar({ steps, currentStep }) {
    return (
        <div className="step-text-progress-bar">
            {steps.map((step, index) => (
                <React.Fragment key={index}>
          <span className={`step-text ${index <= currentStep ? 'active' : ''}`}>
            {step}
          </span>
                    {index < steps.length - 1 && (
                        <span
                            className={`step-separator ${index < currentStep ? 'active' : ''}`}
                        >
              ------
            </span>
                    )}
                </React.Fragment>
            ))}
        </div>
    );
}
export default StepProgressBar;
