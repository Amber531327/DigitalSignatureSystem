import React from 'react';
import { motion } from 'framer-motion';

interface AlgorithmSelectorProps {
  selectedAlgorithm: string;
  onSelectAlgorithm: (algorithm: string) => void;
}

const AlgorithmSelector: React.FC<AlgorithmSelectorProps> = ({
  selectedAlgorithm,
  onSelectAlgorithm,
}) => {
  const algorithms = ['RSA', 'DSA', 'ECDSA'];

  return (
    <div className="algorithm-selector">
      {algorithms.map((algorithm) => (
        <motion.button
          key={algorithm}
          className={`algorithm-button ${selectedAlgorithm === algorithm ? 'selected' : ''}`}
          onClick={() => onSelectAlgorithm(algorithm)}
          whileHover={{ scale: 1.05 }}
          whileTap={{ scale: 0.95 }}
        >
          {algorithm}
        </motion.button>
      ))}
    </div>
  );
};

export default AlgorithmSelector; 