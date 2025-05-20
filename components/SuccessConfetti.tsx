import React, { useEffect, useState } from 'react';
import { motion } from 'framer-motion';

interface ConfettiPiece {
  id: number;
  x: number;
  delay: number;
  duration: number;
  color: string;
  size: number;
  rotation: number;
  type: 'circle' | 'square' | 'triangle';
}

interface SuccessConfettiProps {
  show: boolean;
}

const SuccessConfetti: React.FC<SuccessConfettiProps> = ({ show }) => {
  const [confetti, setConfetti] = useState<ConfettiPiece[]>([]);
  
  useEffect(() => {
    if (show) {
      // Generate confetti pieces
      const pieces: ConfettiPiece[] = [];
      const colors = ['#4CAF50', '#8BC34A', '#CDDC39', '#FFEB3B', '#FFC107'];
      
      for (let i = 0; i < 50; i++) {
        pieces.push({
          id: i,
          x: Math.random() * 100,
          delay: Math.random() * 0.3,
          duration: 1 + Math.random() * 2,
          color: colors[Math.floor(Math.random() * colors.length)],
          size: 5 + Math.random() * 10,
          rotation: Math.random() * 360,
          type: ['circle', 'square', 'triangle'][Math.floor(Math.random() * 3)] as 'circle' | 'square' | 'triangle'
        });
      }
      
      setConfetti(pieces);
      
      // Clear confetti after animation completes
      const timer = setTimeout(() => {
        setConfetti([]);
      }, 3000);
      
      return () => clearTimeout(timer);
    }
  }, [show]);
  
  const renderConfettiPiece = (piece: ConfettiPiece) => {
    switch (piece.type) {
      case 'circle':
        return (
          <motion.div
            key={piece.id}
            style={{
              position: 'absolute',
              left: `${piece.x}%`,
              top: '-5%',
              width: `${piece.size}px`,
              height: `${piece.size}px`,
              borderRadius: '50%',
              backgroundColor: piece.color,
              zIndex: 100
            }}
            initial={{ top: '-5%', rotate: 0 }}
            animate={{ 
              top: '105%', 
              rotate: piece.rotation,
              x: [0, Math.random() * 100 - 50, Math.random() * 100 - 50, Math.random() * 100 - 50],
              opacity: [1, 1, 0.8, 0]
            }}
            transition={{ 
              duration: piece.duration, 
              delay: piece.delay, 
              ease: 'easeIn' 
            }}
          />
        );
      case 'square':
        return (
          <motion.div
            key={piece.id}
            style={{
              position: 'absolute',
              left: `${piece.x}%`,
              top: '-5%',
              width: `${piece.size}px`,
              height: `${piece.size}px`,
              backgroundColor: piece.color,
              zIndex: 100
            }}
            initial={{ top: '-5%', rotate: 0 }}
            animate={{ 
              top: '105%', 
              rotate: piece.rotation,
              x: [0, Math.random() * 100 - 50, Math.random() * 100 - 50, Math.random() * 100 - 50],
              opacity: [1, 1, 0.8, 0]
            }}
            transition={{ 
              duration: piece.duration, 
              delay: piece.delay, 
              ease: 'easeIn' 
            }}
          />
        );
      case 'triangle':
        return (
          <motion.div
            key={piece.id}
            style={{
              position: 'absolute',
              left: `${piece.x}%`,
              top: '-5%',
              width: 0,
              height: 0,
              borderLeft: `${piece.size/2}px solid transparent`,
              borderRight: `${piece.size/2}px solid transparent`,
              borderBottom: `${piece.size}px solid ${piece.color}`,
              zIndex: 100
            }}
            initial={{ top: '-5%', rotate: 0 }}
            animate={{ 
              top: '105%', 
              rotate: piece.rotation,
              x: [0, Math.random() * 100 - 50, Math.random() * 100 - 50, Math.random() * 100 - 50],
              opacity: [1, 1, 0.8, 0]
            }}
            transition={{ 
              duration: piece.duration, 
              delay: piece.delay, 
              ease: 'easeIn' 
            }}
          />
        );
      default:
        return null;
    }
  };
  
  if (!show || confetti.length === 0) return null;
  
  return (
    <div 
      style={{ 
        position: 'fixed', 
        top: 0, 
        left: 0, 
        width: '100%', 
        height: '100%', 
        pointerEvents: 'none',
        overflow: 'hidden'
      }}
    >
      {confetti.map(piece => renderConfettiPiece(piece))}
    </div>
  );
};

export default SuccessConfetti; 