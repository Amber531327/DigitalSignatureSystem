import React, { useEffect, useRef } from 'react';
import { motion } from 'framer-motion';

interface VerificationBadgeProps {
  show: boolean;
}

const VerificationBadge: React.FC<VerificationBadgeProps> = ({ show }) => {
  if (!show) return null;
  
  return (
    <motion.div
      className="verification-badge"
      initial={{ scale: 0, rotate: -30 }}
      animate={{ scale: 1, rotate: 0 }}
      transition={{ 
        type: 'spring', 
        stiffness: 260, 
        damping: 20, 
        duration: 0.8 
      }}
      style={{
        position: 'absolute',
        top: '20px',
        right: '20px',
        zIndex: 100,
        transformOrigin: 'top right',
        perspective: '1000px'
      }}
    >
      <motion.div
        className="badge-inner"
        animate={{ 
          rotateY: [0, 10, 0, -10, 0],
          rotateX: [0, 5, 0, -5, 0]
        }}
        transition={{ 
          repeat: Infinity, 
          duration: 5, 
          ease: 'easeInOut' 
        }}
        style={{
          background: 'linear-gradient(135deg, #4CAF50, #2ecc71)',
          color: 'white',
          padding: '15px 25px',
          borderRadius: '10px',
          boxShadow: '0 10px 25px rgba(0, 0, 0, 0.2), 0 5px 10px rgba(0, 0, 0, 0.1)',
          display: 'flex',
          flexDirection: 'column',
          alignItems: 'center',
          justifyContent: 'center',
          transformStyle: 'preserve-3d'
        }}
      >
        <svg 
          xmlns="http://www.w3.org/2000/svg" 
          width="64" 
          height="64" 
          viewBox="0 0 24 24" 
          fill="none" 
          stroke="currentColor" 
          strokeWidth="2" 
          strokeLinecap="round" 
          strokeLinejoin="round"
          style={{ 
            marginBottom: '10px',
            filter: 'drop-shadow(0 2px 5px rgba(0, 0, 0, 0.2))'
          }}
        >
          <path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"></path>
          <polyline points="22 4 12 14.01 9 11.01"></polyline>
        </svg>
        <div style={{ fontSize: '18px', fontWeight: 'bold', textAlign: 'center' }}>
          数字签名验证成功
        </div>
        <div style={{ fontSize: '14px', opacity: 0.8, marginTop: '5px' }}>
          消息内容未被篡改
        </div>
      </motion.div>
    </motion.div>
  );
};

export default VerificationBadge; 