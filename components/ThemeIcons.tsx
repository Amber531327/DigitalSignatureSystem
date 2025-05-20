import React from 'react';
import { motion } from 'framer-motion';

interface IconProps {  size?: number;  color?: string;  className?: string;  verified?: boolean;}

export const MessageIcon: React.FC<IconProps> = ({ 
  size = 40, 
  color = '#3498db',
  className = '' 
}) => {
  return (
    <motion.div 
      className={`theme-icon message-icon ${className}`}
      whileHover={{ scale: 1.1 }}
      style={{
        width: size,
        height: size,
        display: 'inline-flex',
        justifyContent: 'center',
        alignItems: 'center'
      }}
    >
      <svg 
        xmlns="http://www.w3.org/2000/svg" 
        viewBox="0 0 24 24" 
        width={size} 
        height={size} 
        fill="none" 
        stroke={color} 
        strokeWidth="2" 
        strokeLinecap="round" 
        strokeLinejoin="round"
      >
        <path d="M4 4h16c1.1 0 2 .9 2 2v12c0 1.1-.9 2-2 2H4c-1.1 0-2-.9-2-2V6c0-1.1.9-2 2-2z"></path>
        <polyline points="22,6 12,13 2,6"></polyline>
      </svg>
    </motion.div>
  );
};

export const KeyIcon: React.FC<IconProps> = ({ 
  size = 40, 
  color = '#e67e22',
  className = '' 
}) => {
  return (
    <motion.div 
      className={`theme-icon key-icon ${className}`}
      whileHover={{ scale: 1.1 }}
      style={{
        width: size,
        height: size,
        display: 'inline-flex',
        justifyContent: 'center',
        alignItems: 'center'
      }}
    >
      <svg 
        xmlns="http://www.w3.org/2000/svg" 
        viewBox="0 0 24 24" 
        width={size} 
        height={size} 
        fill="none" 
        stroke={color} 
        strokeWidth="2" 
        strokeLinecap="round" 
        strokeLinejoin="round"
      >
        <path d="M21 2l-2 2m-7.61 7.61a5.5 5.5 0 1 1-7.778 7.778 5.5 5.5 0 0 1 7.777-7.777zm0 0L15.5 7.5m0 0l3 3L22 7l-3-3m-3.5 3.5L19 4"></path>
      </svg>
    </motion.div>
  );
};

export const HashIcon: React.FC<IconProps> = ({ 
  size = 40, 
  color = '#9b59b6',
  className = '' 
}) => {
  return (
    <motion.div 
      className={`theme-icon hash-icon ${className}`}
      whileHover={{ scale: 1.1 }}
      style={{
        width: size,
        height: size,
        display: 'inline-flex',
        justifyContent: 'center',
        alignItems: 'center'
      }}
    >
      <svg 
        xmlns="http://www.w3.org/2000/svg" 
        viewBox="0 0 24 24" 
        width={size} 
        height={size} 
        fill="none" 
        stroke={color} 
        strokeWidth="2" 
        strokeLinecap="round" 
        strokeLinejoin="round"
      >
        <line x1="4" y1="9" x2="20" y2="9"></line>
        <line x1="4" y1="15" x2="20" y2="15"></line>
        <line x1="10" y1="3" x2="8" y2="21"></line>
        <line x1="16" y1="3" x2="14" y2="21"></line>
      </svg>
    </motion.div>
  );
};

export const SignatureIcon: React.FC<IconProps> = ({ 
  size = 40, 
  color = '#2ecc71',
  className = '' 
}) => {
  return (
    <motion.div 
      className={`theme-icon signature-icon ${className}`}
      whileHover={{ scale: 1.1 }}
      style={{
        width: size,
        height: size,
        display: 'inline-flex',
        justifyContent: 'center',
        alignItems: 'center'
      }}
    >
      <svg 
        xmlns="http://www.w3.org/2000/svg" 
        viewBox="0 0 24 24" 
        width={size} 
        height={size} 
        fill="none" 
        stroke={color} 
        strokeWidth="2" 
        strokeLinecap="round" 
        strokeLinejoin="round"
      >
        <path d="M3 17l6-6 4 4 8-8"></path>
        <path d="M14 7h7v7"></path>
      </svg>
    </motion.div>
  );
};

export const VerificationIcon: React.FC<IconProps> = ({ 
  size = 40, 
  color = '#f39c12',
  className = '',
  verified = false
}) => {
  return (
    <motion.div 
      className={`theme-icon verification-icon ${className}`}
      whileHover={{ scale: 1.1 }}
      style={{
        width: size,
        height: size,
        display: 'inline-flex',
        justifyContent: 'center',
        alignItems: 'center'
      }}
    >
      <svg 
        xmlns="http://www.w3.org/2000/svg" 
        viewBox="0 0 24 24" 
        width={size} 
        height={size} 
        fill="none" 
        stroke={verified ? '#2ecc71' : color} 
        strokeWidth="2" 
        strokeLinecap="round" 
        strokeLinejoin="round"
      >
        {verified ? (
          // Checkmark for verified
          <>
            <path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"></path>
            <polyline points="22 4 12 14.01 9 11.01"></polyline>
          </>
        ) : (
          // Shield for verification
          <>
            <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"></path>
          </>
        )}
      </svg>
    </motion.div>
  );
};

export const HackerIcon: React.FC<IconProps> = ({ 
  size = 40, 
  color = '#e74c3c',
  className = '' 
}) => {
  return (
    <motion.div 
      className={`theme-icon hacker-icon ${className}`}
      whileHover={{ scale: 1.1 }}
      animate={{ 
        rotate: [0, -5, 5, -3, 3, 0],
        transition: { repeat: Infinity, duration: 5, repeatType: 'loop' }
      }}
      style={{
        width: size,
        height: size,
        display: 'inline-flex',
        justifyContent: 'center',
        alignItems: 'center'
      }}
    >
      <svg 
        xmlns="http://www.w3.org/2000/svg" 
        viewBox="0 0 24 24" 
        width={size} 
        height={size} 
        fill="none" 
        stroke={color} 
        strokeWidth="2" 
        strokeLinecap="round" 
        strokeLinejoin="round"
      >
        <rect x="3" y="11" width="18" height="11" rx="2" ry="2"></rect>
        <path d="M7 11V7a5 5 0 0 1 10 0v4"></path>
        <line x1="8" y1="15" x2="10" y2="15"></line>
        <line x1="14" y1="15" x2="16" y2="15"></line>
      </svg>
    </motion.div>
  );
}; 