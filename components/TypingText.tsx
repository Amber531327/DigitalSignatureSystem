import React, { useState, useEffect } from 'react';

interface TypingTextProps {
  text: string;
  typingSpeed?: number;
  className?: string;
  delay?: number;
  showCursor?: boolean;
}

const TypingText: React.FC<TypingTextProps> = ({ 
  text, 
  typingSpeed = 50, 
  className = '', 
  delay = 0,
  showCursor = true
}) => {
  const [displayText, setDisplayText] = useState('');
  const [isTyping, setIsTyping] = useState(false);
  
  useEffect(() => {
    let timeout: NodeJS.Timeout;
    let interval: NodeJS.Timeout;
    
    // Reset and start typing when text changes
    setDisplayText('');
    setIsTyping(false);
    
    // Initial delay before typing starts
    timeout = setTimeout(() => {
      setIsTyping(true);
      
      let i = 0;
      // Start typing one character at a time
      interval = setInterval(() => {
        if (i < text.length) {
          setDisplayText(prev => prev + text.charAt(i));
          i++;
        } else {
          clearInterval(interval);
          setIsTyping(false);
        }
      }, typingSpeed);
    }, delay);
    
    // Cleanup
    return () => {
      clearTimeout(timeout);
      clearInterval(interval);
    };
  }, [text, typingSpeed, delay]);
  
  return (
    <span className={`typing-text ${className}`}>
      {displayText}
      {showCursor && isTyping && (
        <span className="typing-cursor" style={{ animation: 'blink 1s step-end infinite' }}>|</span>
      )}
      <style jsx>{`
        @keyframes blink {
          from, to {
            opacity: 1;
          }
          50% {
            opacity: 0;
          }
        }
        
        .typing-text {
          display: inline-block;
        }
        
        .typing-cursor {
          display: inline-block;
          margin-left: 2px;
          font-weight: bold;
        }
      `}</style>
    </span>
  );
};

export default TypingText; 