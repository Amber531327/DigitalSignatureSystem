import React, { useState, useEffect } from 'react';
import { motion } from 'framer-motion';
import { AlgorithmFactory, KeyPair, SignatureResult } from '../algorithms';

// We'll use dynamic imports for browser-only libraries
let JSEncrypt: any = null;
let EC: any = null;

interface StepActionsProps {
  steps: string[];
  currentStep: number;
  onStepChange: (step: number) => void;
  algorithm: string;
  message: string;
  setMessage: (message: string) => void;
  setKeys: (keys: any) => void;
  keys: any;
  setSignature: (signature: any) => void;
  signature: any;
  setVerificationResult: (result: boolean | null) => void;
  setAnimation: (animation: string) => void;
  attackMode?: boolean;
  modifiedMessage?: string;
}

const StepActions: React.FC<StepActionsProps> = ({
  steps,
  currentStep,
  onStepChange,
  algorithm,
  message,
  setMessage,
  setKeys,
  keys,
  setSignature,
  signature,
  setVerificationResult,
  setAnimation,
  attackMode,
  modifiedMessage,
}) => {
  const [messageInput, setMessageInput] = useState('');
  const [isClient, setIsClient] = useState(false);
  const [error, setError] = useState<string | null>(null);

  // Load browser-only libraries after component mounts
  useEffect(() => {
    // Only import these libraries on the client side
    import('jsencrypt').then(module => {
      JSEncrypt = module.default;
    });
    
    import('elliptic').then(module => {
      EC = module.ec;
    });
    
    setIsClient(typeof window !== 'undefined');
  }, []);

  const handleStepClick = (step: number) => {
    if (step === 0) {
      // Message input step can be accessed anytime
      onStepChange(step);
    } else if (step <= currentStep + 1 && (step === 1 || (step > 1 && message))) {
      // Other steps need to follow order and require message
      onStepChange(step);
    }
  };

  const handleMessageSubmit = () => {
    if (messageInput.trim()) {
      setMessage(messageInput.trim());
      setAnimation('message-submitted');
      
      // Removed automatic step transition - user will manually click the next step
    }
  };

  const generateKeys = async () => {
    if (!isClient) return;
    
    try {
      setError(null);
      // 获取当前选择的算法实例
      const cryptoAlgorithm = AlgorithmFactory.getAlgorithm(algorithm);
      // 生成密钥对
      const generatedKeys = await cryptoAlgorithm.generateKeys();
      
      setKeys(generatedKeys);
      setAnimation('keys-generated');
      
      // Removed automatic step transition - user will manually click the next step
    } catch (err) {
      console.error(`生成${algorithm}密钥时出错:`, err);
      setError(`生成密钥时出错: ${err instanceof Error ? err.message : String(err)}`);
    }
  };

  const generateSignature = async () => {
    if (!isClient || !keys) return;
    
    try {
      setError(null);
      // 获取当前选择的算法实例
      const cryptoAlgorithm = AlgorithmFactory.getAlgorithm(algorithm);
      // 生成签名
      const generatedSignature = await cryptoAlgorithm.sign(message, keys);
      
      setSignature(generatedSignature);
      
      // Trigger the animation for signature generated
      setAnimation('signature-generated');
      
      // Removed automatic step transition - user will manually click the next step
    } catch (err) {
      console.error(`生成${algorithm}签名时出错:`, err);
      setError(`生成签名时出错: ${err instanceof Error ? err.message : String(err)}`);
    }
  };

  const verifySignature = async () => {
    if (!isClient || !keys || !signature) return;
    
    try {
      setError(null);
      // 获取当前选择的算法实例
      const cryptoAlgorithm = AlgorithmFactory.getAlgorithm(algorithm);
      
      // In attack mode, check if modified message is the same as original
      if (attackMode) {
        // If modified message exactly matches the original message, then verification should succeed
        if (modifiedMessage === message) {
          // Verify with original message
          const result = await cryptoAlgorithm.verify(message, signature, keys);
          setVerificationResult(result);
          setAnimation(result ? 'verification-success' : 'verification-failure');
        } else {
          // Modified message is different, verification should fail
          setVerificationResult(false);
          setAnimation('verification-failure');
        }
        return;
      }
      
      // Regular verification logic (non-attack mode)
      const result = await cryptoAlgorithm.verify(message, signature, keys);
      
      setVerificationResult(result);
      setAnimation(result ? 'verification-success' : 'verification-failure');
    } catch (err) {
      console.error(`验证${algorithm}签名时出错:`, err);
      setError(`验证签名时出错: ${err instanceof Error ? err.message : String(err)}`);
      setVerificationResult(false);
      setAnimation('verification-failure');
    }
  };

  // Render current step content
  const renderStepContent = () => {
    switch (currentStep) {
      case 0: // Message Input
        return (
          <div className="step-content message-input">
            <textarea
              value={messageInput}
              onChange={(e) => setMessageInput(e.target.value)}
              placeholder="输入要签名的消息"
              rows={4}
            />
            <motion.button
              onClick={handleMessageSubmit}
              disabled={!messageInput.trim()}
              whileHover={{ scale: 1.05 }}
              whileTap={{ scale: 0.95 }}
              className="action-button"
            >
              提交消息
            </motion.button>
          </div>
        );
      case 1: // Key Generation
        return (
          <div className="step-content key-generation">
            <motion.button
              onClick={generateKeys}
              whileHover={{ scale: 1.05 }}
              whileTap={{ scale: 0.95 }}
              className="action-button"
              disabled={!isClient}
            >
              生成 {algorithm} 密钥对
            </motion.button>
          </div>
        );
      case 2: // Signature Generation
        return (
          <div className="step-content signature-generation">
            <motion.button
              onClick={generateSignature}
              whileHover={{ scale: 1.05 }}
              whileTap={{ scale: 0.95 }}
              className="action-button"
              disabled={!isClient || !keys}
            >
              生成数字签名
            </motion.button>
          </div>
        );
      case 3: // Signature Verification
        return (
          <div className="step-content signature-verification">
            <motion.button
              onClick={verifySignature}
              whileHover={{ scale: 1.05 }}
              whileTap={{ scale: 0.95 }}
              className="action-button"
              disabled={!isClient || !keys || !signature}
            >
              验证数字签名
            </motion.button>
          </div>
        );
      default:
        return null;
    }
  };

  return (
    <div className="step-actions">
      <div className="step-buttons">
        {steps.map((step, index) => (
          <motion.button
            key={index}
            className={`step-button ${currentStep === index ? 'active' : ''} ${
              index <= currentStep ? 'accessible' : 'locked'
            }`}
            onClick={() => handleStepClick(index)}
            whileHover={{ scale: index <= currentStep + 1 ? 1.05 : 1 }}
            whileTap={{ scale: index <= currentStep + 1 ? 0.95 : 1 }}
            disabled={index > currentStep + 1}
          >
            {step}
          </motion.button>
        ))}
      </div>
      
      {error && <div className="error-message">{error}</div>}
      
      {renderStepContent()}
    </div>
  );
};

// Add CryptoJS for hashing
const CryptoJS = {
  SHA256: (message: string) => {
    let hash = 0;
    for (let i = 0; i < message.length; i++) {
      hash = ((hash << 5) - hash) + message.charCodeAt(i);
      hash |= 0;
    }
    return hash.toString(16);
  }
};

export default StepActions; 