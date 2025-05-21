import { useState, useEffect } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import AlgorithmSelector from '../components/AlgorithmSelector';
import StepActions from '../components/StepActions';
import VisualizationArea from '../components/VisualizationArea';
import UserRole from '../components/UserRole';
import SuccessConfetti from '../components/SuccessConfetti';
import ParticleBackground from '../components/ParticleBackground';


export default function Home() {
  // State for the selected algorithm
  const [algorithm, setAlgorithm] = useState('RSA');
  // State for the current step
  const [currentStep, setCurrentStep] = useState(0);
  // State for the message
  const [message, setMessage] = useState('');
  // State for keys
  const [keys, setKeys] = useState<any>(null);
  // State for signature
  const [signature, setSignature] = useState<any>(null);
  // State for verification result
  const [verificationResult, setVerificationResult] = useState<boolean | null>(null);
  // Animation state
  const [animation, setAnimation] = useState<string | null>(null);
  // Attack mode
  const [attackMode, setAttackMode] = useState(false);
  // Modified message
  const [modifiedMessage, setModifiedMessage] = useState('');
  // Show attack input
  const [showAttackInput, setShowAttackInput] = useState(false);
  // Modified message hash
  const [modifiedHash, setModifiedHash] = useState<string | null>(null);

  const steps = ['输入消息', '密钥生成', '签名生成', '签名验证'];
  
  // Function to handle step changes
  const handleStepChange = (step: number) => {
    if (step <= currentStep + 1) {
      setCurrentStep(step);
    }
  };

  // Function to truncate message for display
  const getTruncatedMessage = () => {
    if (message.length > 10) {
      return `${message.substring(0, 10)}...`;
    }
    return message;
  };

  // Function to get hash display value
  const getHashDisplay = () => {
    if (signature && signature.messageHash) {
      return signature.messageHash.substring(0, 8) + '...';
    }
    return null;
  };

  // Function to get modified hash display value
  const getModifiedHashDisplay = () => {
    if (modifiedHash) {
      return modifiedHash.substring(0, 8) + '...';
    }
    return null;
  };

  // Function to get signature display value
  const getSignatureDisplay = () => {
    if (signature) {
      if (algorithm === 'RSA' && signature.signature) {
        return signature.signature.substring(0, 8) + '...';
      } else if (algorithm === 'DSA') {
        return `r: ${signature.r?.substring(0, 8)}..., s: ${signature.s?.substring(0, 8)}...`;
      } else if (algorithm === 'ECDSA' && signature.signature) {
        return signature.signature.substring(0, 8) + '...';
      }
    }
    return null;
  };

  // Function to handle starting attack
  const handleStartAttack = () => {
    // Clear any existing verification results when starting an attack
    setVerificationResult(null);
    // Reset animation state to remove any verification indicators
    setAnimation(null);
    // Show attack input and set attack mode
    setShowAttackInput(true);
    setAttackMode(true);
  };

  // Function to handle submitting modified message
  const handleModifiedMessageSubmit = async () => {
    if (!modifiedMessage) return;
    
    // Reset verification result to ensure no verification indicators appear
    setVerificationResult(null);
    
    // Generate hash for modified message
    try {
      const encoder = new TextEncoder();
      const data = encoder.encode(modifiedMessage);
      const hashBuffer = await crypto.subtle.digest('SHA-256', data);
      const hashArray = Array.from(new Uint8Array(hashBuffer));
      const hashHex = hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
      
      setModifiedHash(hashHex);
      setShowAttackInput(false);
      // Use 'attack-completed' as animation name instead of anything related to verification
      setAnimation('attack-completed');
    } catch (err) {
      console.error('Error generating hash:', err);
      // Fallback simple hash if WebCrypto API fails
      const hashHex = simpleHash(modifiedMessage);
      setModifiedHash(hashHex);
      setShowAttackInput(false);
      setAnimation('attack-completed');
    }
  };

  // Simple hash function fallback
  const simpleHash = (text: string) => {
    let hash = 0;
    for (let i = 0; i < text.length; i++) {
      const char = text.charCodeAt(i);
      hash = ((hash << 5) - hash) + char;
      hash = hash & hash;
    }
    return Math.abs(hash).toString(16).padStart(8, '0').repeat(8).substring(0, 64);
  };

  return (
    <div className="container">
      {/* 添加粒子背景 */}
      <ParticleBackground />
      
      <h1 className="title">
        数字签名可视化系统
      </h1>
      
      <AlgorithmSelector 
        selectedAlgorithm={algorithm} 
        onSelectAlgorithm={setAlgorithm} 
      />
      
      <div className="main-content">
        <div className="workflow">
          <StepActions 
            steps={steps}
            currentStep={currentStep} 
            onStepChange={handleStepChange} 
            algorithm={algorithm}
            message={message}
            setMessage={setMessage}
            setKeys={setKeys}
            keys={keys}
            setSignature={setSignature}
            signature={signature}
            setVerificationResult={setVerificationResult}
            setAnimation={setAnimation}
            attackMode={attackMode}
            modifiedMessage={modifiedMessage}
          />
          
          <VisualizationArea 
            currentStep={currentStep}
            algorithm={algorithm}
            message={message}
            keys={keys}
            signature={signature}
            verificationResult={verificationResult}
            animation={animation}
            attackMode={attackMode}
            modifiedMessage={modifiedMessage}
            attackedMessageHash={modifiedHash || undefined}
          />
        </div>
        
        <div className="user-roles">
          <UserRole type="sender" position="left" />
          <UserRole type="receiver" position="right" />
          
          <AnimatePresence>
            {message && (
              <motion.div 
                className="message-flow-container"
                initial={{ opacity: 0 }}
                animate={{ opacity: 1 }}
                exit={{ opacity: 0 }}
                transition={{ duration: 0.3 }}
              >
                <motion.div 
                  className="message-flow-arrow"
                  initial={{ scaleX: 0 }}
                  animate={{ scaleX: 1 }}
                  transition={{ duration: 0.8 }}
                />
                <motion.div 
                  initial={{ scale: 0.8 }}
                  animate={{ scale: 1 }}
                  transition={{ duration: 0.5, delay: 0.3 }}
                >
                  <div className="message-icon">
                    <div className="message-paper">
                      ✉️
                    </div>
                  </div>
                </motion.div>
                <motion.div 
                  className="message-container"
                  initial={{ opacity: 0, y: -10 }}
                  animate={{ opacity: 1, y: 0 }}
                  transition={{ duration: 0.5, delay: 0.6 }}
                >
                  <div className="message-content">
                    消息的内容：{getTruncatedMessage()}
                  </div>
                </motion.div>
              </motion.div>
            )}
          </AnimatePresence>
          
          <AnimatePresence>
            {currentStep >= 2 && signature && (
              <>
                {/* Hash Visualization */}
                <motion.div 
                  className="hash-flow-container"
                  initial={{ opacity: 0 }}
                  animate={{ opacity: 1 }}
                  exit={{ opacity: 0 }}
                  transition={{ duration: 0.3, delay: 0.2 }}
                >
                  <motion.div 
                    className="hash-flow-arrow"
                    initial={animation === 'signature-generated' ? { scaleX: 0 } : { scaleX: 1 }}
                    animate={{ scaleX: 1 }}
                    transition={{ duration: 0.8 }}
                  />
                  <motion.div 
                    initial={animation === 'signature-generated' ? { scale: 0.8 } : { scale: 1 }}
                    animate={{ scale: 1 }}
                    transition={{ duration: 0.5, delay: 0.3 }}
                  >
                    <div className="hash-icon">
                      <div className="hash-symbol">
                        #
                      </div>
                    </div>
                  </motion.div>
                  <motion.div 
                    className="hash-value-container"
                    initial={animation === 'signature-generated' ? { opacity: 0, y: -10 } : { opacity: 1, y: 0 }}
                    animate={{ opacity: 1, y: 0 }}
                    transition={{ duration: 0.5, delay: 0.6 }}
                  >
                    <div className="hash-value-content">
                      哈希后的值：{getHashDisplay()}
                    </div>
                  </motion.div>
                </motion.div>
                
                {/* Signature Visualization */}
                <motion.div 
                  className="signature-flow-container"
                  initial={{ opacity: 0 }}
                  animate={{ opacity: 1 }}
                  exit={{ opacity: 0 }}
                  transition={{ duration: 0.3, delay: animation === 'signature-generated' ? 1.0 : 0.2 }}
                >
                  <motion.div 
                    className="signature-flow-arrow"
                    initial={animation === 'signature-generated' ? { scaleX: 0 } : { scaleX: 1 }}
                    animate={{ scaleX: 1 }}
                    transition={{ duration: 0.8 }}
                  />
                  <motion.div 
                    initial={animation === 'signature-generated' ? { scale: 0.8 } : { scale: 1 }}
                    animate={{ scale: 1 }}
                    transition={{ duration: 0.5, delay: 0.3 }}
                  >
                    <div className="signature-icon">
                      <div className="signature-symbol">
                        ✍️
                      </div>
                    </div>
                  </motion.div>
                  <motion.div 
                    className="signature-value-container"
                    initial={animation === 'signature-generated' ? { opacity: 0, y: -10 } : { opacity: 1, y: 0 }}
                    animate={{ opacity: 1, y: 0 }}
                    transition={{ duration: 0.5, delay: 0.6 }}
                  >
                    <div className="signature-value-content">
                      签名的值：{getSignatureDisplay()}
                    </div>
                  </motion.div>
                </motion.div>
              </>
            )}
          </AnimatePresence>
          
          {/* Verification Flow Visualization */}
          <AnimatePresence>
            {currentStep === 3 && signature && (
              <>
                {/* Arrow from Receiver to Signature Icon */}
                <motion.div 
                  className="receiver-to-signature-arrow"
                  initial={animation === 'verification-success' || animation === 'verification-failure' ? { scaleX: 0 } : { scaleX: 1 }}
                  animate={{ scaleX: 1 }}
                  transition={{ duration: 0.8 }}
                />
                
                {/* Arrow down from Signature */}
                <motion.div 
                  className="signature-verification-arrow"
                  initial={animation === 'verification-success' || animation === 'verification-failure' ? { scaleY: 0 } : { scaleY: 1 }}
                  animate={{ scaleY: 1 }}
                  transition={{ duration: 0.8, delay: 0.3 }}
                />
                
                {/* Arrow from Public Key to Signature Verification Process */}
                <motion.div 
                  className="pubkey-to-verification-arrow"
                  initial={animation === 'verification-success' || animation === 'verification-failure' ? { scaleX: 0 } : { scaleX: 1 }}
                  animate={{ scaleX: 1 }}
                  transition={{ duration: 0.8, delay: 0.6 }}
                />
                
                {/* Verification Result */}
                {(animation === 'verification-success' || animation === 'verification-failure') && verificationResult !== null && (
                  <motion.div 
                    className="verification-result-container"
                    initial={{ opacity: 0, y: -10 }}
                    animate={{ opacity: 1, y: 0 }}
                    transition={{ duration: 0.5, delay: 0.9 }}
                  >
                    <div className={`verification-result-content ${verificationResult ? 'success' : 'failure'}`}>
                      验证{verificationResult ? '成功' : '失败'}{verificationResult ? '✓' : '✗'}
                    </div>
                  </motion.div>
                )}

                {/* 验证成功时显示庆祝效果 */}
                <SuccessConfetti show={verificationResult === true && animation === 'verification-success'} />
                
               
              </>
            )}
          </AnimatePresence>
          
          {/* Attack Visualization */}
          <AnimatePresence>
            {currentStep === 3 && (attackMode || verificationResult === true) && (
              <motion.div 
                className="attack-button-container"
                initial={{ opacity: 0 }}
                animate={{ opacity: 1 }}
                exit={{ opacity: 0 }}
                transition={{ duration: 0.3 }}
              >
                <div className="hacker-icon">
                  <img src="/images/hacker.jpg" alt="Hacker" className="hacker-image" />
                </div>
                {!attackMode && (
                  <motion.button
                    className="attack-button"
                    onClick={handleStartAttack}
                    whileHover={{ scale: 1.05 }}
                    whileTap={{ scale: 0.95 }}
                  >
                    开始攻击
                  </motion.button>
                )}
              </motion.div>
            )}
          </AnimatePresence>
          
          {/* Attack Input Dialog */}
          <AnimatePresence>
            {showAttackInput && (
              <motion.div 
                className="attack-input-container"
                initial={{ opacity: 0, y: 20 }}
                animate={{ opacity: 1, y: 0 }}
                exit={{ opacity: 0, y: 20 }}
                transition={{ duration: 0.3 }}
              >
                <h3>篡改消息内容</h3>
                <textarea
                  value={modifiedMessage}
                  onChange={(e) => setModifiedMessage(e.target.value)}
                  placeholder="输入篡改后的消息内容"
                  rows={3}
                />
                <motion.button
                  className="attack-submit-button"
                  onClick={handleModifiedMessageSubmit}
                  whileHover={{ scale: 1.05 }}
                  whileTap={{ scale: 0.95 }}
                  disabled={!modifiedMessage}
                >
                  提交篡改内容
                </motion.button>
              </motion.div>
            )}
          </AnimatePresence>
          
          {/* Attack Flow Visualization */}
          <AnimatePresence>
            {attackMode && modifiedHash && (
              <>
                {/* Arrow from Original Message to Hacker */}
                <motion.div 
                  className="message-to-hacker-arrow"
                  initial={{ scaleY: 0 }}
                  animate={{ scaleY: 1 }}
                  transition={{ duration: 0.8 }}
                />
                
                {/* Hacker Label - 不再显示黑客图标，因为上方已经有了 */}
                <motion.div 
                  className="hacker-flow-container"
                  initial={{ opacity: 0 }}
                  animate={{ opacity: 1 }}
                  transition={{ duration: 0.3, delay: 0.2 }}
                >
                  <div className="hacker-label">
                    开始攻击
                  </div>
                </motion.div>
                
                {/* Arrow from Hacker to Modified Message */}
                <motion.div 
                  className="hacker-to-modified-arrow"
                  initial={{ scaleX: 0 }}
                  animate={{ scaleX: 1 }}
                  transition={{ duration: 0.8, delay: 0.4 }}
                />
                
                {/* Modified Message */}
                <motion.div 
                  className="modified-message-container"
                  initial={{ opacity: 0 }}
                  animate={{ opacity: 1 }}
                  transition={{ duration: 0.3, delay: 0.6 }}
                >
                  <div className="modified-message-content">
                    篡改消息内容为 {modifiedMessage}
                  </div>
                </motion.div>
                
                {/* Arrow from Modified Message to Modified Hash */}
                <motion.div 
                  className="modified-to-hash-arrow"
                  initial={{ scaleX: 0 }}
                  animate={{ scaleX: 1 }}
                  transition={{ duration: 0.8, delay: 0.8 }}
                />
                
                {/* Modified Hash */}
                <motion.div 
                  className="modified-hash-container"
                  initial={{ opacity: 0 }}
                  animate={{ opacity: 1 }}
                  transition={{ duration: 0.3, delay: 1.0 }}
                >
                  <div className="modified-hash-content">
                    哈希后的值 {getModifiedHashDisplay()}
                  </div>
                </motion.div>
                
                {/* Arrow from Modified Hash to Verification */}
                <motion.div 
                  className="modified-to-verification-arrow"
                  initial={{ scaleX: 0 }}
                  animate={{ scaleX: 1 }}
                  transition={{ duration: 0.8, delay: 1.2 }}
                />
                
                {/* 新增：Arrow from Hash to Verification Failure */}
                {verificationResult === false && (
                <motion.div 
                  className="hash-to-verification-failure-arrow"
                  initial={{ scaleX: 0 }}
                  animate={{ scaleX: 1 }}
                  transition={{ duration: 0.8, delay: 1.4 }}
                />
                )}
                
                {/* Arrow from Hash to Verification Success (when attack with same message) */}
                {verificationResult === true && (
                <motion.div 
                  className="hash-to-verification-success-arrow"
                  initial={{ scaleX: 0 }}
                  animate={{ scaleX: 1 }}
                  transition={{ duration: 0.8, delay: 1.4 }}
                />
                )}
              </>
            )}
          </AnimatePresence>
        </div>
        
        <div className="keys-display-area"></div>
      </div>

    </div>
  );
} 