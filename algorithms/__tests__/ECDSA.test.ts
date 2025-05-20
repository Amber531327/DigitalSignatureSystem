import { ECDSA } from '../ECDSA';
import { KeyPair } from '../types';

describe('ECDSA Algorithm', () => {
  let ecdsa: ECDSA;
  let keyPair: KeyPair;
  
  // Setup - generate keys once for all tests
  beforeAll(async () => {
    ecdsa = new ECDSA();
    keyPair = await ecdsa.generateKeys();
    // Ensure keys were generated
    expect(keyPair.publicKey).toBeDefined();
    expect(keyPair.privateKey).toBeDefined();
  }, 30000); // Give it 30 seconds to generate keys
  
  test('should have correctly formatted keys', () => {
    // Public key should have x, y coordinates
    expect(keyPair.publicKey.x).toBeDefined();
    expect(keyPair.publicKey.y).toBeDefined();
    expect(keyPair.publicKey.curve).toBeDefined();
    
    // Private key should have d (private key value)
    expect(keyPair.privateKey.d).toBeDefined();
    expect(keyPair.privateKey.curve).toBeDefined();
  });
  
  test('should have valid key values', () => {
    // Keys should be hex strings
    expect(typeof keyPair.publicKey.x).toBe('string');
    expect(typeof keyPair.publicKey.y).toBe('string');
    expect(typeof keyPair.privateKey.d).toBe('string');
    
    // Hex strings should be valid
    expect(() => BigInt(`0x${keyPair.publicKey.x}`)).not.toThrow();
    expect(() => BigInt(`0x${keyPair.publicKey.y}`)).not.toThrow();
    expect(() => BigInt(`0x${keyPair.privateKey.d}`)).not.toThrow();
    
    // Convert to numeric values (with proper hex format)
    const x = BigInt(`0x${keyPair.publicKey.x}`);
    const y = BigInt(`0x${keyPair.publicKey.y}`);
    const d = BigInt(`0x${keyPair.privateKey.d}`);
    
    // Values should be positive
    expect(x).toBeGreaterThan(0n);
    expect(y).toBeGreaterThan(0n);
    expect(d).toBeGreaterThan(0n);
  });
  
  test('should have curve specified', () => {
    // Check curve information
    expect(keyPair.publicKey.curve).toBe('secp256k1');
    expect(keyPair.privateKey.curve).toBe('secp256k1');
  });
  
  test('should have key with appropriate length', () => {
    // ECDSA secp256k1 keys should be 256 bits (32 bytes)
    expect(keyPair.publicKey.x.length).toBeGreaterThanOrEqual(64); // 64 hex chars = 32 bytes
    expect(keyPair.publicKey.y.length).toBeGreaterThanOrEqual(64);
    expect(keyPair.privateKey.d.length).toBeGreaterThanOrEqual(64);
  });
  
  // 签名和验证测试
  describe('Signature and Verification', () => {
    test('should successfully sign and verify a message', async () => {
      const message = "Hello, ECDSA digital signature!";
      
      // 生成签名
      const signature = await ecdsa.sign(message, keyPair);
      
      // 验证签名结果包含所需属性
      expect(signature).toBeDefined();
      expect(signature.r).toBeDefined();
      expect(signature.s).toBeDefined();
      expect(signature.messageHash).toBeDefined();
      expect(signature.signature).toBeDefined(); // DER格式的签名
      
      // 验证签名
      const result = await ecdsa.verify(message, signature, keyPair);
      expect(result).toBe(true);
      console.info(`原始消息验证结果: ${result ? '成功✓' : '失败✗'}`);
    });
    
    test('should return signature with expected format', async () => {
      const message = "Testing ECDSA signature format";
      
      const signature = await ecdsa.sign(message, keyPair);
      
      // 验证r和s是字符串且可解析为BigInt
      expect(typeof signature.r).toBe('string');
      expect(typeof signature.s).toBe('string');
      expect(typeof signature.signature).toBe('string');
      
      // 检查r和s是否为标准的64位十六进制字符串（256位）
      expect(signature.r?.length).toBe(64);
      expect(signature.s?.length).toBe(64);
      
      // 检查r和s的值是否有效
      const r = BigInt(`0x${signature.r || ''}`);
      const s = BigInt(`0x${signature.s || ''}`);
      
      expect(r).toBeGreaterThan(0n);
      expect(s).toBeGreaterThan(0n);
      
      // 验证哈希值格式
      expect(typeof signature.messageHash).toBe('string');
      // SHA-256 输出长度可能因具体实现而异，但应该至少有30个字符
      expect(signature.messageHash?.length).toBeGreaterThanOrEqual(30);
    });
    
    test('should reject signatures for tampered messages', async () => {
      // 原始消息
      const originalMessage = "Original message for ECDSA testing";
      
      // 生成签名
      const signature = await ecdsa.sign(originalMessage, keyPair);
      
      // 验证原始消息（应成功）
      const validResult = await ecdsa.verify(originalMessage, signature, keyPair);
      expect(validResult).toBe(true);
      console.info(`原始消息验证结果: ${validResult ? '成功✓' : '失败✗'}`);
      
      // 验证篡改消息（应失败）
      const tamperedMessage = "This message has been tampered with!";
      const invalidResult = await ecdsa.verify(tamperedMessage, signature, keyPair);
      expect(invalidResult).toBe(false);
      console.info(`篡改消息验证结果: ${invalidResult ? '错误地成功✗' : '正确地失败✓'}`);
    });
    
    test('should reject tampered signatures', async () => {
      // 原始消息
      const message = "Message for tampered signature test";
      
      // 生成签名
      const signature = await ecdsa.sign(message, keyPair);
      
      // 篡改签名的r值
      const originalR = signature.r;
      const rBigInt = BigInt(`0x${originalR}`);
      const tamperedR = (rBigInt + 1n).toString(16).padStart(64, '0');
      
      const tamperedSignature = {
        ...signature,
        r: tamperedR
      };
      
      // 验证篡改签名（应失败）
      const result = await ecdsa.verify(message, tamperedSignature, keyPair);
      expect(result).toBe(false);
      console.info(`篡改r值验证结果: ${result ? '错误地成功✗' : '正确地失败✓'}`);
      
      // 篡改签名的s值
      const originalS = signature.s;
      const sBigInt = BigInt(`0x${originalS}`);
      const tamperedS = (sBigInt + 1n).toString(16).padStart(64, '0');
      
      const tamperedSignature2 = {
        ...signature,
        s: tamperedS
      };
      
      // 验证篡改签名（应失败）
      const result2 = await ecdsa.verify(message, tamperedSignature2, keyPair);
      expect(result2).toBe(false);
      console.info(`篡改s值验证结果: ${result2 ? '错误地成功✗' : '正确地失败✓'}`);
    });
    
    test('should verify signatures with different message lengths', async () => {
      // 测试不同长度的消息
      const messages = [
        "", // 空消息
        "a", // 单字符
        "Short message", // 短消息
        "This is a medium length message for testing ECDSA signature verification", // 中等长度
        "A".repeat(1000) // 长消息
      ];
      
      for (const message of messages) {
        // 生成签名
        const signature = await ecdsa.sign(message, keyPair);
        
        // 验证签名
        const result = await ecdsa.verify(message, signature, keyPair);
        
        // 记录结果
        console.info(`消息长度 ${message.length} 验证结果: ${result ? '成功✓' : '失败✗'}`);
        
        // 验证应该成功
        expect(result).toBe(true);
      }
    });
    
    test('should verify using both direct r,s and DER encoded signatures', async () => {
      const message = "Testing DER encoding and direct r,s verification";
      
      // 生成签名
      const signature = await ecdsa.sign(message, keyPair);
      
      // 使用直接提供的r和s进行验证
      const directResult = await ecdsa.verify(message, {
        r: signature.r,
        s: signature.s
      }, keyPair);
      
      expect(directResult).toBe(true);
      console.info(`直接r,s验证结果: ${directResult ? '成功✓' : '失败✗'}`);
      
      // 使用DER编码签名进行验证
      const derResult = await ecdsa.verify(message, {
        signature: signature.signature
      }, keyPair);
      
      expect(derResult).toBe(true);
      console.info(`DER编码验证结果: ${derResult ? '成功✓' : '失败✗'}`);
    });
    
    test('should reject invalid signature formats', async () => {
      const message = "Testing invalid signature handling";
      
      // 测试无效签名格式
      const invalidSignature = { foo: "bar" };
      
      // 应该拒绝或优雅处理无效格式
      const result = await ecdsa.verify(message, invalidSignature, keyPair);
      expect(result).toBe(false);
      
      // 测试无效r值（超出曲线阶n的范围）
      // 创建一个超大的r值
      const hugeValue = "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff";
      
      const invalidR = {
        r: hugeValue,
        s: "1111111111111111111111111111111111111111111111111111111111111111"
      };
      
      const resultInvalidR = await ecdsa.verify(message, invalidR, keyPair);
      expect(resultInvalidR).toBe(false);
      
      console.info('无效签名处理测试通过✓');
    });
  });
}); 