import { AlgorithmFactory } from '../index';
import { RSA } from '../RSA';
import { DSA } from '../DSA';
import { ECDSA } from '../ECDSA';
import { CryptoAlgorithm } from '../types';

describe('AlgorithmFactory', () => {
  test('should return RSA instance', () => {
    const instance = AlgorithmFactory.getAlgorithm('RSA');
    expect(instance).toBeInstanceOf(RSA);
  });
  
  test('should return DSA instance', () => {
    const instance = AlgorithmFactory.getAlgorithm('DSA');
    expect(instance).toBeInstanceOf(DSA);
  });
  
  test('should return ECDSA instance', () => {
    const instance = AlgorithmFactory.getAlgorithm('ECDSA');
    expect(instance).toBeInstanceOf(ECDSA);
  });
  
  test('should be case-insensitive', () => {
    const instance1 = AlgorithmFactory.getAlgorithm('rsa');
    const instance2 = AlgorithmFactory.getAlgorithm('Rsa');
    
    expect(instance1).toBeInstanceOf(RSA);
    expect(instance2).toBeInstanceOf(RSA);
  });
  
  test('should return the same instance on repeated calls', () => {
    const instance1 = AlgorithmFactory.getAlgorithm('RSA');
    const instance2 = AlgorithmFactory.getAlgorithm('RSA');
    
    expect(instance1).toBe(instance2); // Same object reference
  });
  
  test('should throw error for unsupported algorithm', () => {
    expect(() => {
      AlgorithmFactory.getAlgorithm('UnsupportedAlgorithm');
    }).toThrow('不支持的算法: UnsupportedAlgorithm');
  });
  
  test('each algorithm instance should implement CryptoAlgorithm interface', () => {
    const algorithms = ['RSA', 'DSA', 'ECDSA'];
    
    for (const algo of algorithms) {
      const instance = AlgorithmFactory.getAlgorithm(algo);
      
      // Check interface implementation
      expect(typeof instance.generateKeys).toBe('function');
      expect(typeof instance.sign).toBe('function');
      expect(typeof instance.verify).toBe('function');
    }
  });
}); 