import React from 'react';
import { motion } from 'framer-motion';

interface UserRoleProps {
  type: 'sender' | 'receiver';
  position?: 'left' | 'right';
}

const UserRole: React.FC<UserRoleProps> = ({ type, position = type === 'sender' ? 'left' : 'right' }) => {
  return (
    <div className={`user-role ${type} ${position}`}>
      <motion.div
        className="avatar"
        initial={{ scale: 0.8 }}
        animate={{ scale: 1 }}
        transition={{ duration: 0.3 }}
      >
        <img src="/images/person.png" alt={type === 'sender' ? '发送方' : '接收方'} className="avatar-image" />
      </motion.div>
      <p className="role-label">
        {type === 'sender' ? '发送方' : '接收方'}
      </p>
    </div>
  );
};

export default UserRole; 