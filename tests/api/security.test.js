import request from 'supertest';
import { app } from '../../server.js';

describe('Security Challenge & Admin Setup Endpoints', () => {
  it('POST /api/auth/login - should return 401 for non-existent user', async () => {
    const res = await request(app)
      .post('/api/auth/login')
      .send({ userId: 'nonexistent-user-12345', password: 'somepassword' });
    
    expect(res.status).toBe(401);
    expect(res.body.error).toBe('Account not found.');
  }, 30000);

  it('POST /api/auth/verify-security-question - should return 400 if parameters are missing', async () => {
    const res = await request(app)
      .post('/api/auth/verify-security-question')
      .send({});
    
    expect(res.status).toBe(400);
    expect(res.body.error).toBe('User ID, security question, and security answer are required.');
  }, 30000);

  it('POST /api/auth/verify-security-question - should return 400 if question is missing', async () => {
    const res = await request(app)
      .post('/api/auth/verify-security-question')
      .send({ userId: 'someuser', securityAnswer: 'test' });
    
    expect(res.status).toBe(400);
    expect(res.body.error).toBe('User ID, security question, and security answer are required.');
  }, 30000);

  it('POST /api/auth/verify-security-question - should return 404 for non-existent user', async () => {
    const res = await request(app)
      .post('/api/auth/verify-security-question')
      .send({ userId: 'nonexistent-user-12345', securityQuestion: 'In what city were you born?', securityAnswer: 'test' });
    
    expect(res.status).toBe(404);
    expect(res.body.error).toBe('User not found.');
  }, 30000);

  it('POST /api/auth/verify-security-question - should enforce 15-min lockout after 5 failed attempts', async () => {
    const testUserId = 'test-lockout-user-' + Date.now();
    for (let i = 0; i < 5; i++) {
      await request(app)
        .post('/api/auth/verify-security-question')
        .send({ userId: testUserId, securityQuestion: 'In what city were you born?', securityAnswer: 'wrong' });
    }
    const res = await request(app)
      .post('/api/auth/verify-security-question')
      .send({ userId: testUserId, securityQuestion: 'In what city were you born?', securityAnswer: 'wrong' });

    expect(res.status).toBe(429);
    expect(res.body.error).toContain('Too many failed attempts');
  }, 30000);

  it('POST /api/auth/setup - should reject if workspace is already initialized', async () => {
    const res = await request(app)
      .post('/api/auth/setup')
      .send({ team: [{ id: 'admin-1', name: 'Admin', password: 'pass' }] });
    
    expect(res.status).toBe(400);
    expect(res.body.error).toBe('Workspace already set up.');
  }, 30000);
});
