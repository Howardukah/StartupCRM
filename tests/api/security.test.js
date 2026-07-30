import request from 'supertest';
import { app } from '../../server.js';

describe('Security Challenge & Admin Setup Endpoints', () => {
  it('POST /api/auth/login - should return 401 for non-existent user', async () => {
    const res = await request(app)
      .post('/api/auth/login')
      .send({ userId: 'user-login-test-' + Date.now(), password: 'somepassword' });
    
    expect(res.status).toBe(401);
    expect(res.body.error).toBe('Incorrect credentials. Check login credentials and try again.');
  }, 30000);

  it('POST /api/auth/verify-security-question - should return 400 if parameters are missing', async () => {
    const res = await request(app)
      .post('/api/auth/verify-security-question')
      .send({});
    
    expect(res.status).toBe(400);
    expect(res.body.error).toBe('User ID, challenge token, security question, security answer, and password are required.');
  }, 30000);

  it('POST /api/auth/verify-security-question - should return 400 if question is missing', async () => {
    const res = await request(app)
      .post('/api/auth/verify-security-question')
      .send({ userId: 'user-sec-test-' + Date.now(), challengeToken: 'dummy', securityAnswer: 'test', password: 'pass' });
    
    expect(res.status).toBe(400);
    expect(res.body.error).toBe('User ID, challenge token, security question, security answer, and password are required.');
  }, 30000);

  it('POST /api/auth/verify-security-question - should return 404 for non-existent user', async () => {
    const res = await request(app)
      .post('/api/auth/verify-security-question')
      .send({ userId: 'nonexistent-user-' + Date.now(), challengeToken: 'dummy.token', securityQuestion: 'In what city were you born?', securityAnswer: 'test', password: 'somepassword' });
    
    expect(res.status).toBe(404);
    expect(res.body.error).toBe('User not found.');
  }, 30000);

  it('POST /api/auth/verify-security-question - should return 404 for user not found in database', async () => {
    const res = await request(app)
      .post('/api/auth/verify-security-question')
      .send({ userId: 'unregistered-user-' + Date.now(), challengeToken: 'invalid.token', securityQuestion: 'In what city were you born?', securityAnswer: 'test', password: 'somepassword' });
    
    expect(res.status).toBe(404);
    expect(res.body.error).toBe('User not found.');
  }, 30000);

  it('POST /api/auth/setup - should reject if workspace is already initialized', async () => {
    const res = await request(app)
      .post('/api/auth/setup')
      .send({ team: [{ id: 'admin-1', name: 'Admin', password: 'pass' }] });
    
    expect(res.status).toBe(400);
    expect(res.body.error).toBe('Workspace already set up.');
  }, 30000);
});
