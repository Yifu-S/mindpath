const request = require('supertest');
const app = require('../server');

describe('MindPath Integration Tests', () => {
  let authToken;
  let userId;

  // Test user data
  const testUser = {
    username: 'testuser_' + Date.now(),
    password: 'Test123!',
    yearInSchool: 'junior'
  };

  describe('Authentication', () => {
    test('POST /api/auth/signup - Create new user', async () => {
      const res = await request(app)
        .post('/api/auth/signup')
        .send(testUser);
      
      expect(res.statusCode).toBe(200);
      expect(res.body).toHaveProperty('token');
      expect(res.body).toHaveProperty('user');
      expect(res.body.user.username).toBe(testUser.username);
      
      authToken = res.body.token;
      userId = res.body.user.id;
    });

    test('POST /api/auth/login - Login user', async () => {
      const res = await request(app)
        .post('/api/auth/login')
        .send({
          username: testUser.username,
          password: testUser.password
        });
      
      expect(res.statusCode).toBe(200);
      expect(res.body).toHaveProperty('token');
    });
  });

  describe('Mood Tracking', () => {
    test('POST /api/mood - Save mood entry', async () => {
      const moodData = {
        mood: 7,
        emotions: ['Happy', 'Confident'],
        context: 'Exams/Tests'
      };

      const res = await request(app)
        .post('/api/mood')
        .set('Authorization', `Bearer ${authToken}`)
        .send(moodData);
      
      expect(res.statusCode).toBe(200);
      expect(res.body).toHaveProperty('success', true);
    });

    test('GET /api/mood/history - Get mood history', async () => {
      const res = await request(app)
        .get('/api/mood/history')
        .set('Authorization', `Bearer ${authToken}`);
      
      expect(res.statusCode).toBe(200);
      expect(Array.isArray(res.body)).toBe(true);
    });
  });

  describe('Journal Entries', () => {
    test('POST /api/journal - Save journal entry', async () => {
      const journalData = {
        text: 'I am feeling stressed about my upcoming exam. Need to study more.'
      };

      const res = await request(app)
        .post('/api/journal')
        .set('Authorization', `Bearer ${authToken}`)
        .send(journalData);
      
      expect(res.statusCode).toBe(200);
      expect(res.body).toHaveProperty('success', true);
      expect(res.body).toHaveProperty('aiResponse');
    });
  });

  describe('Insights and Analytics', () => {
    test('GET /api/insights/patterns - Get mood patterns', async () => {
      const res = await request(app)
        .get('/api/insights/patterns')
        .set('Authorization', `Bearer ${authToken}`);
      
      expect(res.statusCode).toBe(200);
      expect(res.body).toHaveProperty('averageMood');
      expect(res.body).toHaveProperty('moodTrend');
      expect(res.body).toHaveProperty('commonEmotions');
      expect(res.body).toHaveProperty('stressPatterns');
      expect(res.body).toHaveProperty('recommendations');
    });

    test('GET /api/insights/journal - Get journal insights', async () => {
      const res = await request(app)
        .get('/api/insights/journal')
        .set('Authorization', `Bearer ${authToken}`);
      
      expect(res.statusCode).toBe(200);
      expect(res.body).toHaveProperty('totalEntries');
      expect(res.body).toHaveProperty('averageLength');
      expect(res.body).toHaveProperty('commonThemes');
      expect(res.body).toHaveProperty('writingFrequency');
    });
  });

  describe('Coping Strategies', () => {
    test('GET /api/strategies - Get personalized strategies', async () => {
      const res = await request(app)
        .get('/api/strategies')
        .set('Authorization', `Bearer ${authToken}`);
      
      expect(res.statusCode).toBe(200);
      expect(Array.isArray(res.body)).toBe(true);
      expect(res.body.length).toBeGreaterThan(0);
      expect(res.body[0]).toHaveProperty('id');
      expect(res.body[0]).toHaveProperty('category');
      expect(res.body[0]).toHaveProperty('title');
      expect(res.body[0]).toHaveProperty('description');
      expect(res.body[0]).toHaveProperty('steps');
    });
  });

  describe('Academic Calendar', () => {
    test('POST /api/calendar/event - Add calendar event', async () => {
      const eventData = {
        eventType: 'Final Exam',
        eventDate: '2024-12-15',
        description: 'Organic Chemistry Final'
      };

      const res = await request(app)
        .post('/api/calendar/event')
        .set('Authorization', `Bearer ${authToken}`)
        .send(eventData);
      
      expect(res.statusCode).toBe(200);
      expect(res.body).toHaveProperty('success', true);
    });

    test('GET /api/calendar/events - Get calendar events', async () => {
      const res = await request(app)
        .get('/api/calendar/events')
        .set('Authorization', `Bearer ${authToken}`);
      
      expect(res.statusCode).toBe(200);
      expect(Array.isArray(res.body)).toBe(true);
    });
  });

  describe('Privacy and Data Management', () => {
    test('POST /api/privacy/export - Export user data', async () => {
      const res = await request(app)
        .post('/api/privacy/export')
        .set('Authorization', `Bearer ${authToken}`);
      
      expect(res.statusCode).toBe(200);
      expect(res.body).toHaveProperty('profile');
      expect(res.body).toHaveProperty('moods');
      expect(res.body).toHaveProperty('journals');
    });
  });

  describe('Crisis Resources', () => {
    test('GET /api/crisis/resources - Get crisis resources', async () => {
      const res = await request(app)
        .get('/api/crisis/resources');
      
      expect(res.statusCode).toBe(200);
      expect(Array.isArray(res.body)).toBe(true);
      expect(res.body.length).toBeGreaterThan(0);
      expect(res.body[0]).toHaveProperty('name');
      expect(res.body[0]).toHaveProperty('type');
    });
  });

  describe('Health Check', () => {
    test('GET /api/health - Health endpoint', async () => {
      const res = await request(app)
        .get('/api/health');
      
      expect(res.statusCode).toBe(200);
      expect(res.body).toHaveProperty('status', 'healthy');
      expect(res.body).toHaveProperty('timestamp');
      expect(res.body).toHaveProperty('environment');
    });
  });

  // Cleanup - Delete test user data
  afterAll(async () => {
    if (authToken) {
      await request(app)
        .delete('/api/privacy/delete-all')
        .set('Authorization', `Bearer ${authToken}`);
    }
  });
});
