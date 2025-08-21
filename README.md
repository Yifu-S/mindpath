# 🧠 MindPath - Privacy-First Mental Health Support for College Students

**AI-Powered Privacy-First Mental Health Platform for College Students (Ages 18-26)**

Empowering academic success through intelligent emotional support while maintaining complete privacy and anonymity.

## 🌟 Features

### ✅ Core Features (Completed)

- **🔐 End-to-End Encryption**: All data encrypted before leaving device
- **👤 Anonymous Authentication**: No real names or email addresses required
- **📊 Mood Tracking**: 1-10 scale with student-specific emotions and contexts
- **📝 Private Journaling**: AI-powered journal entries with personalized responses
- **📈 Dynamic Insights**: Real-time pattern analysis and mood trends
- **🎯 Personalized Coping Strategies**: Evidence-based techniques tailored to user patterns
- **📅 Academic Calendar**: Track important events and deadlines
- **🛡️ Privacy Controls**: Granular data permissions and export/deletion options
- **🚨 Crisis Support**: Resources and detection of concerning patterns
- **📱 Mobile Responsive**: Optimized for smartphone usage between classes

### ✨ Recent Enhancements

- **📖 Clickable Journal Entries**: View full journal content and AI feedback in beautiful modal
- **🔄 Auto-Refresh After Mood Check-in**: Page refreshes automatically to show updated insights and strategies
- **🎯 Single Emotion Selection**: Focused emotion selection for more targeted coping strategies
- **🤖 Enhanced AI Strategy System**: Comprehensive strategy pools with randomization for all emotion-context combinations
- **🎨 Therapist-Like UI**: Professional, calming design with warm colors and improved UX
- **🔒 Content Security Policy**: Fixed Google Fonts loading and enhanced security
- **📊 Mood History View**: Complete history of mood ratings, emotions, and contexts
- **🎪 Journal Inspirations**: 30+ writing prompts for when users need guidance

### 🔧 Technical Features

- **🔒 Zero-Knowledge Architecture**: Service cannot decrypt user data
- **⚡ Real-time Analytics**: Dynamic insights that update with new data
- **🤖 AI Integration**: OpenAI-powered journal responses and pattern analysis
- **📊 Data Visualization**: Interactive charts and pattern recognition
- **🔄 Offline Fallback**: Local storage when API unavailable
- **🛡️ Security**: JWT authentication, rate limiting, CORS protection
- **🎨 Modern UI**: Glassmorphism design with smooth animations
- **📱 Progressive Web App**: App-like experience with offline capabilities

## 🚀 Quick Start

### Prerequisites

- Node.js 16+
- npm 8+
- OpenAI API key (optional, for AI features)

### Installation

1. **Clone the repository**

   ```bash
   git clone <repository-url>
   cd mindpath
   ```

2. **Install dependencies**

   ```bash
   npm install
   ```

3. **Set up environment variables**

   ```bash
   cp .env.example .env
   # Edit .env with your configuration
   ```

4. **Start the server**

   ```bash
   npm start
   ```

5. **Access the application**
   - Frontend: http://localhost:10000
   - API: http://localhost:10000/api
   - Health Check: http://localhost:10000/api/health

### Environment Variables

```env
# Server Configuration
PORT=10000
NODE_ENV=production

# Security
JWT_SECRET=your-super-secret-jwt-key
ENCRYPTION_KEY=your-32-character-encryption-key

# OpenAI (Optional)
OPENAI_API_KEY=your-openai-api-key

# CORS
ALLOWED_ORIGINS=http://localhost:10000,https://yourdomain.com

# Rate Limiting
RATE_LIMIT_WINDOW_MS=900000
RATE_LIMIT_MAX_REQUESTS=100
```

## 📊 API Endpoints

### Authentication

- `POST /api/auth/signup` - Create new account
- `POST /api/auth/login` - User login

### Mood Tracking

- `POST /api/mood` - Save mood entry
- `GET /api/mood/history` - Get mood history with emotions and contexts

### Journal

- `POST /api/journal` - Save journal entry with AI response
- `GET /api/journal/history` - Get journal history with AI feedback

### Insights

- `GET /api/insights/patterns` - Get mood pattern analysis
- `GET /api/insights/journal` - Get journal insights

### Coping Strategies

- `GET /api/strategies` - Get personalized strategies based on recent mood

### Privacy

- `POST /api/privacy/export` - Export all user data
- `DELETE /api/privacy/delete-all` - Delete all user data

### Crisis Support

- `GET /api/crisis/resources` - Get crisis resources

### Health

- `GET /api/health` - Health check endpoint

## 🧪 Testing

Run the comprehensive test suite:

```bash
npm test
```

Tests cover:

- ✅ Authentication flows
- ✅ Mood tracking functionality
- ✅ Journal entries with AI
- ✅ Insights and analytics
- ✅ Coping strategies
- ✅ Privacy controls
- ✅ Crisis resources
- ✅ API health checks

## 🔒 Privacy & Security

### Encryption

- **AES-256-GCM** encryption for all sensitive data
- **Zero-knowledge architecture** - service cannot decrypt user data
- **Client-side encryption** before data transmission

### Data Protection

- **No real names required** - anonymous usernames only
- **No institutional tracking** - completely independent
- **Local-first storage** - sensitive data stored on user device
- **Automatic data purging** - old data automatically deleted

### Security Features

- **JWT authentication** with secure token management
- **Rate limiting** to prevent abuse
- **CORS protection** for cross-origin requests
- **SQL injection prevention** with parameterized queries
- **XSS protection** with content security policies
- **Content Security Policy** with Google Fonts support

## 🎯 User Experience

### Student-Focused Design

- **Academic context awareness** - understands semester rhythms
- **College-specific emotions** - anxiety, stress, homesickness, etc.
- **Mobile-optimized** - works perfectly on smartphones
- **Quick interactions** - designed for between-class usage
- **Therapist-like interface** - calming, professional design

### Privacy-First Interface

- **Clear privacy indicators** - always shows encryption status
- **Granular controls** - users choose what data to share
- **Transparency** - clear view of data usage and storage
- **Easy data management** - one-click export and deletion

### Interactive Features

- **Clickable journal entries** - view full content and AI feedback in modal
- **Auto-refresh functionality** - updated insights after mood check-ins
- **Dynamic coping strategies** - personalized recommendations that change
- **Mood history visualization** - complete emotional journey tracking

## 🏗️ Architecture

### Backend (Node.js/Express)

- **Express.js** web framework
- **SQLite** database with encryption
- **JWT** authentication
- **OpenAI API** integration
- **Rate limiting** and security middleware
- **Strategy pool system** - comprehensive emotion-context mapping

### Frontend (Vanilla JavaScript)

- **Single-page application** with dynamic content
- **Client-side encryption** using Web Crypto API
- **Responsive design** with CSS Grid and Flexbox
- **Progressive enhancement** - works without JavaScript
- **Modal system** - beautiful overlays for detailed content
- **Real-time updates** - automatic page refresh for fresh data

### Database Schema

- **Users** - anonymous user accounts
- **Mood Entries** - encrypted mood tracking data with emotions and contexts
- **Journal Entries** - encrypted journal with AI responses
- **Crisis Logs** - pattern detection and alerts

## 🚀 Deployment

### Render (Current)

The application is currently deployed on Render:

- **URL**: https://mindpath-74e8.onrender.com
- **Environment**: Production
- **Database**: SQLite with automatic backups

### Local Development

```bash
# Development mode
NODE_ENV=development npm start

# Production mode
NODE_ENV=production npm start
```

## 📈 Analytics & Insights

### Mood Patterns

- **Trend analysis** - improving, declining, or stable
- **Common emotions** - most frequent emotional states (8 core emotions)
- **Stress patterns** - academic context correlation (8 contexts)
- **Recommendations** - personalized coping strategies with randomization

### Journal Insights

- **Writing frequency** - daily, regular, or occasional
- **Common themes** - academic, social, stress, health, future
- **Entry length** - average characters per entry
- **Emotional trends** - patterns in journal content
- **AI feedback** - personalized responses for each entry

### Coping Strategy System

- **8 Core Emotions**: Anxious, Stressed, Lonely, Exhausted, Confident, Motivated, Excited, Frustrated
- **8 Contexts**: Exams/Tests, Assignments, Social Life, Relationships, Family, Financial, Career/Future, Health
- **Strategy Pools**: Each emotion-context combination has 2 pools with 4+ strategies each
- **Randomization**: 2 strategies from each pool (4 total) for variety and personalization

## 🎓 College Student Features

### Academic Integration

- **Semester awareness** - understands academic calendars
- **Exam stress management** - specific strategies for test anxiety
- **Assignment tracking** - deadline management and stress reduction
- **Study-life balance** - tips for maintaining wellbeing

### Social Support

- **Loneliness management** - strategies for social connection
- **Roommate relationships** - conflict resolution and communication
- **Campus integration** - tips for feeling connected
- **Peer support** - anonymous insights from other students

### Mental Health Tools

- **Mood tracking** - 1-10 scale with emotional context
- **Journal writing** - AI-powered reflection with 30+ prompts
- **Coping strategies** - evidence-based techniques for specific situations
- **Crisis detection** - pattern recognition for concerning trends
- **Professional resources** - campus and community mental health support

## 🔮 Future Enhancements

### Planned Features

- **Sleep tracking** - correlation with mood and academic performance
- **Financial stress tools** - budget management and stress reduction
- **Graduation transition** - senior year and post-college support
- **Anonymous community** - safe space for peer sharing
- **Integration APIs** - calendar and productivity tool connections

### Technical Improvements

- **Progressive Web App** - offline functionality and app-like experience
- **Advanced analytics** - machine learning for better pattern recognition
- **Multi-language support** - international student accessibility
- **Voice journaling** - speech-to-text for easier journaling

## 🤝 Contributing

### Development Setup

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests for new functionality
5. Submit a pull request

### Code Standards

- **ES6+ JavaScript** with async/await
- **Proper error handling** with try/catch blocks
- **Security-first approach** - validate all inputs
- **Privacy by design** - encryption for all sensitive data
- **Responsive design** - mobile-first approach
- **Accessibility** - WCAG compliance

## 📞 Support & Resources

### Crisis Resources

- **National Suicide Prevention Lifeline**: 988
- **Crisis Text Line**: Text HOME to 741741
- **Campus Counseling**: Contact your university's counseling center
- **Emergency Services**: 911 for immediate safety concerns

### Technical Support

- **Documentation**: See API documentation above
- **Issues**: Report bugs via GitHub issues
- **Security**: Report security concerns privately

## 📄 License

MIT License - see LICENSE file for details.

## 🙏 Acknowledgments

- **College students** who provided feedback and insights
- **Mental health professionals** who reviewed content and strategies
- **Privacy advocates** who ensured security best practices
- **Open source community** for the amazing tools and libraries

---

**MindPath** - Your mental health, your privacy. 🧠🔒

_Note: MindPath is a supportive tool designed for typical college stressors and personal growth. Students experiencing severe mental health crises, suicidal thoughts, or other serious conditions should seek immediate professional help through campus counseling services, community mental health providers, or crisis hotlines._
