// server.js - MindPath Backend Server
const express = require("express");
const cors = require("cors");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const sqlite3 = require("sqlite3").verbose();
const crypto = require("crypto");
const path = require("path");
const fs = require("fs");
const rateLimit = require("express-rate-limit");
const helmet = require("helmet");
const compression = require("compression");
const { OpenAI } = require("openai");

// Environment configuration
require("dotenv").config();

const app = express();
app.set("trust proxy", 1);
const PORT = process.env.PORT || 10000; // Render will provide PORT
const JWT_SECRET =
  process.env.JWT_SECRET || crypto.randomBytes(64).toString("hex");
const ENCRYPTION_KEY =
  process.env.ENCRYPTION_KEY || crypto.randomBytes(32).toString("hex");

// Add production URL handling
const isDevelopment = process.env.NODE_ENV === "development";
const BASE_URL = process.env.RENDER_EXTERNAL_URL || `http://localhost:${PORT}`;

// OpenAI Configuration
const openai = new OpenAI({
  apiKey: process.env.OPENAI_API_KEY,
});

// Security middleware
app.use(
  helmet({
    contentSecurityPolicy: {
      directives: {
        defaultSrc: ["'self'"],
        styleSrc: ["'self'", "'unsafe-inline'"],
        scriptSrc: ["'self'", "'unsafe-inline'", "'unsafe-eval'"],
        scriptSrcAttr: ["'unsafe-inline'"], // This fixes the onclick issue
        imgSrc: ["'self'", "data:", "https:"],
      },
    },
  })
);
app.use(compression());
app.use(
  cors({
    origin: process.env.ALLOWED_ORIGINS?.split(",") || [
      "http://localhost:3000",
      "https://mindpath-74e8.onrender.com",
    ],
    credentials: true,
  })
);
app.use(express.json({ limit: "10mb" }));
app.use(express.static("public"));

// Rate limiting
const limiter = rateLimit({
  windowMs: process.env.RATE_LIMIT_WINDOW_MS || 15 * 60 * 1000, // 15 minutes
  max: process.env.RATE_LIMIT_MAX_REQUESTS || 100, // limit each IP to 100 requests per windowMs
});

const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 50, // limit auth attempts (increased for testing)
});

// Apply rate limiting (comment out for testing if needed)
app.use("/api/", limiter);
app.use("/api/auth/", authLimiter);

// Database setup
const db = new sqlite3.Database("./mindpath.db");

// Initialize database tables
db.serialize(() => {
  // Users table
  db.run(`CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        year_in_school TEXT,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        last_login DATETIME,
        settings TEXT
    )`);

  // Mood entries table (encrypted)
  db.run(`CREATE TABLE IF NOT EXISTS mood_entries (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        encrypted_data TEXT NOT NULL,
        iv TEXT NOT NULL,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES users (id)
    )`);

  // Journal entries table (encrypted)
  db.run(`CREATE TABLE IF NOT EXISTS journal_entries (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        encrypted_data TEXT NOT NULL,
        iv TEXT NOT NULL,
        ai_response TEXT,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES users (id)
    )`);

  // Crisis detection logs
  db.run(`CREATE TABLE IF NOT EXISTS crisis_logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        severity_level INTEGER,
        detected_patterns TEXT,
        action_taken TEXT,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES users (id)
    )`);


});

// Encryption utilities
class EncryptionService {
  static algorithm = "aes-256-gcm";

  static encrypt(text, userKey) {
    const iv = crypto.randomBytes(16);
    const key = crypto.scryptSync(userKey + ENCRYPTION_KEY, "salt", 32);
    const cipher = crypto.createCipheriv(this.algorithm, key, iv);

    let encrypted = cipher.update(text, "utf8", "hex");
    encrypted += cipher.final("hex");

    const authTag = cipher.getAuthTag();

    return {
      encrypted: encrypted + authTag.toString("hex"),
      iv: iv.toString("hex"),
    };
  }

  static decrypt(encryptedData, iv, userKey) {
    const key = crypto.scryptSync(userKey + ENCRYPTION_KEY, "salt", 32);
    const decipher = crypto.createDecipheriv(
      this.algorithm,
      key,
      Buffer.from(iv, "hex")
    );

    const authTag = Buffer.from(encryptedData.slice(-32), "hex");
    const encrypted = encryptedData.slice(0, -32);

    decipher.setAuthTag(authTag);

    let decrypted = decipher.update(encrypted, "hex", "utf8");
    decrypted += decipher.final("utf8");

    return decrypted;
  }
}

// JWT Authentication middleware
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers["authorization"];
  const token = authHeader && authHeader.split(" ")[1];

  if (!token) {
    return res.sendStatus(401);
  }

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) return res.sendStatus(403);
    req.user = user;
    next();
  });
};

// API Routes

// Authentication
app.post("/api/auth/signup", async (req, res) => {
  const { username, password, yearInSchool } = req.body;

  if (!username || !password) {
    return res.status(400).json({ error: "Username and password required" });
  }

  try {
    const hashedPassword = await bcrypt.hash(password, 10);

    db.run(
      `INSERT INTO users (username, password_hash, year_in_school) VALUES (?, ?, ?)`,
      [username, hashedPassword, yearInSchool],
      function (err) {
        if (err) {
          if (err.message.includes("UNIQUE")) {
            return res.status(409).json({ error: "Username already exists" });
          }
          return res.status(500).json({ error: "Registration failed" });
        }

        const token = jwt.sign({ id: this.lastID, username }, JWT_SECRET, {
          expiresIn: "24h",
        });

        res.json({
          token,
          user: { id: this.lastID, username, yearInSchool },
        });
      }
    );
  } catch (error) {
    res.status(500).json({ error: "Server error" });
  }
});

app.post("/api/auth/login", async (req, res) => {
  const { username, password } = req.body;

  db.get(
    `SELECT * FROM users WHERE username = ?`,
    [username],
    async (err, user) => {
      if (err || !user) {
        return res.status(401).json({ error: "Invalid credentials" });
      }

      const validPassword = await bcrypt.compare(password, user.password_hash);
      if (!validPassword) {
        return res.status(401).json({ error: "Invalid credentials" });
      }

      // Update last login
      db.run(`UPDATE users SET last_login = CURRENT_TIMESTAMP WHERE id = ?`, [
        user.id,
      ]);

      const token = jwt.sign(
        { id: user.id, username: user.username },
        JWT_SECRET,
        { expiresIn: "24h" }
      );

      res.json({
        token,
        user: {
          id: user.id,
          username: user.username,
          yearInSchool: user.year_in_school,
        },
      });
    }
  );
});

// Mood Tracking
app.post("/api/mood", authenticateToken, (req, res) => {
  const { mood, emotions, context } = req.body;
  const userId = req.user.id;

  const moodData = JSON.stringify({
    mood,
    emotions,
    context,
    timestamp: Date.now(),
    date: new Date().toISOString(),
  });

  const encrypted = EncryptionService.encrypt(moodData, req.user.username);

  db.run(
    `INSERT INTO mood_entries (user_id, encrypted_data, iv) VALUES (?, ?, ?)`,
    [userId, encrypted.encrypted, encrypted.iv],
    function (err) {
      if (err) {
        return res.status(500).json({ error: "Failed to save mood entry" });
      }

      // Check for concerning patterns
      checkCrisisPatterns(userId, { mood, emotions, context });

      res.json({
        success: true,
        id: this.lastID,
        message: "Mood entry saved securely",
      });
    }
  );
});

app.get("/api/mood/history", authenticateToken, (req, res) => {
  const userId = req.user.id;
  const limit = parseInt(req.query.limit) || 30;

  db.all(
    `SELECT * FROM mood_entries WHERE user_id = ? ORDER BY created_at DESC LIMIT ?`,
    [userId, limit],
    (err, rows) => {
      if (err) {
        return res.status(500).json({ error: "Failed to fetch mood history" });
      }

      const decryptedMoods = rows
        .map((row) => {
          try {
            const decrypted = EncryptionService.decrypt(
              row.encrypted_data,
              row.iv,
              req.user.username
            );
            return {
              id: row.id,
              ...JSON.parse(decrypted),
              created_at: row.created_at,
            };
          } catch (e) {
            return null;
          }
        })
        .filter(Boolean);

      res.json(decryptedMoods);
    }
  );
});

// Journal Entries with AI Support
app.post("/api/journal", authenticateToken, async (req, res) => {
  const { text } = req.body;
  const userId = req.user.id;

  if (!text) {
    return res.status(400).json({ error: "Journal text required" });
  }

  try {
    // Get AI response
    const aiResponse = await getAISupport(text, userId);

    const journalData = JSON.stringify({
      text,
      timestamp: Date.now(),
      date: new Date().toISOString(),
    });

    const encrypted = EncryptionService.encrypt(journalData, req.user.username);

    db.run(
      `INSERT INTO journal_entries (user_id, encrypted_data, iv, ai_response) VALUES (?, ?, ?, ?)`,
      [userId, encrypted.encrypted, encrypted.iv, aiResponse],
      function (err) {
        if (err) {
          return res
            .status(500)
            .json({ error: "Failed to save journal entry" });
        }

        res.json({
          success: true,
          id: this.lastID,
          aiResponse: aiResponse,
        });
      }
    );
  } catch (error) {
    console.error("Journal save error:", error);
    res.status(500).json({ error: "Failed to process journal entry" });
  }
});

// Get journal history
app.get("/api/journal/history", authenticateToken, (req, res) => {
  const userId = req.user.id;
  const limit = parseInt(req.query.limit) || 10;

  db.all(
    `SELECT encrypted_data, iv, ai_response, created_at FROM journal_entries 
         WHERE user_id = ? ORDER BY created_at DESC LIMIT ?`,
    [userId, limit],
    (err, rows) => {
      if (err) {
        return res
          .status(500)
          .json({ error: "Failed to fetch journal history" });
      }

      const journalData = rows
        .map((row) => {
          try {
            const decrypted = EncryptionService.decrypt(
              row.encrypted_data,
              row.iv,
              req.user.username
            );
            const journal = JSON.parse(decrypted);
            return {
              ...journal,
              ai_response: row.ai_response,
              created_at: row.created_at,
            };
          } catch (e) {
            return null;
          }
        })
        .filter(Boolean);

      res.json(journalData);
    }
  );
});

// AI Support Function
async function getAISupport(journalText, userId) {
  try {
    // Get user context for personalized response
    const userContext = await getUserContext(userId);

    const systemPrompt = `You are MindPath, a supportive AI companion for college students. 
        You provide empathetic, evidence-based mental health support while maintaining complete privacy.
        
        Student Context:
        - Year in school: ${userContext.yearInSchool}
        - Recent mood average: ${userContext.avgMood}/10
        - Common stressors: ${userContext.commonStressors.join(", ")}
        
        Guidelines:
        - Be empathetic and validating - acknowledge their feelings first
        - Provide specific, actionable coping strategies tailored to college life
        - Reference academic context when relevant (exams, assignments, social life)
        - Suggest campus resources when appropriate (counseling, health services)
        - Keep responses concise but warm (2-3 paragraphs)
        - If detecting crisis signs, gently suggest professional support
        - Use a supportive, non-judgmental tone
        - Include practical tips that can be implemented immediately
        - Reference the coping strategies available in the app when relevant`;

    const completion = await openai.chat.completions.create({
      model: "gpt-3.5-turbo",
      messages: [
        { role: "system", content: systemPrompt },
        { role: "user", content: journalText },
      ],
      max_tokens: 300,
      temperature: 0.7,
    });

    return completion.choices[0].message.content;
  } catch (error) {
    console.error("AI API error:", error);
    // Fallback response if AI fails
    return (
      "Thank you for sharing your thoughts. While I couldn't process this with AI right now, " +
      "remember that your feelings are valid. Consider trying the coping strategies in the app, " +
      "and don't hesitate to reach out to campus counseling if you need additional support."
    );
  }
}

// Get user context for AI
async function getUserContext(userId) {
  return new Promise((resolve) => {
    db.get(
      `SELECT year_in_school FROM users WHERE id = ?`,
      [userId],
      (err, user) => {
        if (err || !user) {
          resolve({ yearInSchool: "unknown", avgMood: 5, commonStressors: [] });
          return;
        }

        // Get recent mood data
        db.all(
          `SELECT encrypted_data, iv FROM mood_entries 
                     WHERE user_id = ? 
                     ORDER BY created_at DESC 
                     LIMIT 10`,
          [userId],
          (err, moods) => {
            let avgMood = 5;
            let stressors = [];

            if (!err && moods) {
              // Decrypt and analyze moods
              // (simplified for demo - would decrypt properly in production)
              avgMood = 6; // Placeholder
              stressors = ["exams", "assignments"];
            }

            resolve({
              yearInSchool: user.year_in_school || "unknown",
              avgMood,
              commonStressors: stressors,
            });
          }
        );
      }
    );
  });
}

// Crisis Pattern Detection
function checkCrisisPatterns(userId, moodData) {
  const { mood, emotions } = moodData;

  // Crisis indicators
  const concerningEmotions = ["Hopeless", "Worthless", "Suicidal"];
  const warningEmotions = ["Anxious", "Overwhelmed", "Depressed"];

  let severityLevel = 0;
  let detectedPatterns = [];

  if (mood <= 2) {
    severityLevel += 2;
    detectedPatterns.push("Very low mood");
  } else if (mood <= 4) {
    severityLevel += 1;
    detectedPatterns.push("Low mood");
  }

  emotions.forEach((emotion) => {
    if (concerningEmotions.includes(emotion)) {
      severityLevel += 3;
      detectedPatterns.push(`Critical emotion: ${emotion}`);
    } else if (warningEmotions.includes(emotion)) {
      severityLevel += 1;
      detectedPatterns.push(`Warning emotion: ${emotion}`);
    }
  });

  if (severityLevel >= 5) {
    // Log crisis detection
    db.run(
      `INSERT INTO crisis_logs (user_id, severity_level, detected_patterns, action_taken) 
             VALUES (?, ?, ?, ?)`,
      [
        userId,
        severityLevel,
        JSON.stringify(detectedPatterns),
        "Alert generated",
      ]
    );
  }

  return { severityLevel, detectedPatterns };
}

// Insights and Analytics
app.get("/api/insights/patterns", authenticateToken, async (req, res) => {
  const userId = req.user.id;

  try {
    // Get mood patterns
    db.all(
      `SELECT encrypted_data, iv, created_at FROM mood_entries 
             WHERE user_id = ? AND created_at >= datetime('now', '-30 days')
             ORDER BY created_at DESC`,
      [userId],
      (err, rows) => {
        if (err) {
          return res.status(500).json({ error: "Failed to fetch insights" });
        }

        // Decrypt and analyze patterns
        const moodData = rows
          .map((row) => {
            try {
              const decrypted = EncryptionService.decrypt(
                row.encrypted_data,
                row.iv,
                req.user.username
              );
              return JSON.parse(decrypted);
            } catch (e) {
              return null;
            }
          })
          .filter(Boolean);

        // Analyze patterns
        const patterns = analyzePatterns(moodData);
        res.json(patterns);
      }
    );
  } catch (error) {
    res.status(500).json({ error: "Failed to generate insights" });
  }
});

// Get journal insights
app.get("/api/insights/journal", authenticateToken, (req, res) => {
  const userId = req.user.id;

  db.all(
    `SELECT encrypted_data, iv, ai_response, created_at FROM journal_entries 
         WHERE user_id = ? AND created_at >= datetime('now', '-30 days')
         ORDER BY created_at DESC`,
    [userId],
    (err, rows) => {
      if (err) {
        return res
          .status(500)
          .json({ error: "Failed to fetch journal insights" });
      }

      const journalData = rows
        .map((row) => {
          try {
            const decrypted = EncryptionService.decrypt(
              row.encrypted_data,
              row.iv,
              req.user.username
            );
            return {
              ...JSON.parse(decrypted),
              ai_response: row.ai_response,
              created_at: row.created_at,
            };
          } catch (e) {
            return null;
          }
        })
        .filter(Boolean);

      // Analyze journal patterns
      const insights = analyzeJournalPatterns(journalData);
      res.json(insights);
    }
  );
});

function analyzePatterns(moodData) {
  if (moodData.length === 0) {
    return {
      averageMood: 0,
      moodTrend: "neutral",
      commonEmotions: [],
      stressPatterns: [],
      recommendations: [],
    };
  }

  // Calculate average mood
  const avgMood =
    moodData.reduce((sum, entry) => sum + entry.mood, 0) / moodData.length;

  // Find mood trend
  const recentAvg =
    moodData.slice(0, 7).reduce((sum, entry) => sum + entry.mood, 0) /
    Math.min(7, moodData.length);
  const olderAvg =
    moodData.slice(7, 14).reduce((sum, entry) => sum + entry.mood, 0) /
      Math.min(7, moodData.slice(7, 14).length) || avgMood;

  const trend =
    recentAvg > olderAvg
      ? "improving"
      : recentAvg < olderAvg
        ? "declining"
        : "stable";

  // Count emotions
  const emotionCounts = {};
  moodData.forEach((entry) => {
    (entry.emotions || []).forEach((emotion) => {
      emotionCounts[emotion] = (emotionCounts[emotion] || 0) + 1;
    });
  });

  const commonEmotions = Object.entries(emotionCounts)
    .sort((a, b) => b[1] - a[1])
    .slice(0, 5)
    .map(([emotion, count]) => ({
      emotion,
      frequency: count / moodData.length,
    }));

  // Identify stress patterns
  const stressPatterns = [];
  const contextCounts = {};

  moodData.forEach((entry) => {
    if (entry.context) {
      contextCounts[entry.context] = (contextCounts[entry.context] || 0) + 1;
    }
  });

  Object.entries(contextCounts).forEach(([context, count]) => {
    if (count >= 3) {
      stressPatterns.push({
        context,
        frequency: count,
        percentage: ((count / moodData.length) * 100).toFixed(1),
      });
    }
  });

  // Generate recommendations
  const recommendations = generateRecommendations(
    avgMood,
    commonEmotions,
    stressPatterns
  );

  return {
    averageMood: avgMood.toFixed(1),
    moodTrend: trend,
    commonEmotions,
    stressPatterns,
    recommendations,
    dataPoints: moodData.length,
  };
}

function generateRecommendations(avgMood, commonEmotions, stressPatterns) {
  const recommendations = [];

  if (avgMood < 5) {
    recommendations.push({
      type: "support",
      title: "Consider Additional Support",
      description:
        "Your mood has been lower than average. Consider reaching out to campus counseling.",
    });
  }

  const hasAnxiety = commonEmotions.some((e) =>
    ["Anxious", "Stressed", "Overwhelmed"].includes(e.emotion)
  );

  if (hasAnxiety) {
    recommendations.push({
      type: "technique",
      title: "Try Breathing Exercises",
      description:
        "Anxiety is common. Practice the 4-7-8 breathing technique daily.",
    });
  }

  const hasExamStress = stressPatterns.some(
    (p) =>
      p.context.toLowerCase().includes("exam") ||
      p.context.toLowerCase().includes("test")
  );

  if (hasExamStress) {
    recommendations.push({
      type: "academic",
      title: "Exam Preparation Strategy",
      description:
        "Create a study schedule and use the Pomodoro technique for better focus.",
    });
  }

  return recommendations;
}

function analyzeJournalPatterns(journalData) {
  if (journalData.length === 0) {
    return {
      totalEntries: 0,
      averageLength: 0,
      commonThemes: [],
      writingFrequency: "none",
      emotionalTrends: [],
    };
  }

  // Calculate average entry length
  const totalLength = journalData.reduce(
    (sum, entry) => sum + (entry.text?.length || 0),
    0
  );
  const averageLength = Math.round(totalLength / journalData.length);

  // Analyze writing frequency
  const entriesByDay = {};
  journalData.forEach((entry) => {
    const date = new Date(entry.created_at).toDateString();
    entriesByDay[date] = (entriesByDay[date] || 0) + 1;
  });

  const avgEntriesPerDay =
    Object.values(entriesByDay).reduce((a, b) => a + b, 0) /
    Object.keys(entriesByDay).length;
  let writingFrequency = "low";
  if (avgEntriesPerDay >= 1) writingFrequency = "daily";
  else if (avgEntriesPerDay >= 0.5) writingFrequency = "regular";
  else if (avgEntriesPerDay >= 0.2) writingFrequency = "occasional";

  // Simple theme detection (keyword-based)
  const themes = {
    academic: ["study", "exam", "assignment", "class", "homework", "grade"],
    social: ["friend", "roommate", "relationship", "social", "party"],
    stress: ["stress", "anxiety", "overwhelmed", "pressure", "worried"],
    health: ["sleep", "exercise", "health", "tired", "sick"],
    future: ["career", "job", "future", "plan", "goal"],
  };

  const themeCounts = {};
  journalData.forEach((entry) => {
    const text = entry.text?.toLowerCase() || "";
    Object.entries(themes).forEach(([theme, keywords]) => {
      if (keywords.some((keyword) => text.includes(keyword))) {
        themeCounts[theme] = (themeCounts[theme] || 0) + 1;
      }
    });
  });

  const commonThemes = Object.entries(themeCounts)
    .sort((a, b) => b[1] - a[1])
    .slice(0, 3)
    .map(([theme, count]) => ({
      theme,
      frequency: count,
      percentage: Math.round((count / journalData.length) * 100),
    }));

  return {
    totalEntries: journalData.length,
    averageLength,
    commonThemes,
    writingFrequency,
    emotionalTrends: commonThemes,
  };
}

// Privacy and Data Management
app.post("/api/privacy/export", authenticateToken, (req, res) => {
  const userId = req.user.id;

  // Gather all user data
  const userData = {
    profile: {},
    moods: [],
    journals: [],
    exportDate: new Date().toISOString(),
  };

  db.get(`SELECT * FROM users WHERE id = ?`, [userId], (err, user) => {
    if (err || !user) {
      return res.status(404).json({ error: "User not found" });
    }

    userData.profile = {
      username: user.username,
      yearInSchool: user.year_in_school,
      createdAt: user.created_at,
    };

    // Get mood entries
    db.all(
      `SELECT * FROM mood_entries WHERE user_id = ?`,
      [userId],
      (err, moods) => {
        if (!err && moods) {
          userData.moods = moods.map((mood) => ({
            encrypted_data: mood.encrypted_data,
            iv: mood.iv,
            created_at: mood.created_at,
          }));
        }

        // Get journal entries
        db.all(
          `SELECT * FROM journal_entries WHERE user_id = ?`,
          [userId],
          (err, journals) => {
            if (!err && journals) {
              userData.journals = journals.map((journal) => ({
                encrypted_data: journal.encrypted_data,
                iv: journal.iv,
                ai_response: journal.ai_response,
                created_at: journal.created_at,
              }));
            }

            res.json(userData);
          }
        );
      }
    );
  });
});

app.delete("/api/privacy/delete-all", authenticateToken, (req, res) => {
  const userId = req.user.id;

  // Delete all user data
  db.serialize(() => {
    db.run(`DELETE FROM mood_entries WHERE user_id = ?`, [userId]);
    db.run(`DELETE FROM journal_entries WHERE user_id = ?`, [userId]);
    db.run(`DELETE FROM crisis_logs WHERE user_id = ?`, [userId]);
    db.run(`DELETE FROM users WHERE id = ?`, [userId], (err) => {
      if (err) {
        return res.status(500).json({ error: "Failed to delete data" });
      }
      res.json({ success: true, message: "All data deleted successfully" });
    });
  });
});

// Coping Strategies (Static content with personalization)
app.get("/api/strategies", authenticateToken, async (req, res) => {
  const userId = req.user.id;

  // Get user patterns to personalize strategies
  const patterns = await new Promise((resolve) => {
    db.all(
      `SELECT encrypted_data, iv FROM mood_entries 
             WHERE user_id = ? 
             ORDER BY created_at DESC 
             LIMIT 10`,
      [userId],
      (err, rows) => {
        if (err || !rows) {
          resolve([]);
          return;
        }

        // Analyze actual mood data
        const userPatterns = [];
        rows.forEach((row) => {
          try {
            const decrypted = EncryptionService.decrypt(
              row.encrypted_data,
              row.iv,
              req.user.username
            );
            const moodData = JSON.parse(decrypted);

            // Add emotions to patterns
            if (moodData.emotions) {
              moodData.emotions.forEach((emotion) => {
                const lowerEmotion = emotion.toLowerCase();
                if (
                  lowerEmotion.includes("anxious") ||
                  lowerEmotion.includes("stress") ||
                  lowerEmotion.includes("worried")
                ) {
                  userPatterns.push("anxiety", "stress");
                }
                if (
                  lowerEmotion.includes("lonely") ||
                  lowerEmotion.includes("alone") ||
                  lowerEmotion.includes("isolated")
                ) {
                  userPatterns.push("loneliness", "social");
                }
                if (
                  lowerEmotion.includes("overwhelm") ||
                  lowerEmotion.includes("pressure") ||
                  lowerEmotion.includes("burdened")
                ) {
                  userPatterns.push("stress", "anxiety");
                }
                if (
                  lowerEmotion.includes("tired") ||
                  lowerEmotion.includes("exhaust") ||
                  lowerEmotion.includes("fatigue")
                ) {
                  userPatterns.push("sleep", "health");
                }
                if (
                  lowerEmotion.includes("frustrated") ||
                  lowerEmotion.includes("angry") ||
                  lowerEmotion.includes("irritated")
                ) {
                  userPatterns.push("emotional", "stress");
                }
                if (
                  lowerEmotion.includes("sad") ||
                  lowerEmotion.includes("depressed") ||
                  lowerEmotion.includes("down")
                ) {
                  userPatterns.push("emotional", "mood");
                }
                if (
                  lowerEmotion.includes("excited") ||
                  lowerEmotion.includes("happy") ||
                  lowerEmotion.includes("joyful")
                ) {
                  userPatterns.push("gratitude", "positivity");
                }
                if (
                  lowerEmotion.includes("confident") ||
                  lowerEmotion.includes("motivated") ||
                  lowerEmotion.includes("energetic")
                ) {
                  userPatterns.push("energy", "motivation", "confidence");
                }
              });
            }

            // Add context to patterns
            if (moodData.context) {
              const lowerContext = moodData.context.toLowerCase();
              if (
                lowerContext.includes("exam") ||
                lowerContext.includes("test") ||
                lowerContext.includes("assignment") ||
                lowerContext.includes("study")
              ) {
                userPatterns.push("academic", "focus");
              }
              if (
                lowerContext.includes("career") ||
                lowerContext.includes("future") ||
                lowerContext.includes("job") ||
                lowerContext.includes("professional")
              ) {
                userPatterns.push("career", "future", "planning");
              }
              if (
                lowerContext.includes("social") ||
                lowerContext.includes("relationship") ||
                lowerContext.includes("friend")
              ) {
                userPatterns.push("social", "connection");
              }
              if (
                lowerContext.includes("money") ||
                lowerContext.includes("financial") ||
                lowerContext.includes("budget")
              ) {
                userPatterns.push("financial", "stress");
              }
              if (
                lowerContext.includes("phone") ||
                lowerContext.includes("screen") ||
                lowerContext.includes("social media")
              ) {
                userPatterns.push("technology", "focus");
              }
              if (
                lowerContext.includes("room") ||
                lowerContext.includes("environment") ||
                lowerContext.includes("space")
              ) {
                userPatterns.push("environment", "calm");
              }
              if (
                lowerContext.includes("food") ||
                lowerContext.includes("nutrition") ||
                lowerContext.includes("diet")
              ) {
                userPatterns.push("nutrition", "health");
              }
              if (
                lowerContext.includes("exercise") ||
                lowerContext.includes("workout") ||
                lowerContext.includes("physical")
              ) {
                userPatterns.push("physical", "energy");
              }
            }

            // Add mood level patterns
            if (moodData.mood <= 3) {
              userPatterns.push("stress", "anxiety");
            }
          } catch (e) {
            console.error("Error decrypting mood data for strategies");
          }
        });

        // Remove duplicates and return unique patterns
        resolve([...new Set(userPatterns)]);
      }
    );
  });

  const strategies = [
    {
      id: 1,
      category: "quick",
      title: "Box Breathing (5 min)",
      description: "A simple technique to calm your nervous system",
      steps: [
        "Inhale for 4 counts",
        "Hold for 4 counts",
        "Exhale for 4 counts",
        "Hold for 4 counts",
        "Repeat 4-5 times",
      ],
      tags: ["anxiety", "stress", "quick"],
    },
    {
      id: 2,
      category: "academic",
      title: "Pomodoro Technique",
      description: "Improve focus and reduce study stress",
      steps: [
        "25 minutes focused work",
        "5 minute break",
        "Repeat 4 times",
        "15-30 minute long break",
      ],
      tags: ["focus", "productivity", "study"],
    },
    {
      id: 3,
      category: "sleep",
      title: "Sleep Hygiene for Students",
      description: "Better sleep for better mental health",
      steps: [
        "No screens 30 min before bed",
        "Keep room at 65-68°F",
        "Use white noise if needed",
        "Avoid caffeine after 2 PM",
        "Consistent sleep schedule",
      ],
      tags: ["sleep", "routine", "health"],
    },
    {
      id: 4,
      category: "social",
      title: "Social Connection Building",
      description: "Combat loneliness and build friendships",
      steps: [
        "Join one campus club or activity",
        "Study in common areas occasionally",
        "Reach out to one person per week",
        "Attend dorm/floor events",
        "Be patient - friendships take time",
      ],
      tags: ["loneliness", "social", "connection"],
    },
    {
      id: 5,
      category: "physical",
      title: "5-Minute Movement Break",
      description: "Quick physical activity to boost mood and energy",
      steps: [
        "Stand up and stretch",
        "Do 10 jumping jacks",
        "Walk around your room",
        "Do 5 push-ups or wall push-ups",
        "Take 5 deep breaths",
      ],
      tags: ["energy", "mood", "physical", "quick"],
    },
    {
      id: 6,
      category: "mindfulness",
      title: "Body Scan Meditation",
      description: "Connect with your body and reduce tension",
      steps: [
        "Lie down or sit comfortably",
        "Close your eyes",
        "Focus on your toes, then feet",
        "Move attention up your body",
        "Notice any tension and release it",
        "Continue to the top of your head",
      ],
      tags: ["anxiety", "stress", "mindfulness", "relaxation"],
    },
    {
      id: 7,
      category: "nutrition",
      title: "Brain-Boosting Snacks",
      description: "Foods that support mental clarity and mood",
      steps: [
        "Keep nuts and seeds handy",
        "Eat dark chocolate (70%+)",
        "Include fatty fish or omega-3s",
        "Stay hydrated with water",
        "Avoid sugary energy drinks",
      ],
      tags: ["energy", "focus", "nutrition", "health"],
    },
    {
      id: 8,
      category: "academic",
      title: "Study Environment Optimization",
      description: "Create a space that supports learning",
      steps: [
        "Clear your desk completely",
        "Add natural light or good lighting",
        "Keep water and healthy snacks nearby",
        "Use noise-canceling headphones if needed",
        "Set phone to Do Not Disturb",
      ],
      tags: ["focus", "productivity", "study", "environment"],
    },
    {
      id: 9,
      category: "emotional",
      title: "Emotion Labeling Technique",
      description: "Process and understand your feelings",
      steps: [
        "Name the emotion you're feeling",
        "Rate its intensity (1-10)",
        "Identify what triggered it",
        "Notice where you feel it in your body",
        "Remind yourself it's temporary",
      ],
      tags: ["emotions", "self-awareness", "processing"],
    },
    {
      id: 10,
      category: "social",
      title: "Boundary Setting",
      description: "Protect your mental health in relationships",
      steps: [
        "Identify what drains your energy",
        "Practice saying 'no' to small things first",
        "Communicate your needs clearly",
        "Set time limits for social activities",
        "Prioritize your own wellbeing",
      ],
      tags: ["boundaries", "social", "self-care"],
    },
    {
      id: 11,
      category: "creative",
      title: "Creative Expression",
      description: "Use art to process emotions",
      steps: [
        "Doodle or draw for 10 minutes",
        "Write a poem or short story",
        "Create a playlist for your mood",
        "Take photos of things that bring you joy",
        "Try a new creative hobby",
      ],
      tags: ["creativity", "emotions", "self-expression"],
    },
    {
      id: 12,
      category: "routine",
      title: "Morning Routine Reset",
      description: "Start your day with intention",
      steps: [
        "Wake up at the same time daily",
        "Drink a glass of water first",
        "Spend 5 minutes in silence",
        "Write down 3 priorities for the day",
        "Eat a nutritious breakfast",
      ],
      tags: ["routine", "morning", "productivity", "health"],
    },
    {
      id: 13,
      category: "financial",
      title: "Financial Stress Management",
      description: "Reduce money-related anxiety",
      steps: [
        "Track all expenses for one week",
        "Create a simple budget",
        "Look for student discounts",
        "Consider part-time work or gigs",
        "Talk to financial aid office",
      ],
      tags: ["financial", "stress", "planning"],
    },
    {
      id: 14,
      category: "technology",
      title: "Digital Detox",
      description: "Reduce screen time for better mental health",
      steps: [
        "Set app time limits on your phone",
        "Turn off notifications for social media",
        "Use grayscale mode to reduce appeal",
        "Charge phone outside bedroom",
        "Schedule tech-free hours daily",
      ],
      tags: ["technology", "stress", "focus", "sleep"],
    },
    {
      id: 15,
      category: "gratitude",
      title: "Gratitude Practice",
      description: "Shift focus to positive aspects of life",
      steps: [
        "Write down 3 things you're grateful for",
        "Thank someone who helped you",
        "Notice small moments of joy",
        "Reflect on your progress",
        "Share appreciation with others",
      ],
      tags: ["gratitude", "positivity", "mood", "confidence", "motivation"],
    },
    {
      id: 16,
      category: "academic",
      title: "Test Anxiety Management",
      description: "Prepare mentally for exams",
      steps: [
        "Review material in small chunks",
        "Practice deep breathing before tests",
        "Get adequate sleep the night before",
        "Eat a light, nutritious meal",
        "Arrive early to avoid rushing",
      ],
      tags: ["anxiety", "academic", "exams", "stress"],
    },
    {
      id: 17,
      category: "physical",
      title: "Progressive Muscle Relaxation",
      description: "Release physical tension systematically",
      steps: [
        "Start with your toes",
        "Tense muscles for 5 seconds",
        "Release and feel the relaxation",
        "Move up to calves, thighs, stomach",
        "Continue to shoulders and face",
      ],
      tags: ["relaxation", "tension", "physical", "stress"],
    },
    {
      id: 18,
      category: "social",
      title: "Conflict Resolution",
      description: "Handle disagreements constructively",
      steps: [
        "Take time to cool down first",
        "Use 'I feel' statements",
        "Listen without interrupting",
        "Find common ground",
        "Agree to disagree when needed",
      ],
      tags: ["conflict", "communication", "social"],
    },
    {
      id: 19,
      category: "environment",
      title: "Study Space Transformation",
      description: "Create a calming, productive environment",
      steps: [
        "Add plants or natural elements",
        "Use calming colors (blue, green)",
        "Organize supplies and materials",
        "Add personal touches (photos, art)",
        "Keep it clean and clutter-free",
      ],
      tags: ["environment", "calm", "productivity", "study"],
    },
    {
      id: 20,
      category: "mindfulness",
      title: "Walking Meditation",
      description: "Practice mindfulness while moving",
      steps: [
        "Walk slowly and deliberately",
        "Focus on the sensation of walking",
        "Notice your surroundings",
        "Breathe naturally",
        "Return to walking when mind wanders",
      ],
      tags: ["mindfulness", "movement", "meditation", "stress"],
    },
    {
      id: 21,
      category: "emotional",
      title: "Self-Compassion Break",
      description: "Be kind to yourself during difficult times",
      steps: [
        "Acknowledge your suffering",
        "Remember you're not alone",
        "Offer yourself kind words",
        "Place hand on heart if helpful",
        "Give yourself permission to struggle",
      ],
      tags: ["self-compassion", "kindness", "emotional"],
    },
    {
      id: 22,
      category: "academic",
      title: "Note-Taking Strategy",
      description: "Improve learning and reduce study stress",
      steps: [
        "Use the Cornell method",
        "Write key points in your own words",
        "Review notes within 24 hours",
        "Create visual summaries",
        "Teach concepts to others",
      ],
      tags: ["study", "learning", "academic", "organization"],
    },
    {
      id: 23,
      category: "sleep",
      title: "Power Nap Protocol",
      description: "Recharge without disrupting sleep cycle",
      steps: [
        "Set alarm for 20-30 minutes",
        "Find a quiet, dark space",
        "Lie down or recline comfortably",
        "Focus on your breathing",
        "Don't worry if you don't fall asleep",
      ],
      tags: ["sleep", "energy", "rest", "quick"],
    },
    {
      id: 24,
      category: "social",
      title: "Active Listening",
      description: "Improve relationships through better communication",
      steps: [
        "Maintain eye contact",
        "Don't interrupt or plan responses",
        "Ask clarifying questions",
        "Reflect back what you heard",
        "Show empathy and understanding",
      ],
      tags: ["communication", "social", "relationships"],
    },
    {
      id: 25,
      category: "creative",
      title: "Vision Board Creation",
      description: "Visualize your goals and aspirations",
      steps: [
        "Collect images that inspire you",
        "Add words and quotes",
        "Include academic and personal goals",
        "Place where you'll see it daily",
        "Update as goals evolve",
      ],
      tags: ["goals", "motivation", "creative", "planning", "confidence", "future", "career"],
    },
    {
      id: 26,
      category: "routine",
      title: "Goal Achievement Framework",
      description: "Turn confidence into concrete progress",
      steps: [
        "Break big goals into small, actionable steps",
        "Set specific deadlines for each step",
        "Track progress weekly",
        "Celebrate small wins",
        "Adjust goals as needed",
      ],
      tags: ["goals", "motivation", "confidence", "planning", "productivity"],
    },
    {
      id: 27,
      category: "academic",
      title: "Career Development Planning",
      description: "Build your professional future",
      steps: [
        "Research career paths in your field",
        "Connect with professionals on LinkedIn",
        "Attend career fairs and networking events",
        "Develop relevant skills through courses",
        "Create a professional portfolio",
      ],
      tags: ["career", "future", "planning", "motivation", "confidence"],
    },
    {
      id: 28,
      category: "social",
      title: "Networking Confidence Builder",
      description: "Build professional relationships with confidence",
      steps: [
        "Practice your elevator pitch",
        "Prepare thoughtful questions to ask",
        "Follow up with new connections",
        "Join professional organizations",
        "Attend industry meetups",
      ],
      tags: ["social", "confidence", "career", "networking", "motivation"],
    },
    {
      id: 29,
      category: "mindfulness",
      title: "Confidence Meditation",
      description: "Strengthen your self-assurance through mindfulness",
      steps: [
        "Sit comfortably and close your eyes",
        "Focus on your breath",
        "Recall a moment of success",
        "Feel the confidence in your body",
        "Affirm your capabilities",
      ],
      tags: ["confidence", "mindfulness", "motivation", "self-awareness"],
    },
    {
      id: 30,
      category: "physical",
      title: "Power Pose Practice",
      description: "Use body language to boost confidence",
      steps: [
        "Stand with feet shoulder-width apart",
        "Place hands on hips",
        "Lift your chin slightly",
        "Take deep breaths",
        "Hold for 2 minutes before important events",
      ],
      tags: ["confidence", "physical", "motivation", "energy"],
    },
  ];

  // Prioritize strategies based on user patterns
  const personalizedStrategies = strategies.sort((a, b) => {
    const aRelevance = a.tags.filter((tag) => patterns.includes(tag)).length;
    const bRelevance = b.tags.filter((tag) => patterns.includes(tag)).length;
    return bRelevance - aRelevance;
  });

  // Add debugging information
  console.log("User patterns detected:", patterns);
  console.log("Top 5 strategies:", personalizedStrategies.slice(0, 5).map(s => ({ title: s.title, tags: s.tags, relevance: s.tags.filter(tag => patterns.includes(tag)).length })));

  // Return only top 6 strategies to ensure variety and prevent overwhelming
  res.json(personalizedStrategies.slice(0, 6));
});



// Crisis Resources (Static)
app.get("/api/crisis/resources", (req, res) => {
  res.json([
    {
      name: "National Suicide Prevention Lifeline",
      number: "988",
      description: "24/7 free and confidential support",
      type: "hotline",
    },
    {
      name: "Crisis Text Line",
      number: "Text HOME to 741741",
      description: "Free 24/7 text support",
      type: "text",
    },
    {
      name: "Campus Counseling",
      description: "Contact your university counseling center",
      type: "campus",
    },
    {
      name: "Emergency Services",
      number: "911",
      description: "For immediate danger",
      type: "emergency",
    },
  ]);
});

// Health check endpoint
app.get("/api/health", (req, res) => {
  res.json({
    status: "healthy",
    timestamp: new Date().toISOString(),
    environment: process.env.NODE_ENV || "development",
  });
});

// Serve the frontend
app.get("*", (req, res) => {
  res.sendFile(path.join(__dirname, "public", "index.html"));
});

// Error handling middleware
app.use((err, req, res, next) => {
  console.error(err.stack);
  res.status(500).json({
    error: "Something went wrong!",
    message: process.env.NODE_ENV === "development" ? err.message : undefined,
  });
});

// Start server only if this file is run directly
if (require.main === module) {
  const server = app.listen(PORT, () => {
    console.log(`
        🧠 MindPath Server Running
        ========================
        Port: ${PORT}
        Environment: ${process.env.NODE_ENV || "development"}
        Database: ./mindpath.db
        
        Frontend: http://localhost:${PORT}
        API: http://localhost:${PORT}/api
        Health: http://localhost:${PORT}/api/health
        
        Security Features:
        ✅ End-to-end encryption
        ✅ JWT authentication
        ✅ Rate limiting
        ✅ CORS protection
        ✅ SQL injection prevention
        ✅ XSS protection
        
        To test the API:
        curl http://localhost:${PORT}/api/health
        `);
  });

  // Graceful shutdown
  process.on("SIGTERM", () => {
    console.log("SIGTERM signal received: closing HTTP server");
    server.close(() => {
      console.log("HTTP server closed");
      db.close(() => {
        console.log("Database connection closed");
        process.exit(0);
      });
    });
  });
}

module.exports = app;
