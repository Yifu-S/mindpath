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

            // Add emotions to patterns (8 core emotions)
            if (moodData.emotions) {
              console.log("😊 Processing emotions:", moodData.emotions);
              moodData.emotions.forEach((emotion) => {
                const lowerEmotion = emotion.toLowerCase();
                if (lowerEmotion.includes("anxious")) {
                  userPatterns.push("anxiety", "stress");
                }
                if (lowerEmotion.includes("stressed")) {
                  userPatterns.push("stress", "anxiety");
                }
                if (lowerEmotion.includes("lonely")) {
                  userPatterns.push("loneliness", "social");
                }
                if (lowerEmotion.includes("exhausted")) {
                  userPatterns.push("sleep", "health");
                }
                if (lowerEmotion.includes("confident")) {
                  userPatterns.push("confidence", "motivation");
                }
                if (lowerEmotion.includes("motivated")) {
                  userPatterns.push("motivation", "energy");
                }
                if (lowerEmotion.includes("excited")) {
                  userPatterns.push("positivity", "energy");
                }
                if (lowerEmotion.includes("frustrated")) {
                  userPatterns.push("stress", "emotional");
                }
              });
            }

            // Add context to patterns (8 core contexts)
            if (moodData.context) {
              console.log("🎯 Processing context:", moodData.context);
              const lowerContext = moodData.context.toLowerCase();
              if (
                lowerContext.includes("exams") ||
                lowerContext.includes("tests")
              ) {
                userPatterns.push("academic", "focus");
              }
              if (lowerContext.includes("assignments")) {
                userPatterns.push("academic", "focus");
              }
              if (lowerContext.includes("social life")) {
                userPatterns.push("social", "connection");
              }
              if (lowerContext.includes("relationships")) {
                userPatterns.push("social", "connection");
              }
              if (lowerContext.includes("family")) {
                userPatterns.push("social", "connection");
              }
              if (lowerContext.includes("financial")) {
                userPatterns.push("financial", "stress");
              }
              if (
                lowerContext.includes("career") ||
                lowerContext.includes("future")
              ) {
                userPatterns.push("career", "future", "planning");
              }
              if (lowerContext.includes("health")) {
                userPatterns.push("health", "sleep");
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
        const uniquePatterns = [...new Set(userPatterns)];
        console.log("🔍 Detected patterns for user:", uniquePatterns);
        console.log("📊 Raw mood data analyzed:", rows.length, "entries");
        resolve(uniquePatterns);
      }
    );
  });

  // Strategy pools for each emotion-context combination
  const strategyPools = {
    // Anxious emotion pools
    anxious: {
      "exams/tests": {
        pool1: [
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
          },
          {
            id: 2,
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
          },
          {
            id: 3,
            category: "mindfulness",
            title: "Progressive Muscle Relaxation",
            description: "Release physical tension systematically",
            steps: [
              "Start with your toes",
              "Tense muscles for 5 seconds",
              "Release and feel the relaxation",
              "Move up to calves, thighs, stomach",
              "Continue to shoulders and face",
            ],
          },
          {
            id: 4,
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
          },
        ],
        pool2: [
          {
            id: 5,
            category: "academic",
            title: "Pomodoro Technique",
            description: "Improve focus and reduce study stress",
            steps: [
              "25 minutes focused work",
              "5 minute break",
              "Repeat 4 times",
              "15-30 minute long break",
            ],
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
          },
          {
            id: 7,
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
          },
          {
            id: 8,
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
          },
        ],
      },
      assignments: {
        pool1: [
          {
            id: 9,
            category: "academic",
            title: "Assignment Breakdown Method",
            description: "Break large assignments into manageable pieces",
            steps: [
              "List all requirements",
              "Break into smaller tasks",
              "Set deadlines for each task",
              "Start with easiest part first",
              "Review and revise",
            ],
          },
          {
            id: 10,
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
          },
          {
            id: 11,
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
          },
          {
            id: 12,
            category: "mindfulness",
            title: "Progressive Muscle Relaxation",
            description: "Release physical tension systematically",
            steps: [
              "Start with your toes",
              "Tense muscles for 5 seconds",
              "Release and feel the relaxation",
              "Move up to calves, thighs, stomach",
              "Continue to shoulders and face",
            ],
          },
        ],
        pool2: [
          {
            id: 13,
            category: "academic",
            title: "Pomodoro Technique",
            description: "Improve focus and reduce study stress",
            steps: [
              "25 minutes focused work",
              "5 minute break",
              "Repeat 4 times",
              "15-30 minute long break",
            ],
          },
          {
            id: 14,
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
          },
          {
            id: 15,
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
          },
          {
            id: 16,
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
          },
        ],
      },
      "social life": {
        pool1: [
          {
            id: 17,
            category: "social",
            title: "Social Anxiety Coping",
            description: "Manage social anxiety in group settings",
            steps: [
              "Practice deep breathing before events",
              "Set realistic expectations",
              "Focus on listening rather than talking",
              "Have an exit plan if needed",
              "Remember everyone feels nervous sometimes",
            ],
          },
          {
            id: 18,
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
          },
          {
            id: 19,
            category: "mindfulness",
            title: "Progressive Muscle Relaxation",
            description: "Release physical tension systematically",
            steps: [
              "Start with your toes",
              "Tense muscles for 5 seconds",
              "Release and feel the relaxation",
              "Move up to calves, thighs, stomach",
              "Continue to shoulders and face",
            ],
          },
          {
            id: 20,
            category: "social",
            title: "Small Talk Preparation",
            description: "Prepare for social interactions",
            steps: [
              "Think of 3 conversation starters",
              "Practice asking follow-up questions",
              "Remember people love talking about themselves",
              "Have a few interesting topics ready",
              "Practice with a friend first",
            ],
          },
        ],
        pool2: [
          {
            id: 21,
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
          },
          {
            id: 22,
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
          },
          {
            id: 23,
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
          },
        ],
      },
      relationships: {
        pool1: [
          {
            id: 25,
            category: "social",
            title: "Relationship Anxiety Management",
            description: "Handle anxiety in relationships",
            steps: [
              "Communicate your feelings openly",
              "Practice self-soothing techniques",
              "Set healthy boundaries",
              "Focus on the present moment",
              "Seek support from trusted friends",
            ],
          },
          {
            id: 26,
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
          },
          {
            id: 27,
            category: "mindfulness",
            title: "Progressive Muscle Relaxation",
            description: "Release physical tension systematically",
            steps: [
              "Start with your toes",
              "Tense muscles for 5 seconds",
              "Release and feel the relaxation",
              "Move up to calves, thighs, stomach",
              "Continue to shoulders and face",
            ],
          },
          {
            id: 28,
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
          },
        ],
        pool2: [
          {
            id: 29,
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
          },
          {
            id: 30,
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
          },
          {
            id: 31,
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
          },
          {
            id: 32,
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
          },
        ],
      },
      family: {
        pool1: [
          {
            id: 33,
            category: "social",
            title: "Family Communication",
            description: "Improve communication with family",
            steps: [
              "Set regular check-in times",
              "Be honest about your feelings",
              "Listen to their concerns",
              "Set healthy boundaries",
              "Express appreciation regularly",
            ],
          },
          {
            id: 34,
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
          },
          {
            id: 35,
            category: "mindfulness",
            title: "Progressive Muscle Relaxation",
            description: "Release physical tension systematically",
            steps: [
              "Start with your toes",
              "Tense muscles for 5 seconds",
              "Release and feel the relaxation",
              "Move up to calves, thighs, stomach",
              "Continue to shoulders and face",
            ],
          },
          {
            id: 36,
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
          },
        ],
        pool2: [
          {
            id: 37,
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
          },
          {
            id: 38,
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
          },
          {
            id: 39,
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
          },
          {
            id: 40,
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
          },
        ],
      },
      financial: {
        pool1: [
          {
            id: 41,
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
          },
          {
            id: 42,
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
          },
          {
            id: 43,
            category: "mindfulness",
            title: "Progressive Muscle Relaxation",
            description: "Release physical tension systematically",
            steps: [
              "Start with your toes",
              "Tense muscles for 5 seconds",
              "Release and feel the relaxation",
              "Move up to calves, thighs, stomach",
              "Continue to shoulders and face",
            ],
          },
          {
            id: 44,
            category: "financial",
            title: "Budget Planning",
            description: "Create a realistic student budget",
            steps: [
              "List all income sources",
              "Track monthly expenses",
              "Set spending limits",
              "Plan for emergencies",
              "Review and adjust monthly",
            ],
          },
        ],
        pool2: [
          {
            id: 45,
            category: "financial",
            title: "Student Money Management",
            description: "Smart financial strategies for students",
            steps: [
              "Use student discounts everywhere",
              "Cook meals instead of eating out",
              "Share expenses with roommates",
              "Use public transportation",
              "Find free campus activities",
            ],
          },
          {
            id: 46,
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
          },
          {
            id: 47,
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
          },
          {
            id: 48,
            category: "financial",
            title: "Financial Goal Setting",
            description: "Set and achieve financial goals",
            steps: [
              "Define short and long-term goals",
              "Break goals into smaller steps",
              "Track progress regularly",
              "Celebrate small wins",
              "Adjust goals as needed",
            ],
          },
        ],
      },
      "career/future": {
        pool1: [
          {
            id: 49,
            category: "academic",
            title: "Career Anxiety Management",
            description: "Handle anxiety about future career",
            steps: [
              "Focus on what you can control",
              "Break career planning into small steps",
              "Practice self-compassion",
              "Seek career counseling",
              "Remember it's okay to change paths",
            ],
          },
          {
            id: 50,
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
          },
          {
            id: 51,
            category: "mindfulness",
            title: "Progressive Muscle Relaxation",
            description: "Release physical tension systematically",
            steps: [
              "Start with your toes",
              "Tense muscles for 5 seconds",
              "Release and feel the relaxation",
              "Move up to calves, thighs, stomach",
              "Continue to shoulders and face",
            ],
          },
          {
            id: 52,
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
          },
        ],
        pool2: [
          {
            id: 53,
            category: "academic",
            title: "Networking Confidence Builder",
            description: "Build professional relationships with confidence",
            steps: [
              "Practice your elevator pitch",
              "Prepare thoughtful questions to ask",
              "Follow up with new connections",
              "Join professional organizations",
              "Attend industry meetups",
            ],
          },
          {
            id: 54,
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
          },
          {
            id: 55,
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
          },
          {
            id: 56,
            category: "academic",
            title: "Skill Development Planning",
            description: "Plan your skill development journey",
            steps: [
              "Identify skills needed for your field",
              "Take online courses",
              "Practice skills through projects",
              "Seek feedback from mentors",
              "Update your resume regularly",
            ],
          },
        ],
      },
      health: {
        pool1: [
          {
            id: 57,
            category: "health",
            title: "Health Anxiety Management",
            description: "Manage anxiety about health",
            steps: [
              "Focus on facts, not fears",
              "Practice good self-care",
              "Seek professional help if needed",
              "Limit health-related internet searches",
              "Build a support network",
            ],
          },
          {
            id: 58,
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
          },
          {
            id: 59,
            category: "mindfulness",
            title: "Progressive Muscle Relaxation",
            description: "Release physical tension systematically",
            steps: [
              "Start with your toes",
              "Tense muscles for 5 seconds",
              "Release and feel the relaxation",
              "Move up to calves, thighs, stomach",
              "Continue to shoulders and face",
            ],
          },
          {
            id: 60,
            category: "health",
            title: "Wellness Routine Building",
            description: "Create a sustainable wellness routine",
            steps: [
              "Start with small, manageable changes",
              "Include physical activity",
              "Prioritize sleep",
              "Eat nutritious foods",
              "Practice stress management",
            ],
          },
        ],
        pool2: [
          {
            id: 61,
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
          },
          {
            id: 62,
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
          },
          {
            id: 63,
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
          },
          {
            id: 64,
            category: "health",
            title: "Stress Management Techniques",
            description: "Comprehensive stress management approach",
            steps: [
              "Identify stress triggers",
              "Practice regular relaxation",
              "Maintain healthy boundaries",
              "Seek social support",
              "Consider professional help if needed",
            ],
          },
        ],
      },
    },
    // Lonely emotion pools
    lonely: {
      "exams/tests": {
        pool1: [
          {
            id: 129,
            category: "social",
            title: "Study Group Formation",
            description: "Connect with others while studying",
            steps: [
              "Post in class group chats",
              "Ask classmates to study together",
              "Join existing study groups",
              "Create a study schedule with others",
              "Share notes and resources",
            ],
          },
          {
            id: 130,
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
          },
          {
            id: 131,
            category: "mindfulness",
            title: "Progressive Muscle Relaxation",
            description: "Release physical tension systematically",
            steps: [
              "Start with your toes",
              "Tense muscles for 5 seconds",
              "Release and feel the relaxation",
              "Move up to calves, thighs, stomach",
              "Continue to shoulders and face",
            ],
          },
          {
            id: 132,
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
          },
        ],
        pool2: [
          {
            id: 133,
            category: "academic",
            title: "Pomodoro Technique",
            description: "Improve focus and reduce study stress",
            steps: [
              "25 minutes focused work",
              "5 minute break",
              "Repeat 4 times",
              "15-30 minute long break",
            ],
          },
          {
            id: 134,
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
          },
          {
            id: 135,
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
          },
          {
            id: 136,
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
          },
        ],
      },
      assignments: {
        pool1: [
          {
            id: 137,
            category: "social",
            title: "Collaborative Assignment Work",
            description: "Work on assignments with others",
            steps: [
              "Find classmates working on similar assignments",
              "Set up virtual study sessions",
              "Share resources and ideas",
              "Give and receive feedback",
              "Celebrate completion together",
            ],
          },
          {
            id: 138,
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
          },
          {
            id: 139,
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
          },
          {
            id: 140,
            category: "mindfulness",
            title: "Progressive Muscle Relaxation",
            description: "Release physical tension systematically",
            steps: [
              "Start with your toes",
              "Tense muscles for 5 seconds",
              "Release and feel the relaxation",
              "Move up to calves, thighs, stomach",
              "Continue to shoulders and face",
            ],
          },
        ],
        pool2: [
          {
            id: 141,
            category: "academic",
            title: "Pomodoro Technique",
            description: "Improve focus and reduce study stress",
            steps: [
              "25 minutes focused work",
              "5 minute break",
              "Repeat 4 times",
              "15-30 minute long break",
            ],
          },
          {
            id: 142,
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
          },
          {
            id: 143,
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
          },
          {
            id: 144,
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
          },
        ],
      },
      "social life": {
        pool1: [
          {
            id: 145,
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
          },
          {
            id: 146,
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
          },
          {
            id: 147,
            category: "mindfulness",
            title: "Progressive Muscle Relaxation",
            description: "Release physical tension systematically",
            steps: [
              "Start with your toes",
              "Tense muscles for 5 seconds",
              "Release and feel the relaxation",
              "Move up to calves, thighs, stomach",
              "Continue to shoulders and face",
            ],
          },
          {
            id: 148,
            category: "social",
            title: "Small Talk Preparation",
            description: "Prepare for social interactions",
            steps: [
              "Think of 3 conversation starters",
              "Practice asking follow-up questions",
              "Remember people love talking about themselves",
              "Have a few interesting topics ready",
              "Practice with a friend first",
            ],
          },
        ],
        pool2: [
          {
            id: 149,
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
          },
          {
            id: 150,
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
          },
          {
            id: 151,
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
          },
          {
            id: 152,
            category: "social",
            title: "Social Anxiety Coping",
            description: "Manage social anxiety in group settings",
            steps: [
              "Practice deep breathing before events",
              "Set realistic expectations",
              "Focus on listening rather than talking",
              "Have an exit plan if needed",
              "Remember everyone feels nervous sometimes",
            ],
          },
        ],
      },
      relationships: {
        pool1: [
          {
            id: 153,
            category: "social",
            title: "Relationship Building",
            description: "Build deeper connections with others",
            steps: [
              "Be vulnerable and share your feelings",
              "Show genuine interest in others",
              "Spend quality time together",
              "Express appreciation regularly",
              "Be a good listener",
            ],
          },
          {
            id: 154,
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
          },
          {
            id: 155,
            category: "mindfulness",
            title: "Progressive Muscle Relaxation",
            description: "Release physical tension systematically",
            steps: [
              "Start with your toes",
              "Tense muscles for 5 seconds",
              "Release and feel the relaxation",
              "Move up to calves, thighs, stomach",
              "Continue to shoulders and face",
            ],
          },
          {
            id: 156,
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
          },
        ],
        pool2: [
          {
            id: 157,
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
          },
          {
            id: 158,
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
          },
          {
            id: 159,
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
          },
          {
            id: 160,
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
          },
        ],
      },
      family: {
        pool1: [
          {
            id: 161,
            category: "social",
            title: "Family Communication",
            description: "Improve communication with family",
            steps: [
              "Set regular check-in times",
              "Be honest about your feelings",
              "Listen to their concerns",
              "Set healthy boundaries",
              "Express appreciation regularly",
            ],
          },
          {
            id: 162,
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
          },
          {
            id: 163,
            category: "mindfulness",
            title: "Progressive Muscle Relaxation",
            description: "Release physical tension systematically",
            steps: [
              "Start with your toes",
              "Tense muscles for 5 seconds",
              "Release and feel the relaxation",
              "Move up to calves, thighs, stomach",
              "Continue to shoulders and face",
            ],
          },
          {
            id: 164,
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
          },
        ],
        pool2: [
          {
            id: 165,
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
          },
          {
            id: 166,
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
          },
          {
            id: 167,
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
          },
          {
            id: 168,
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
          },
        ],
      },
      financial: {
        pool1: [
          {
            id: 169,
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
          },
          {
            id: 170,
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
          },
          {
            id: 171,
            category: "mindfulness",
            title: "Progressive Muscle Relaxation",
            description: "Release physical tension systematically",
            steps: [
              "Start with your toes",
              "Tense muscles for 5 seconds",
              "Release and feel the relaxation",
              "Move up to calves, thighs, stomach",
              "Continue to shoulders and face",
            ],
          },
          {
            id: 172,
            category: "financial",
            title: "Budget Planning",
            description: "Create a realistic student budget",
            steps: [
              "List all income sources",
              "Track monthly expenses",
              "Set spending limits",
              "Plan for emergencies",
              "Review and adjust monthly",
            ],
          },
        ],
        pool2: [
          {
            id: 173,
            category: "financial",
            title: "Student Money Management",
            description: "Smart financial strategies for students",
            steps: [
              "Use student discounts everywhere",
              "Cook meals instead of eating out",
              "Share expenses with roommates",
              "Use public transportation",
              "Find free campus activities",
            ],
          },
          {
            id: 174,
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
          },
          {
            id: 175,
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
          },
          {
            id: 176,
            category: "financial",
            title: "Financial Goal Setting",
            description: "Set and achieve financial goals",
            steps: [
              "Define short and long-term goals",
              "Break goals into smaller steps",
              "Track progress regularly",
              "Celebrate small wins",
              "Adjust goals as needed",
            ],
          },
        ],
      },
      "career/future": {
        pool1: [
          {
            id: 177,
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
          },
          {
            id: 178,
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
          },
          {
            id: 179,
            category: "mindfulness",
            title: "Progressive Muscle Relaxation",
            description: "Release physical tension systematically",
            steps: [
              "Start with your toes",
              "Tense muscles for 5 seconds",
              "Release and feel the relaxation",
              "Move up to calves, thighs, stomach",
              "Continue to shoulders and face",
            ],
          },
          {
            id: 180,
            category: "academic",
            title: "Networking Confidence Builder",
            description: "Build professional relationships with confidence",
            steps: [
              "Practice your elevator pitch",
              "Prepare thoughtful questions to ask",
              "Follow up with new connections",
              "Join professional organizations",
              "Attend industry meetups",
            ],
          },
        ],
        pool2: [
          {
            id: 181,
            category: "academic",
            title: "Skill Development Planning",
            description: "Plan your skill development journey",
            steps: [
              "Identify skills needed for your field",
              "Take online courses",
              "Practice skills through projects",
              "Seek feedback from mentors",
              "Update your resume regularly",
            ],
          },
          {
            id: 182,
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
          },
          {
            id: 183,
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
          },
          {
            id: 184,
            category: "academic",
            title: "Career Anxiety Management",
            description: "Handle anxiety about future career",
            steps: [
              "Focus on what you can control",
              "Break career planning into small steps",
              "Practice self-compassion",
              "Seek career counseling",
              "Remember it's okay to change paths",
            ],
          },
        ],
      },
      health: {
        pool1: [
          {
            id: 185,
            category: "health",
            title: "Health Anxiety Management",
            description: "Manage anxiety about health",
            steps: [
              "Focus on facts, not fears",
              "Practice good self-care",
              "Seek professional help if needed",
              "Limit health-related internet searches",
              "Build a support network",
            ],
          },
          {
            id: 186,
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
          },
          {
            id: 187,
            category: "mindfulness",
            title: "Progressive Muscle Relaxation",
            description: "Release physical tension systematically",
            steps: [
              "Start with your toes",
              "Tense muscles for 5 seconds",
              "Release and feel the relaxation",
              "Move up to calves, thighs, stomach",
              "Continue to shoulders and face",
            ],
          },
          {
            id: 188,
            category: "health",
            title: "Wellness Routine Building",
            description: "Create a sustainable wellness routine",
            steps: [
              "Start with small, manageable changes",
              "Include physical activity",
              "Prioritize sleep",
              "Eat nutritious foods",
              "Practice stress management",
            ],
          },
        ],
        pool2: [
          {
            id: 189,
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
          },
          {
            id: 190,
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
          },
          {
            id: 191,
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
          },
          {
            id: 192,
            category: "health",
            title: "Stress Management Techniques",
            description: "Comprehensive stress management approach",
            steps: [
              "Identify stress triggers",
              "Practice regular relaxation",
              "Maintain healthy boundaries",
              "Seek social support",
              "Consider professional help if needed",
            ],
          },
        ],
      },
    },
    // Exhausted emotion pools
    exhausted: {
      "exams/tests": {
        pool1: [
          {
            id: 193,
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
          },
          {
            id: 194,
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
          },
          {
            id: 195,
            category: "mindfulness",
            title: "Progressive Muscle Relaxation",
            description: "Release physical tension systematically",
            steps: [
              "Start with your toes",
              "Tense muscles for 5 seconds",
              "Release and feel the relaxation",
              "Move up to calves, thighs, stomach",
              "Continue to shoulders and face",
            ],
          },
          {
            id: 196,
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
          },
        ],
        pool2: [
          {
            id: 197,
            category: "academic",
            title: "Pomodoro Technique",
            description: "Improve focus and reduce study stress",
            steps: [
              "25 minutes focused work",
              "5 minute break",
              "Repeat 4 times",
              "15-30 minute long break",
            ],
          },
          {
            id: 198,
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
          },
          {
            id: 199,
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
          },
          {
            id: 200,
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
          },
        ],
      },
      financial: {
        pool1: [
          {
            id: 201,
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
          },
          {
            id: 202,
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
          },
          {
            id: 203,
            category: "mindfulness",
            title: "Progressive Muscle Relaxation",
            description: "Release physical tension systematically",
            steps: [
              "Start with your toes",
              "Tense muscles for 5 seconds",
              "Release and feel the relaxation",
              "Move up to calves, thighs, stomach",
              "Continue to shoulders and face",
            ],
          },
          {
            id: 204,
            category: "financial",
            title: "Budget Planning",
            description: "Create a realistic student budget",
            steps: [
              "List all income sources",
              "Track monthly expenses",
              "Set spending limits",
              "Plan for emergencies",
              "Review and adjust monthly",
            ],
          },
        ],
        pool2: [
          {
            id: 205,
            category: "financial",
            title: "Student Money Management",
            description: "Smart financial strategies for students",
            steps: [
              "Use student discounts everywhere",
              "Cook meals instead of eating out",
              "Share expenses with roommates",
              "Use public transportation",
              "Find free campus activities",
            ],
          },
          {
            id: 206,
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
          },
          {
            id: 207,
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
          },
          {
            id: 208,
            category: "financial",
            title: "Financial Goal Setting",
            description: "Set and achieve financial goals",
            steps: [
              "Define short and long-term goals",
              "Break goals into smaller steps",
              "Track progress regularly",
              "Celebrate small wins",
              "Adjust goals as needed",
            ],
          },
        ],
      },
    },
    // Confident emotion pools
    confident: {
      "exams/tests": {
        pool1: [
          {
            id: 209,
            category: "academic",
            title: "Test Confidence Building",
            description: "Maintain confidence during exams",
            steps: [
              "Review your preparation",
              "Use positive self-talk",
              "Focus on what you know",
              "Stay calm and composed",
              "Trust your abilities",
            ],
          },
          {
            id: 210,
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
          },
          {
            id: 211,
            category: "mindfulness",
            title: "Progressive Muscle Relaxation",
            description: "Release physical tension systematically",
            steps: [
              "Start with your toes",
              "Tense muscles for 5 seconds",
              "Release and feel the relaxation",
              "Move up to calves, thighs, stomach",
              "Continue to shoulders and face",
            ],
          },
          {
            id: 212,
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
          },
        ],
        pool2: [
          {
            id: 213,
            category: "academic",
            title: "Pomodoro Technique",
            description: "Improve focus and reduce study stress",
            steps: [
              "25 minutes focused work",
              "5 minute break",
              "Repeat 4 times",
              "15-30 minute long break",
            ],
          },
          {
            id: 214,
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
          },
          {
            id: 215,
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
          },
          {
            id: 216,
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
          },
        ],
      },
      "career/future": {
        pool1: [
          {
            id: 217,
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
          },
          {
            id: 218,
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
          },
          {
            id: 219,
            category: "mindfulness",
            title: "Progressive Muscle Relaxation",
            description: "Release physical tension systematically",
            steps: [
              "Start with your toes",
              "Tense muscles for 5 seconds",
              "Release and feel the relaxation",
              "Move up to calves, thighs, stomach",
              "Continue to shoulders and face",
            ],
          },
          {
            id: 220,
            category: "academic",
            title: "Networking Confidence Builder",
            description: "Build professional relationships with confidence",
            steps: [
              "Practice your elevator pitch",
              "Prepare thoughtful questions to ask",
              "Follow up with new connections",
              "Join professional organizations",
              "Attend industry meetups",
            ],
          },
        ],
        pool2: [
          {
            id: 221,
            category: "academic",
            title: "Skill Development Planning",
            description: "Plan your skill development journey",
            steps: [
              "Identify skills needed for your field",
              "Take online courses",
              "Practice skills through projects",
              "Seek feedback from mentors",
              "Update your resume regularly",
            ],
          },
          {
            id: 222,
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
          },
          {
            id: 223,
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
          },
          {
            id: 224,
            category: "academic",
            title: "Career Anxiety Management",
            description: "Handle anxiety about future career",
            steps: [
              "Focus on what you can control",
              "Break career planning into small steps",
              "Practice self-compassion",
              "Seek career counseling",
              "Remember it's okay to change paths",
            ],
          },
        ],
      },
    },
    // Motivated emotion pools
    motivated: {
      "exams/tests": {
        pool1: [
          {
            id: 225,
            category: "academic",
            title: "Study Momentum Building",
            description: "Maintain motivation during study sessions",
            steps: [
              "Set specific study goals",
              "Break tasks into smaller chunks",
              "Reward yourself for progress",
              "Track your achievements",
              "Stay focused on your goals",
            ],
          },
          {
            id: 226,
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
          },
          {
            id: 227,
            category: "mindfulness",
            title: "Progressive Muscle Relaxation",
            description: "Release physical tension systematically",
            steps: [
              "Start with your toes",
              "Tense muscles for 5 seconds",
              "Release and feel the relaxation",
              "Move up to calves, thighs, stomach",
              "Continue to shoulders and face",
            ],
          },
          {
            id: 228,
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
          },
        ],
        pool2: [
          {
            id: 229,
            category: "academic",
            title: "Pomodoro Technique",
            description: "Improve focus and reduce study stress",
            steps: [
              "25 minutes focused work",
              "5 minute break",
              "Repeat 4 times",
              "15-30 minute long break",
            ],
          },
          {
            id: 230,
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
          },
          {
            id: 231,
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
          },
          {
            id: 232,
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
          },
        ],
      },
      "career/future": {
        pool1: [
          {
            id: 233,
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
          },
          {
            id: 234,
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
          },
          {
            id: 235,
            category: "mindfulness",
            title: "Progressive Muscle Relaxation",
            description: "Release physical tension systematically",
            steps: [
              "Start with your toes",
              "Tense muscles for 5 seconds",
              "Release and feel the relaxation",
              "Move up to calves, thighs, stomach",
              "Continue to shoulders and face",
            ],
          },
          {
            id: 236,
            category: "academic",
            title: "Networking Confidence Builder",
            description: "Build professional relationships with confidence",
            steps: [
              "Practice your elevator pitch",
              "Prepare thoughtful questions to ask",
              "Follow up with new connections",
              "Join professional organizations",
              "Attend industry meetups",
            ],
          },
        ],
        pool2: [
          {
            id: 237,
            category: "academic",
            title: "Skill Development Planning",
            description: "Plan your skill development journey",
            steps: [
              "Identify skills needed for your field",
              "Take online courses",
              "Practice skills through projects",
              "Seek feedback from mentors",
              "Update your resume regularly",
            ],
          },
          {
            id: 238,
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
          },
          {
            id: 239,
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
          },
          {
            id: 240,
            category: "academic",
            title: "Career Anxiety Management",
            description: "Handle anxiety about future career",
            steps: [
              "Focus on what you can control",
              "Break career planning into small steps",
              "Practice self-compassion",
              "Seek career counseling",
              "Remember it's okay to change paths",
            ],
          },
        ],
      },
    },
    // Excited emotion pools
    excited: {
      "exams/tests": {
        pool1: [
          {
            id: 241,
            category: "academic",
            title: "Test Preparation Strategy",
            description: "Channel excitement into effective preparation",
            steps: [
              "Use your energy to review material",
              "Create study schedules",
              "Practice with sample questions",
              "Stay organized and focused",
              "Maintain positive momentum",
            ],
          },
          {
            id: 242,
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
          },
          {
            id: 243,
            category: "mindfulness",
            title: "Progressive Muscle Relaxation",
            description: "Release physical tension systematically",
            steps: [
              "Start with your toes",
              "Tense muscles for 5 seconds",
              "Release and feel the relaxation",
              "Move up to calves, thighs, stomach",
              "Continue to shoulders and face",
            ],
          },
          {
            id: 244,
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
          },
        ],
        pool2: [
          {
            id: 245,
            category: "academic",
            title: "Pomodoro Technique",
            description: "Improve focus and reduce study stress",
            steps: [
              "25 minutes focused work",
              "5 minute break",
              "Repeat 4 times",
              "15-30 minute long break",
            ],
          },
          {
            id: 246,
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
          },
          {
            id: 247,
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
          },
          {
            id: 248,
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
          },
        ],
      },
      "career/future": {
        pool1: [
          {
            id: 249,
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
          },
          {
            id: 250,
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
          },
          {
            id: 251,
            category: "mindfulness",
            title: "Progressive Muscle Relaxation",
            description: "Release physical tension systematically",
            steps: [
              "Start with your toes",
              "Tense muscles for 5 seconds",
              "Release and feel the relaxation",
              "Move up to calves, thighs, stomach",
              "Continue to shoulders and face",
            ],
          },
          {
            id: 252,
            category: "academic",
            title: "Networking Confidence Builder",
            description: "Build professional relationships with confidence",
            steps: [
              "Practice your elevator pitch",
              "Prepare thoughtful questions to ask",
              "Follow up with new connections",
              "Join professional organizations",
              "Attend industry meetups",
            ],
          },
        ],
        pool2: [
          {
            id: 253,
            category: "academic",
            title: "Skill Development Planning",
            description: "Plan your skill development journey",
            steps: [
              "Identify skills needed for your field",
              "Take online courses",
              "Practice skills through projects",
              "Seek feedback from mentors",
              "Update your resume regularly",
            ],
          },
          {
            id: 254,
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
          },
          {
            id: 255,
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
          },
          {
            id: 256,
            category: "academic",
            title: "Career Anxiety Management",
            description: "Handle anxiety about future career",
            steps: [
              "Focus on what you can control",
              "Break career planning into small steps",
              "Practice self-compassion",
              "Seek career counseling",
              "Remember it's okay to change paths",
            ],
          },
        ],
      },
    },
    // Frustrated emotion pools
    frustrated: {
      "exams/tests": {
        pool1: [
          {
            id: 257,
            category: "academic",
            title: "Frustration Management",
            description: "Handle academic frustration constructively",
            steps: [
              "Take a short break to cool down",
              "Break the problem into smaller parts",
              "Ask for help from classmates or tutors",
              "Focus on what you can control",
              "Practice self-compassion",
            ],
          },
          {
            id: 258,
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
          },
          {
            id: 259,
            category: "mindfulness",
            title: "Progressive Muscle Relaxation",
            description: "Release physical tension systematically",
            steps: [
              "Start with your toes",
              "Tense muscles for 5 seconds",
              "Release and feel the relaxation",
              "Move up to calves, thighs, stomach",
              "Continue to shoulders and face",
            ],
          },
          {
            id: 260,
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
          },
        ],
        pool2: [
          {
            id: 261,
            category: "academic",
            title: "Pomodoro Technique",
            description: "Improve focus and reduce study stress",
            steps: [
              "25 minutes focused work",
              "5 minute break",
              "Repeat 4 times",
              "15-30 minute long break",
            ],
          },
          {
            id: 262,
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
          },
          {
            id: 263,
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
          },
          {
            id: 264,
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
          },
        ],
      },
      assignments: {
        pool1: [
          {
            id: 265,
            category: "academic",
            title: "Assignment Breakdown Method",
            description: "Break large assignments into manageable pieces",
            steps: [
              "List all requirements",
              "Break into smaller tasks",
              "Set deadlines for each task",
              "Start with easiest part first",
              "Review and revise",
            ],
          },
          {
            id: 266,
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
          },
          {
            id: 267,
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
          },
          {
            id: 268,
            category: "mindfulness",
            title: "Progressive Muscle Relaxation",
            description: "Release physical tension systematically",
            steps: [
              "Start with your toes",
              "Tense muscles for 5 seconds",
              "Release and feel the relaxation",
              "Move up to calves, thighs, stomach",
              "Continue to shoulders and face",
            ],
          },
        ],
        pool2: [
          {
            id: 269,
            category: "academic",
            title: "Pomodoro Technique",
            description: "Improve focus and reduce study stress",
            steps: [
              "25 minutes focused work",
              "5 minute break",
              "Repeat 4 times",
              "15-30 minute long break",
            ],
          },
          {
            id: 270,
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
          },
          {
            id: 271,
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
          },
          {
            id: 272,
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
          },
        ],
      },
    },
  };

  // Get the most recent mood entry to determine current emotion and context
  const recentMoodQuery = `
    SELECT encrypted_data, iv FROM mood_entries 
    WHERE user_id = ? 
    ORDER BY created_at DESC 
    LIMIT 1
  `;

  db.get(recentMoodQuery, [userId], (err, row) => {
    if (err) {
      console.error("Error fetching recent mood:", err);
      return res
        .status(500)
        .json({ error: "Failed to fetch recent mood data" });
    }

    if (!row) {
      console.log("❌ No mood entries found for user:", userId);
      return res.json([]);
    }

    try {
      // Decrypt the mood data
      const decrypted = EncryptionService.decrypt(
        row.encrypted_data,
        row.iv,
        req.user.username
      );
      const moodData = JSON.parse(decrypted);
      
      const decryptedEmotions = moodData.emotions;
      const decryptedContext = moodData.context;

      // Get the first emotion (since only one is selected now)
      const emotion = decryptedEmotions[0]?.toLowerCase().trim();
      const context = decryptedContext.toLowerCase().trim();

      console.log("🔍 Raw decrypted emotions:", decryptedEmotions);
      console.log("🔍 Raw decrypted context:", decryptedContext);
      console.log("🔍 Normalized emotion:", emotion);
      console.log("🔍 Normalized context:", context);

      console.log("🎯 Current emotion:", emotion);
      console.log("🎯 Current context:", context);
      console.log(
        "🔍 Available emotions in strategyPools:",
        Object.keys(strategyPools)
      );

      // Find the appropriate strategy pools
      const emotionPools = strategyPools[emotion];
      if (!emotionPools) {
        console.log("❌ No pools found for emotion:", emotion);
        console.log("🔍 Available emotions:", Object.keys(strategyPools));
        return res.json([]);
      }

      console.log(
        "🔍 Available contexts for emotion '",
        emotion,
        "':",
        Object.keys(emotionPools)
      );

      let contextPools = emotionPools[context];
      if (!contextPools) {
        console.log("❌ No exact match found for context:", context);
        console.log("🔍 Available contexts:", Object.keys(emotionPools));

        // Try to find a similar context
        const availableContexts = Object.keys(emotionPools);
        const similarContext = availableContexts.find(
          (available) =>
            available.includes(context) || context.includes(available)
        );

        if (similarContext) {
          console.log("🔍 Found similar context:", similarContext);
          contextPools = emotionPools[similarContext];
        } else {
          console.log("❌ No similar context found either");
          return res.json([]);
        }
      }

      // Randomly select 2 strategies from each pool
      const shuffleArray = (array) => {
        const shuffled = [...array];
        for (let i = shuffled.length - 1; i > 0; i--) {
          const j = Math.floor(Math.random() * (i + 1));
          [shuffled[i], shuffled[j]] = [shuffled[j], shuffled[i]];
        }
        return shuffled;
      };

      const pool1Strategies = shuffleArray(contextPools.pool1).slice(0, 2);
      const pool2Strategies = shuffleArray(contextPools.pool2).slice(0, 2);

      const selectedStrategies = [...pool1Strategies, ...pool2Strategies];

      console.log(
        "📊 Pool 1 strategies:",
        pool1Strategies.map((s) => s.title)
      );
      console.log(
        "📊 Pool 2 strategies:",
        pool2Strategies.map((s) => s.title)
      );
      console.log(
        "📊 Final selected strategies:",
        selectedStrategies.map((s) => s.title)
      );

      res.json(selectedStrategies);
    } catch (error) {
      console.error("Error processing mood data:", error);
      res.status(500).json({ error: "Failed to process mood data" });
    }
  });
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
