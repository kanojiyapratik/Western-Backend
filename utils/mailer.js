const path = require('path');
// Ensure .env from Backend folder is loaded when this module is required directly
try {
  const dotenv = require('dotenv');
  const envPath = path.resolve(__dirname, '..', '.env');
  const result = dotenv.config({ path: envPath });
  if (result.error) {
    // fallback to default config (may already be loaded by server.js)
    // console.log('No .env at', envPath, 'falling back to process.env');
  } else {
    console.log('ℹ️ loaded env from', envPath);
  }
} catch (e) {
  // ignore if dotenv not available
}

const sgMail = require('@sendgrid/mail');
const nodemailer = require('nodemailer');

// Email service configuration
const EMAIL_CONFIG = {
  sendgrid: {
    maxRetries: 3,
    retryDelay: 2000, // 2 seconds
    timeout: 10000,   // 10 seconds
  },
  nodemailer: {
    maxRetries: 2,
    retryDelay: 1000, // 1 second
    timeout: 5000,    // 5 seconds
  }
};

// Email delivery tracking
const emailStats = {
  sent: 0,
  failed: 0,
  retries: 0,
  lastSent: null,
  errors: []
};

// Initialize SendGrid if API key is available
if (process.env.SENDGRID_API_KEY) {
  sgMail.setApiKey(process.env.SENDGRID_API_KEY);
  console.log('📧 SendGrid initialized successfully');
} else {
  console.log('⚠️  SendGrid API key not found, falling back to nodemailer');
}

// Validate email configuration
function validateEmailConfig() {
  const errors = [];
  
  if (!process.env.EMAIL_FROM) {
    errors.push('EMAIL_FROM environment variable is not set');
  }
  
  if (!process.env.SENDGRID_API_KEY && !process.env.SMTP_HOST) {
    errors.push('Either SENDGRID_API_KEY or SMTP configuration is required');
  }
  
  if (errors.length > 0) {
    throw new Error(`Email configuration errors: ${errors.join(', ')}`);
  }
}

// Enhanced nodemailer transporter with better configuration
function createEnhancedTransporter() {
  const smtpConfig = {
    host: process.env.SMTP_HOST || 'smtp.ethereal.email',
    port: parseInt(process.env.SMTP_PORT) || 587,
    secure: process.env.SMTP_SECURE === 'true',
    auth: {
      user: process.env.SMTP_USER || 'your-ethereal-user',
      pass: process.env.SMTP_PASS || 'your-ethereal-pass'
    },
    pool: true, // Use pooled connections
    maxConnections: 5,
    maxMessages: 100,
    rateDelta: 1000,
    rateLimit: 5
  };

  return nodemailer.createTransporter(smtpConfig);
}

// Retry logic for email sending
async function sendWithRetry(sendFunction, config, context) {
  let lastError;
  
  for (let attempt = 1; attempt <= config.maxRetries; attempt++) {
    try {
      const result = await Promise.race([
        sendFunction(),
        new Promise((_, reject) => 
          setTimeout(() => reject(new Error('Email sending timeout')), config.timeout)
        )
      ]);
      
      if (attempt > 1) {
        emailStats.retries++;
      }
      
      return result;
    } catch (error) {
      lastError = error;
      
      if (attempt < config.maxRetries && isRetryableEmailError(error)) {
        const delay = config.retryDelay * attempt;
        console.warn(`📧 Email attempt ${attempt} failed, retrying in ${delay}ms:`, error.message);
        await sleep(delay);
        continue;
      }
      
      break;
    }
  }
  
  throw lastError;
}

// Check if email error is retryable
function isRetryableEmailError(error) {
  const retryablePatterns = [
    'timeout',
    'network',
    'ECONNRESET',
    'ENOTFOUND',
    'ETIMEDOUT',
    'temporary',
    'rate limit',
    'throttling'
  ];
  
  const errorMessage = error.message.toLowerCase();
  const statusCode = error.status || error.statusCode;
  
  // Retry based on status codes (5xx server errors)
  if (statusCode && statusCode >= 500 && statusCode < 600) {
    return true;
  }
  
  // Retry based on error message patterns
  return retryablePatterns.some(pattern => errorMessage.includes(pattern));
}

// Sleep utility
function sleep(ms) {
  return new Promise(resolve => setTimeout(resolve, ms));
}

// Enhanced SendGrid email sending
async function sendSendGridEmail(msg) {
  const sendFunction = async () => {
    const result = await sgMail.send({
      ...msg,
      mailSettings: {
        sandboxMode: { enable: process.env.NODE_ENV === 'development' }
      }
    });
    return { success: true, method: 'sendgrid', result };
  };
  
  return await sendWithRetry(sendFunction, EMAIL_CONFIG.sendgrid, 'SendGrid');
}

// Enhanced nodemailer email sending
async function sendNodemailerEmail(mailOptions) {
  const transporter = createEnhancedTransporter();
  
  const sendFunction = async () => {
    const result = await transporter.sendMail(mailOptions);
    return { success: true, method: 'nodemailer', result };
  };
  
  return await sendWithRetry(sendFunction, EMAIL_CONFIG.nodemailer, 'Nodemailer');
}

const getMailerStatus = () => {
  return {
    sendgrid: !!process.env.SENDGRID_API_KEY,
    nodemailer: true,
    config: {
      from: process.env.EMAIL_FROM,
      smtpHost: process.env.SMTP_HOST || 'smtp.ethereal.email',
      smtpPort: process.env.SMTP_PORT || 587
    },
    stats: emailStats
  };
};

const sendEmbedEmail = async (to, subject, html, embedUrl) => {
  const from = process.env.EMAIL_FROM || 'noreply@example.com';
  const replyTo = process.env.REPLY_TO;

  console.log(`📧 Attempting to send email to: ${to}`);
  console.log(`📧 From: ${from}`);
  console.log(`📧 Subject: ${subject}`);

  try {
    // Validate configuration
    validateEmailConfig();

    // Validate email addresses
    if (!isValidEmail(to)) {
      throw new Error(`Invalid recipient email address: ${to}`);
    }

    if (!isValidEmail(from)) {
      throw new Error(`Invalid sender email address: ${from}`);
    }

    const mailData = {
      to,
      from,
      subject,
      html,
      replyTo: replyTo || from,
      headers: {
        'X-Entity-Ref-ID': `email-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`,
        'X-Mailer': '3D-Configurator-Mailer/1.0'
      }
    };

    let result;
    let method = 'unknown';

    if (process.env.SENDGRID_API_KEY) {
      // Use SendGrid with enhanced error handling
      console.log('📧 Sending via SendGrid...');
      result = await sendSendGridEmail(mailData);
      method = 'sendgrid';
    } else {
      // Fallback to nodemailer with enhanced error handling
      console.log('📧 Sending via nodemailer...');
      result = await sendNodemailerEmail(mailData);
      method = 'nodemailer';
    }

    // Update stats
    emailStats.sent++;
    emailStats.lastSent = new Date().toISOString();

    console.log(`✅ ${method} email sent successfully`);
    return {
      ...result,
      to,
      from,
      subject,
      method,
      timestamp: new Date().toISOString()
    };

  } catch (error) {
    console.error('❌ Email sending failed:', error);
    
    // Update error stats
    emailStats.failed++;
    emailStats.errors.push({
      timestamp: new Date().toISOString(),
      to,
      subject,
      error: error.message,
      code: error.code,
      status: error.status || error.statusCode
    });

    // Enhanced error categorization
    let errorCode = 'EMAIL_SEND_ERROR';
    let errorMessage = error.message;
    let isRetryable = false;

    if (error.message.includes('Invalid email')) {
      errorCode = 'INVALID_EMAIL';
      errorMessage = 'Invalid email address format';
    } else if (error.message.includes('timeout')) {
      errorCode = 'EMAIL_TIMEOUT';
      errorMessage = 'Email sending timed out';
      isRetryable = true;
    } else if (error.status === 401 || error.status === 403) {
      errorCode = 'EMAIL_AUTH_ERROR';
      errorMessage = 'Email service authentication failed';
    } else if (error.status === 429) {
      errorCode = 'EMAIL_RATE_LIMIT';
      errorMessage = 'Email service rate limit exceeded';
      isRetryable = true;
    } else if (error.status >= 500) {
      errorCode = 'EMAIL_SERVER_ERROR';
      errorMessage = 'Email service server error';
      isRetryable = true;
    }

    return {
      success: false,
      error: errorMessage,
      code: errorCode,
      retryable: isRetryable,
      details: {
        status: error.status || error.statusCode,
        response: error.response?.body,
        timestamp: new Date().toISOString()
      }
    };
  }
};

// Email validation utility
function isValidEmail(email) {
  const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  return emailRegex.test(email) && email.length <= 254;
}

// Batch email sending
async function sendBatchEmails(emails) {
  const results = [];
  const batchSize = 5; // Process in batches to avoid overwhelming the server

  for (let i = 0; i < emails.length; i += batchSize) {
    const batch = emails.slice(i, i + batchSize);
    const batchPromises = batch.map(async (email) => {
      try {
        const result = await sendEmbedEmail(email.to, email.subject, email.html, email.embedUrl);
        return { ...email, ...result };
      } catch (error) {
        return { ...email, success: false, error: error.message };
      }
    });

    const batchResults = await Promise.all(batchPromises);
    results.push(...batchResults);

    // Small delay between batches
    if (i + batchSize < emails.length) {
      await sleep(1000);
    }
  }

  return results;
}

// Get email delivery statistics
function getEmailStats() {
  return {
    ...emailStats,
    successRate: emailStats.sent + emailStats.failed > 0 
      ? (emailStats.sent / (emailStats.sent + emailStats.failed) * 100).toFixed(2) + '%'
      : '0%'
  };
}

// Clear email statistics
function clearEmailStats() {
  emailStats.sent = 0;
  emailStats.failed = 0;
  emailStats.retries = 0;
  emailStats.lastSent = null;
  emailStats.errors = [];
}

module.exports = {
  sendEmbedEmail,
  sendBatchEmails,
  getMailerStatus,
  getEmailStats,
  clearEmailStats,
  validateEmailConfig,
};