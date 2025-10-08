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
    console.log('\u2139\ufe0f loaded env from', envPath);
  }
} catch (e) {
  // ignore if dotenv not available
}

const sgMail = require('@sendgrid/mail');
const nodemailer = require('nodemailer');

// Initialize SendGrid if API key is available
if (process.env.SENDGRID_API_KEY) {
  sgMail.setApiKey(process.env.SENDGRID_API_KEY);
  console.log('📧 SendGrid initialized successfully');
} else {
  console.log('⚠️  SendGrid API key not found, falling back to nodemailer');
}

// Create nodemailer transporter for fallback
const createTransporter = () => {
  return nodemailer.createTransporter({
    host: 'smtp.ethereal.email',
    port: 587,
    auth: {
      user: 'your-ethereal-user',
      pass: 'your-ethereal-pass'
    }
  });
};

const getMailerStatus = () => {
  return {
    sendgrid: !!process.env.SENDGRID_API_KEY,
    nodemailer: true
  };
};

const sendEmbedEmail = async (to, subject, html, embedUrl) => {
  const from = process.env.EMAIL_FROM || 'noreply@example.com';
  const replyTo = process.env.REPLY_TO;

  console.log(`📧 Attempting to send email to: ${to}`);
  console.log(`📧 From: ${from}`);
  console.log(`📧 Subject: ${subject}`);

  try {
    if (process.env.SENDGRID_API_KEY) {
      // Use SendGrid
      const msg = {
        to,
        from,
        subject,
        html,
        replyTo: replyTo || from
      };

      console.log('📧 Sending via SendGrid...');
      const result = await sgMail.send(msg);
      console.log('✅ SendGrid email sent successfully:', result[0]?.statusCode);
      return { success: true, method: 'sendgrid', result };
    } else {
      // Fallback to nodemailer
      const transporter = createTransporter();
      const mailOptions = {
        from,
        to,
        subject,
        html,
        replyTo: replyTo || from
      };

      console.log('📧 Sending via nodemailer...');
      const result = await transporter.sendMail(mailOptions);
      console.log('✅ Nodemailer email sent successfully:', result.messageId);
      return { success: true, method: 'nodemailer', result };
    }
  } catch (error) {
    console.error('❌ Email sending failed:', error.message);
    if (error.response) {
      console.error('❌ SendGrid response:', error.response.body);
    }
    return {
      success: false,
      error: error.message,
      response: error.response?.body
    };
  }
};

module.exports = {
  sendEmbedEmail,
  getMailerStatus
};