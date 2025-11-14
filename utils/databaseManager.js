/**
 * Database Connection Manager with Retry Logic
 * Handles MongoDB connection with automatic retry and error recovery
 */

const mongoose = require('mongoose');

const DB_CONFIG = {
  maxRetries: 5,
  retryDelay: 2000, // 2 seconds
  connectionTimeout: 10000, // 10 seconds
  socketTimeout: 45000, // 45 seconds
};

class DatabaseManager {
  constructor() {
    this.connection = null;
    this.isConnecting = false;
    this.retryCount = 0;
  }

  /**
   * Connect to MongoDB with retry logic
   * @param {string} uri - MongoDB connection URI
   * @returns {Promise<Connection>} - Mongoose connection
   */
  async connectWithRetry(uri) {
    if (this.connection && this.connection.readyState === 1) {
      console.log('✅ Already connected to MongoDB');
      return this.connection;
    }

    if (this.isConnecting) {
      console.log('⏳ Connection already in progress, waiting...');
      return new Promise((resolve, reject) => {
        const checkConnection = () => {
          if (this.connection && this.connection.readyState === 1) {
            resolve(this.connection);
          } else if (this.retryCount >= DB_CONFIG.maxRetries) {
            reject(new Error('Connection timeout'));
          } else {
            setTimeout(checkConnection, 100);
          }
        };
        checkConnection();
      });
    }

    this.isConnecting = true;
    this.retryCount = 0;

    try {
      await this._attemptConnection(uri);
      return this.connection;
    } catch (error) {
      this.isConnecting = false;
      throw error;
    }
  }

  /**
   * Attempt connection with retry logic
   * @param {string} uri - MongoDB connection URI
   */
  async _attemptConnection(uri) {
    while (this.retryCount <= DB_CONFIG.maxRetries) {
      try {
        console.log(`🔄 Attempting MongoDB connection (${this.retryCount + 1}/${DB_CONFIG.maxRetries + 1})`);
        
        this.connection = await mongoose.connect(uri, {
          serverSelectionTimeoutMS: DB_CONFIG.connectionTimeout,
          socketTimeoutMS: DB_CONFIG.socketTimeout,
          maxPoolSize: 10,
          minPoolSize: 2,
          maxIdleTimeMS: 30000,
          bufferCommands: false,
          retryWrites: true,
          retryReads: true,
        });

        console.log('✅ MongoDB Connected successfully');
        this.isConnecting = false;
        this.retryCount = 0;

        // Set up connection event handlers
        this._setupConnectionHandlers();

        return this.connection;

      } catch (error) {
        this.retryCount++;
        console.error(`❌ MongoDB connection attempt ${this.retryCount} failed:`, error.message);

        if (this.retryCount > DB_CONFIG.maxRetries) {
          console.error('❌ Max retry attempts reached. MongoDB connection failed.');
          this.isConnecting = false;
          throw new Error(`Failed to connect to MongoDB after ${DB_CONFIG.maxRetries + 1} attempts: ${error.message}`);
        }

        // Wait before retry with exponential backoff
        const delay = this._calculateRetryDelay();
        console.log(`⏳ Retrying in ${delay}ms...`);
        await this._sleep(delay);
      }
    }
  }

  /**
   * Calculate retry delay with exponential backoff
   * @returns {number} - Delay in milliseconds
   */
  _calculateRetryDelay() {
    const baseDelay = DB_CONFIG.retryDelay;
    const exponentialDelay = baseDelay * Math.pow(2, this.retryCount - 1);
    const jitter = Math.random() * 1000; // Add random jitter
    return Math.min(exponentialDelay + jitter, 30000); // Cap at 30 seconds
  }

  /**
   * Sleep utility function
   * @param {number} ms - Milliseconds to sleep
   */
  _sleep(ms) {
    return new Promise(resolve => setTimeout(resolve, ms));
  }

  /**
   * Set up connection event handlers
   */
  _setupConnectionHandlers() {
    if (!this.connection) return;

    // Connection opened
    this.connection.on('connected', () => {
      console.log('✅ MongoDB connection established');
      this.retryCount = 0;
    });

    // Connection disconnected
    this.connection.on('disconnected', () => {
      console.warn('⚠️ MongoDB disconnected');
      this.isConnecting = false;
      
      // Attempt to reconnect
      this._attemptReconnect();
    });

    // Connection error
    this.connection.on('error', (error) => {
      console.error('❌ MongoDB connection error:', error);
      this.isConnecting = false;
    });

    // Connection reconnected
    this.connection.on('reconnected', () => {
      console.log('✅ MongoDB reconnected successfully');
      this.retryCount = 0;
    });

    // Connection ready
    this.connection.on('open', () => {
      console.log('✅ MongoDB connection ready');
    });
  }

  /**
   * Attempt to reconnect after disconnection
   */
  async _attemptReconnect() {
    if (this.isConnecting) return;

    this.isConnecting = true;
    console.log('🔄 Attempting to reconnect to MongoDB...');

    try {
      await mongoose.connect(process.env.MONGO_URI || "mongodb://localhost:27017/3dconfigurator", {
        serverSelectionTimeoutMS: DB_CONFIG.connectionTimeout,
        socketTimeoutMS: DB_CONFIG.socketTimeout,
      });
      console.log('✅ MongoDB reconnected successfully');
    } catch (error) {
      console.error('❌ MongoDB reconnection failed:', error.message);
      this.isConnecting = false;
      
      // Schedule another reconnection attempt
      setTimeout(() => this._attemptReconnect(), 5000);
    }
  }

  /**
   * Gracefully close the connection
   */
  async disconnect() {
    if (this.connection) {
      await mongoose.disconnect();
      this.connection = null;
      console.log('✅ MongoDB disconnected gracefully');
    }
  }

  /**
   * Get connection status
   * @returns {Object} - Connection status information
   */
  getStatus() {
    const states = {
      0: 'disconnected',
      1: 'connected',
      2: 'connecting',
      3: 'disconnecting'
    };

    return {
      readyState: this.connection?.readyState || 0,
      state: states[this.connection?.readyState || 0],
      host: this.connection?.host,
      port: this.connection?.port,
      name: this.connection?.name,
      isConnected: this.connection?.readyState === 1,
      retryCount: this.retryCount,
      isConnecting: this.isConnecting
    };
  }

  /**
   * Check if the connection is healthy
   * @returns {Promise<boolean>} - True if connection is healthy
   */
  async isHealthy() {
    if (!this.connection || this.connection.readyState !== 1) {
      return false;
    }

    try {
      await this.connection.db.admin().ping();
      return true;
    } catch (error) {
      console.error('❌ MongoDB health check failed:', error.message);
      return false;
    }
  }
}

// Create and export a singleton instance
const dbManager = new DatabaseManager();

// Helper function to connect with retry
async function connectToDatabase(uri) {
  return await dbManager.connectWithRetry(uri);
}

// Helper function to disconnect
async function disconnectFromDatabase() {
  return await dbManager.disconnect();
}

// Helper function to get connection status
function getConnectionStatus() {
  return dbManager.getStatus();
}

// Helper function to check connection health
async function checkDatabaseHealth() {
  return await dbManager.isHealthy();
}

module.exports = {
  connectToDatabase,
  disconnectFromDatabase,
  getConnectionStatus,
  checkDatabaseHealth,
  DatabaseManager,
  dbManager,
};