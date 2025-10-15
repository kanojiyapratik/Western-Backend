const mongoose = require('mongoose');
const { initPostgreSQL, getDatabaseConfig } = require('./config/database');

// MongoDB Models
const MongoUser = require('./models/User');
const MongoModel = require('./models/Model');

// PostgreSQL Models
const defineUser = require('./models/postgresql/User');
const defineModel = require('./models/postgresql/Model');

class DatabaseAdapter {
  constructor() {
    this.dbType = null;
    this.sequelize = null;
    this.models = {};
  }

  async initialize() {
    const config = getDatabaseConfig();
    this.dbType = config.type;

    if (config.type === 'postgresql') {
      console.log('🐘 Initializing PostgreSQL connection...');
      this.sequelize = initPostgreSQL();
      
      // Define models
      this.models.User = defineUser(this.sequelize);
      this.models.Model = defineModel(this.sequelize);
      
      // Sync database
      await this.sequelize.sync({ alter: true });
      console.log('✅ PostgreSQL Connected and synced');
      
    } else {
      console.log('🍃 Initializing MongoDB connection...');
      await mongoose.connect(config.url);
      this.models.User = MongoUser;
      this.models.Model = MongoModel;
      console.log('✅ MongoDB Connected');
    }
  }

  // Unified API methods
  async findUser(query) {
    if (this.dbType === 'postgresql') {
      return await this.models.User.findOne({ where: query });
    } else {
      return await this.models.User.findOne(query);
    }
  }

  async createUser(userData) {
    if (this.dbType === 'postgresql') {
      return await this.models.User.create(userData);
    } else {
      return await this.models.User.create(userData);
    }
  }

  async findAllUsers() {
    if (this.dbType === 'postgresql') {
      return await this.models.User.findAll();
    } else {
      return await this.models.User.find({});
    }
  }

  async findModel(query) {
    if (this.dbType === 'postgresql') {
      return await this.models.Model.findOne({ where: query });
    } else {
      return await this.models.Model.findOne(query);
    }
  }

  async findAllModels(query = {}) {
    if (this.dbType === 'postgresql') {
      return await this.models.Model.findAll({ where: query });
    } else {
      return await this.models.Model.find(query);
    }
  }

  async createModel(modelData) {
    if (this.dbType === 'postgresql') {
      return await this.models.Model.create(modelData);
    } else {
      return await this.models.Model.create(modelData);
    }
  }

  async updateModel(id, updateData) {
    if (this.dbType === 'postgresql') {
      await this.models.Model.update(updateData, { where: { id } });
      return await this.models.Model.findByPk(id);
    } else {
      return await this.models.Model.findByIdAndUpdate(id, updateData, { new: true });
    }
  }

  async deleteModel(id) {
    if (this.dbType === 'postgresql') {
      return await this.models.Model.destroy({ where: { id } });
    } else {
      return await this.models.Model.findByIdAndDelete(id);
    }
  }
}

module.exports = new DatabaseAdapter();