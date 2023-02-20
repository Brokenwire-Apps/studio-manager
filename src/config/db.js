module.exports = {
    HOST: "localhost",
    USER: process.env.DB_UN,
    PASSWORD: process.env.DB_PW,
    DB: process.env.DB_NAME,
    dialect: "postgres",
    pool: {
        max: 5,
        min: 0,
        acquire: 30000,
        idle: 10000
    }
};