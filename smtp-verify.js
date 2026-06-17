const nodemailer = require('nodemailer');
require('dotenv').config();

const mask = (s = '') => s ? s.replace(/.(?=.{4})/g, '*') : '';

(async function main() {
    console.log('Loaded .env values:');
    console.log('  MAIL_HOST:', process.env.MAIL_HOST || '(none)');
    console.log('  MAIL_PORT:', process.env.MAIL_PORT || '(none)');
    console.log('  MAIL_SECURE:', process.env.MAIL_SECURE || '(none)');
    console.log('  MAIL_USER:', mask(process.env.MAIL_USER || '(none)'));

    const mailPort = Number(process.env.MAIL_PORT || 465);
    const secure = (typeof process.env.MAIL_SECURE !== 'undefined')
        ? process.env.MAIL_SECURE === 'true'
        : mailPort === 465;

    const transporter = nodemailer.createTransport({
        host: process.env.MAIL_HOST,
        port: mailPort,
        secure,
        auth: {
            user: process.env.MAIL_USER,
            pass: process.env.MAIL_PASS
        },
        connectionTimeout: 15000,
        greetingTimeout: 15000,
        socketTimeout: 30000
    });

    console.log('\nAttempting SMTP verify (this will attempt to authenticate)...');
    try {
        await transporter.verify();
        console.log('SMTP verification successful — authentication succeeded.');
        process.exit(0);
    } catch (err) {
        console.error('SMTP verification failed:', err && err.message ? err.message : err);
        if (err && err.response) console.error('SMTP server response:', err.response);
        if (err && err.code) console.error('Error code:', err.code);
        process.exit(2);
    }
})();
