const path = require('path');
const fs = require('fs');
const crypto = require('crypto');
require('dotenv').config({ quiet: true });
const express = require('express');
const multer = require('multer');
const nodemailer = require('nodemailer');
const app = express();
const PORT = process.env.PORT || 3000;
const FOOTER_LOGO_PATH = path.join(__dirname, 'public', 'assets', 'Remaxlogo.png');
const FOOTER_LOGO_CID = 'remax-footer-logo@global-contact-app';
const ALLOWED_REPLY_TO_ADDRESSES = new Set([
  'application@remaxglobalhomes.com',
  'leasing@remaxglobalhomes.com'
]);

const upload = multer({
  storage: multer.diskStorage({
    destination: path.join(__dirname, 'uploads'),
    filename: (req, file, cb) => {
      const timestamp = Date.now();
      cb(null, `${timestamp}-${file.originalname}`);
    }
  })
});

app.use(express.static(path.join(__dirname, 'public')));
app.use('/generated-emails', express.static(path.join(__dirname, 'generated-emails')));
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

function sanitizeHtml(html = '') {
  return html
    .replace(/<script[\s\S]*?>[\s\S]*?<\/script>/gi, '')
    .replace(/on\w+\s*=\s*"[^"]*"/gi, '')
    .replace(/javascript:/gi, '#');
}

function tightenEmailBodyHtml(html = '') {
  const compactParagraphStyle = 'margin:0 0 6px 0;line-height:20px;';

  return sanitizeHtml(html)
    .replace(/<p\b[^>]*>\s*(?:<br\s*\/?>)?\s*<\/p>/gi, '<div style="height:4px;line-height:4px;font-size:4px;">&nbsp;</div>')
    .replace(/<p\b([^>]*)>/gi, (match, attrs = '') => {
      if (/style\s*=/i.test(attrs)) {
        return `<p${attrs.replace(/style\s*=\s*(["'])(.*?)\1/i, (styleMatch, quote, value) => {
          const existingStyle = value.trim().replace(/;?\s*$/, '');
          return `style=${quote}${existingStyle};${compactParagraphStyle}${quote}`;
        })}>`;
      }

      return `<p${attrs} style="${compactParagraphStyle}">`;
    });
}

function escapeHtml(text = '') {
  return String(text)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

function stripHtml(html = '') {
  return String(html)
    .replace(/<br\s*\/?>/gi, '\n')
    .replace(/<\/p>/gi, '\n')
    .replace(/<[^>]*>/g, '')
    .replace(/&nbsp;/g, ' ')
    .trim();
}

function normalizeEmail(email = '') {
  return String(email).trim().toLowerCase();
}

function isValidEmail(email = '') {
  return /^[^\s@,]+@[^\s@,]+\.[^\s@,]+$/.test(String(email).trim());
}

function getSenderAddress() {
  return normalizeEmail(process.env.MAIL_FROM || process.env.MAIL_USER || '');
}

function getEmailDomain(email = '') {
  const parts = normalizeEmail(email).split('@');
  return parts.length === 2 ? parts[1] : '';
}

function getMessageIdDomain(senderAddress) {
  return (process.env.MAIL_MESSAGE_ID_DOMAIN || getEmailDomain(senderAddress)).toLowerCase();
}

function createMessageId(senderAddress) {
  const domain = getMessageIdDomain(senderAddress);
  const uniqueId = `${Date.now()}.${crypto.randomBytes(8).toString('hex')}`;
  return `<${uniqueId}@${domain}>`;
}

function getDkimConfig(senderAddress) {
  const domainName = (process.env.MAIL_DKIM_DOMAIN || getEmailDomain(senderAddress)).toLowerCase();
  const keySelector = process.env.MAIL_DKIM_SELECTOR;
  const privateKey = process.env.MAIL_DKIM_PRIVATE_KEY
    ? process.env.MAIL_DKIM_PRIVATE_KEY.replace(/\\n/g, '\n')
    : (process.env.MAIL_DKIM_PRIVATE_KEY_PATH
      ? fs.readFileSync(path.resolve(__dirname, process.env.MAIL_DKIM_PRIVATE_KEY_PATH), 'utf8')
      : '');

  if (!domainName || !keySelector || !privateKey) {
    return null;
  }

  return {
    domainName,
    keySelector,
    privateKey
  };
}

async function queryDnsOverHttps(name, type) {
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), 15000);

  try {
    const response = await fetch(`https://cloudflare-dns.com/dns-query?name=${encodeURIComponent(name)}&type=${type}`, {
      headers: { accept: 'application/dns-json' },
      signal: controller.signal
    });

    if (!response.ok) {
      throw new Error(`DNS query failed with HTTP ${response.status}`);
    }

    return response.json();
  } finally {
    clearTimeout(timeout);
  }
}

function getDnsAnswers(dnsResponse) {
  return Array.isArray(dnsResponse.Answer) ? dnsResponse.Answer : [];
}

function hasTxtRecord(records, matcher) {
  return records.some((record) => matcher(String(record.data || '').replace(/^"|"$/g, '')));
}

async function getSenderDomainHealth(senderAddress) {
  const domain = getEmailDomain(senderAddress);
  const result = {
    domain,
    ok: false,
    issues: [],
    records: {
      ns: [],
      mx: [],
      txt: [],
      dmarc: []
    }
  };

  if (!domain) {
    result.issues.push('Sender email domain could not be parsed.');
    return result;
  }

  try {
    const [nsResponse, mxResponse, txtResponse, dmarcResponse] = await Promise.all([
      queryDnsOverHttps(domain, 'NS'),
      queryDnsOverHttps(domain, 'MX'),
      queryDnsOverHttps(domain, 'TXT'),
      queryDnsOverHttps(`_dmarc.${domain}`, 'TXT')
    ]);

    result.records.ns = getDnsAnswers(nsResponse).map((record) => record.data);
    result.records.mx = getDnsAnswers(mxResponse).map((record) => record.data);
    result.records.txt = getDnsAnswers(txtResponse).map((record) => record.data);
    result.records.dmarc = getDnsAnswers(dmarcResponse).map((record) => record.data);

    if (nsResponse.Status !== 0 || result.records.ns.length === 0) {
      result.issues.push(`The sender domain ${domain} has no publicly reachable authoritative DNS.`);
    }

    if (mxResponse.Status !== 0 || result.records.mx.length === 0) {
      result.issues.push(`The sender domain ${domain} has no public MX record.`);
    }

    if (txtResponse.Status !== 0 || !hasTxtRecord(getDnsAnswers(txtResponse), (value) => value.toLowerCase().startsWith('v=spf1'))) {
      result.issues.push(`The sender domain ${domain} has no public SPF TXT record.`);
    }

    if (dmarcResponse.Status !== 0 || !hasTxtRecord(getDnsAnswers(dmarcResponse), (value) => value.toLowerCase().startsWith('v=dmarc1'))) {
      result.issues.push(`The sender domain ${domain} has no public DMARC TXT record.`);
    }
  } catch (error) {
    result.issues.push(`Could not verify public DNS for ${domain}: ${error.message}`);
  }

  result.ok = result.issues.length === 0;
  return result;
}

function buildEmailHtml({ name, email, messageHtml }) {
  const safeName = escapeHtml(name);
  const safeMessage = tightenEmailBodyHtml(messageHtml || '');
  const footerLogoSrc = `cid:${FOOTER_LOGO_CID}`;
  return `
<!doctype html>
<html>
  <head>
    <meta name="viewport" content="width=device-width, initial-scale=1.0" />
    <style>
      @media screen and (max-width: 600px) {
        .email-container {
          width: 100% !important;
          max-width: 100% !important;
          border-radius: 0 !important;
        }

        .email-content-pad {
          padding-left: 18px !important;
          padding-right: 18px !important;
        }

        .email-footer-pad {
          padding: 28px 22px 28px 22px !important;
        }

        .footer-logo {
          width: 180px !important;
          max-width: 180px !important;
          height: auto !important;
        }

        .footer-address-cell {
          display: block !important;
          width: 100% !important;
          text-align: left !important;
        }

        .footer-address-cell + .footer-address-cell {
          padding-top: 2px !important;
        }

        .footer-badge-cell {
          padding-left: 22px !important;
          padding-right: 22px !important;
        }

        .footer-social-wrap {
          max-width: 280px !important;
          width: 100% !important;
          text-align: center !important;
        }

        .footer-social-link {
          margin: 0 7px 12px 7px !important;
        }

        .footer-legal-link {
          font-size: 12px !important;
          line-height: 17px !important;
          letter-spacing: 0.35px !important;
        }
      }

      .email-message p {
        margin: 0 0 8px 0;
      }

      .email-message p:last-child {
        margin-bottom: 0;
      }
    </style>
  </head>
  <body style="margin:0;padding:0;background-color:#f4f4f4;font-family:Arial,Helvetica,sans-serif;">
    <center style="width:100%;background-color:#f4f4f4;padding:16px 0;">
      <div class="email-container" style="width:100%;max-width:600px;margin:0 auto;background:#ffffff;border-radius:3px;overflow:hidden;">
        <table role="presentation" cellpadding="0" cellspacing="0" width="100%" style="border-collapse:collapse;background:#ffffff;width:100%;border-radius:3px;">
          <tr>
            <td style="padding:20px 10px;text-align:center;">
              <img src="https://userimg-assets.customeriomail.com/images/client-env-175803/1743774224665_New_RMX_Mark_R4_RGB_dark_01JR0GPG0SRCBV6ME1CTPMTR9R.png" width="174" alt="RE/MAX" style="border:0;display:block;outline:none;text-decoration:none;height:auto;width:100%;max-width:174px;font-size:13px;" />
            </td>
          </tr>
          <tr>
            <td class="email-content-pad" style="padding:0 24px 24px 24px;color:#404041;font-size:14px;line-height:22px;">
              <h1 style="margin:0 0 20px;font-size:24px;font-weight:500;color:#404041;">Dear ${safeName},</h1>
              <div class="email-message" style="margin-bottom:22px;color:#404041;font-size:14px;line-height:20px;text-align:justify;text-justify:inter-word;">${safeMessage}</div>
            </td>
          </tr>
        </table>
        <table role="presentation" cellpadding="0" cellspacing="0" width="100%" style="border-collapse:collapse;background:#253b70;color:#ffffff;width:100%;">
          <tr>
            <td class="email-footer-pad" align="left" style="padding:32px 30px 30px 30px;text-align:left;color:#ffffff;font-family:Arial,Helvetica,sans-serif;">
              <img class="footer-logo" src="${footerLogoSrc}" width="205" alt="RE/MAX" style="border:0;display:block;outline:none;text-decoration:none;height:auto;width:205px;max-width:205px;margin:0 0 22px 0;" />
              <table role="presentation" cellpadding="0" cellspacing="0" width="100%" style="border-collapse:collapse;width:100%;margin:0 auto;">
                <tr>
                  <td align="left" style="padding:0 0 18px 0;text-align:left;font-family:Arial,Helvetica,sans-serif;">
                    <div style="margin:0 0 2px 0;color:#ffffff;font-size:13px;line-height:17px;font-weight:700;letter-spacing:1.35px;">RE/MAX, LLC</div>
                    <table role="presentation" cellpadding="0" cellspacing="0" width="100%" style="border-collapse:collapse;width:100%;">
                      <tr>
                        <td class="footer-address-cell" align="left" width="50%" style="padding:0;text-align:left;color:#2673e8;font-size:13px;line-height:17px;font-weight:700;letter-spacing:1.25px;text-decoration:underline;font-family:Arial,Helvetica,sans-serif;">5075 S Syracuse St</td>
                        <td class="footer-address-cell" align="right" width="50%" style="padding:0;text-align:right;color:#2673e8;font-size:13px;line-height:17px;font-weight:700;letter-spacing:1.25px;text-decoration:underline;font-family:Arial,Helvetica,sans-serif;">Denver, CO 80237</td>
                      </tr>
                    </table>
                  </td>
                </tr>
                <tr>
                  <td align="center" style="padding:0 0 16px 0;text-align:center;">
                    <table role="presentation" cellpadding="0" cellspacing="0" align="center" style="border-collapse:collapse;margin:0 auto;">
                      <tr>
                        <td class="footer-badge-cell" align="center" style="padding:0 40px 0 0;text-align:center;">
                          <img src="https://static-images.remax.com/assets/web/nar-realtor-logo.png" width="54" height="54" alt="REALTOR" style="border:0;display:block;outline:none;text-decoration:none;width:54px;height:54px;margin:0 auto;" />
                        </td>
                        <td class="footer-badge-cell" align="center" style="padding:0 0 0 40px;text-align:center;">
                          <img src="https://static-images.remax.com/assets/web/equal-housing-logo.png" width="54" height="54" alt="EQUAL HOUSING OPPORTUNITY" style="border:0;display:block;outline:none;text-decoration:none;width:54px;height:54px;margin:0 auto;" />
                        </td>
                      </tr>
                    </table>
                  </td>
                </tr>
                <tr>
                  <td align="left" style="padding:0 0 25px 0;text-align:left;color:#ffffff;font-size:13px;line-height:18px;font-weight:400;letter-spacing:0.85px;font-family:Arial,Helvetica,sans-serif;">
                    Each office independently owned and operated.<br><br>
                    RE/MAX, LLC is an Equal Opportunity Employer and supports the Fair Housing Act and equal opportunity housing.<br><br>
                    &copy; 2025 RE/MAX, LLC. All Rights Reserved.
                  </td>
                </tr>
                <tr>
                  <td align="center" style="padding:0 0 24px 0;text-align:center;">
                    <div class="footer-social-wrap" role="presentation" style="width:100%;max-width:420px;margin:0 auto;text-align:center;display:flex;justify-content:center;align-items:center;flex-wrap:wrap;">
                      <a class="footer-social-link" href="https://www.facebook.com/remax" aria-label="RE/MAX on Facebook" style="display:inline-block;color:#ffffff;text-decoration:none;margin:0 7px 12px 7px;">
                        <img src="https://img.icons8.com/ios-filled/50/ffffff/facebook-new.png" width="24" height="24" alt="Facebook" style="border:0;display:block;outline:none;text-decoration:none;width:24px;height:24px;" />
                      </a>
                      <a class="footer-social-link" href="https://x.com/remax" aria-label="RE/MAX on X" style="display:inline-block;color:#ffffff;text-decoration:none;margin:0 7px 12px 7px;">
                        <img src="https://img.icons8.com/ios-filled/50/ffffff/twitterx.png" width="24" height="24" alt="X" style="border:0;display:block;outline:none;text-decoration:none;width:24px;height:24px;" />
                      </a>
                      <a class="footer-social-link" href="https://www.instagram.com/remax/" aria-label="RE/MAX on Instagram" style="display:inline-block;color:#ffffff;text-decoration:none;margin:0 7px 12px 7px;">
                        <img src="https://img.icons8.com/ios-filled/50/ffffff/instagram-new.png" width="24" height="24" alt="Instagram" style="border:0;display:block;outline:none;text-decoration:none;width:24px;height:24px;" />
                      </a>
                      <a class="footer-social-link" href="https://www.youtube.com/remax" aria-label="RE/MAX on YouTube" style="display:inline-block;color:#ffffff;text-decoration:none;margin:0 7px 12px 7px;">
                        <img src="https://img.icons8.com/ios-filled/50/ffffff/youtube-play.png" width="24" height="24" alt="YouTube" style="border:0;display:block;outline:none;text-decoration:none;width:24px;height:24px;" />
                      </a>
                      <a class="footer-social-link" href="https://www.pinterest.com/remax/" aria-label="RE/MAX on Pinterest" style="display:inline-block;color:#ffffff;text-decoration:none;margin:0 7px 12px 7px;">
                        <img src="https://img.icons8.com/ios-filled/50/ffffff/pinterest.png" width="24" height="24" alt="Pinterest" style="border:0;display:block;outline:none;text-decoration:none;width:24px;height:24px;" />
                      </a>
                      <a class="footer-social-link" href="https://www.linkedin.com/company/remax/" aria-label="RE/MAX on LinkedIn" style="display:inline-block;color:#ffffff;text-decoration:none;margin:0 7px 12px 7px;">
                        <img src="https://img.icons8.com/ios-filled/50/ffffff/linkedin.png" width="24" height="24" alt="LinkedIn" style="border:0;display:block;outline:none;text-decoration:none;width:24px;height:24px;" />
                      </a>
                      <a class="footer-social-link" href="https://www.tiktok.com/@remax" aria-label="RE/MAX on TikTok" style="display:inline-block;color:#ffffff;text-decoration:none;margin:0 7px 12px 7px;">
                        <img src="https://img.icons8.com/ios-filled/50/ffffff/tiktok.png" width="24" height="24" alt="TikTok" style="border:0;display:block;outline:none;text-decoration:none;width:24px;height:24px;" />
                      </a>
                    </div>
                  </td>
                </tr>
                <tr>
                  <td align="center" style="padding:0;text-align:center;">
                    <table class="footer-legal-table" role="presentation" cellpadding="0" cellspacing="0" width="100%" style="border-collapse:collapse;width:100%;table-layout:fixed;">
                      <tr>
                        <td class="footer-legal-cell" align="left" valign="bottom" width="50%" style="padding:0;text-align:left;vertical-align:bottom;font-family:Arial,Helvetica,sans-serif;">
                          <a class="footer-legal-link" href="https://www.remax.com/terms-of-use" style="color:#ffffff;text-decoration:underline;font-size:13px;line-height:18px;font-weight:700;letter-spacing:0.85px;">Terms of Use</a>
                        </td>
                        <td class="footer-legal-cell" align="right" valign="bottom" width="50%" style="padding:0;text-align:right;vertical-align:bottom;font-family:Arial,Helvetica,sans-serif;">
                          <a class="footer-legal-link" href="https://www.remax.com/privacy-notice" style="color:#ffffff;text-decoration:underline;font-size:13px;line-height:18px;font-weight:700;letter-spacing:0.85px;">Privacy Notice</a>
                        </td>
                      </tr>
                    </table>
                  </td>
                </tr>
              </table>
            </td>
          </tr>
        </table>
      </div>
    </center>
  </body>
</html>
`;
}

function buildTextBody({ name, messageHtml }) {
  const messageText = stripHtml(messageHtml);
  return `Dear ${name},

${messageText}`;
}

async function createTransporter(senderAddress = '') {
  const mailMode = (process.env.MAIL_MODE || '').toLowerCase();
  const mailPort = Number(process.env.MAIL_PORT || 465);
  const dkim = getDkimConfig(senderAddress);

  if (process.env.MAIL_HOST && process.env.MAIL_USER && process.env.MAIL_PASS && mailPort !== Number(PORT)) {
    const smtpOptions = {
      host: process.env.MAIL_HOST,
      port: mailPort,
      secure: process.env.MAIL_SECURE ? process.env.MAIL_SECURE === 'true' : mailPort === 465,
      connectionTimeout: 15000,
      greetingTimeout: 15000,
      socketTimeout: 30000,
      auth: {
        user: process.env.MAIL_USER,
        pass: process.env.MAIL_PASS
      }
    };

    if (dkim) {
      smtpOptions.dkim = dkim;
    }

    return {
      deliveryMode: 'smtp',
      transporter: nodemailer.createTransport(smtpOptions)
    };
  }

  if (process.env.USE_ETHEREAL === 'true') {
    try {
      const testAccount = await nodemailer.createTestAccount();
      console.log('Using Ethereal test email account:', testAccount.user);
      return {
        deliveryMode: 'ethereal',
      transporter: nodemailer.createTransport({
        host: testAccount.smtp.host,
        port: testAccount.smtp.port,
        secure: testAccount.smtp.secure,
          auth: {
            user: testAccount.user,
            pass: testAccount.pass
          }
        })
      };
    } catch (err) {
      console.warn('Ethereal unavailable.');
    }
  }

  if (process.env.SENDMAIL === 'true' || process.env.SENDMAIL_PATH) {
    return {
      deliveryMode: 'sendmail',
      transporter: nodemailer.createTransport({
        sendmail: true,
        newline: 'unix',
        path: process.env.SENDMAIL_PATH || '/usr/sbin/sendmail',
        ...(dkim ? { dkim } : {})
      })
    };
  }

  if (mailMode !== 'preview') {
    console.info('No SMTP credentials loaded. Using local email preview mode.');
  }
  return {
    deliveryMode: 'preview',
    transporter: createPreviewTransporter()
  };
}

function createPreviewTransporter() {
  return nodemailer.createTransport({
    streamTransport: true,
    buffer: true
  });
}

function saveFallbackEmail(html, text) {
  const emailDir = path.join(__dirname, 'generated-emails');
  fs.mkdirSync(emailDir, { recursive: true });
  const timestamp = Date.now();
  const htmlPath = path.join(emailDir, `email-${timestamp}.html`);
  const txtPath = path.join(emailDir, `email-${timestamp}.txt`);
  fs.writeFileSync(htmlPath, inlineCidImagesForPreview(html), 'utf8');
  fs.writeFileSync(txtPath, text, 'utf8');
  return { htmlPath: `/generated-emails/email-${timestamp}.html`, txtPath: `/generated-emails/email-${timestamp}.txt` };
}

function inlineCidImagesForPreview(html) {
  if (!fs.existsSync(FOOTER_LOGO_PATH)) {
    return html;
  }

  const footerLogoDataUri = `data:image/png;base64,${fs.readFileSync(FOOTER_LOGO_PATH).toString('base64')}`;
  return html.replace(`cid:${FOOTER_LOGO_CID}`, footerLogoDataUri);
}

function getFooterLogoAttachment() {
  if (!fs.existsSync(FOOTER_LOGO_PATH)) {
    console.warn(`Footer logo not found at ${FOOTER_LOGO_PATH}.`);
    return null;
  }

  return {
    filename: 'Remaxlogo.png',
    path: FOOTER_LOGO_PATH,
    cid: FOOTER_LOGO_CID,
    contentType: 'image/png',
    contentDisposition: 'inline'
  };
}

app.post('/api/contact', upload.single('pdfFile'), async (req, res) => {
  const { selectedEmail, name, email, subject, message, website, ts } = req.body;
  const recipientEmail = normalizeEmail(email);
  const replyToAddress = normalizeEmail(selectedEmail);
  const fileInfo = req.file ? {
    originalName: req.file.originalname,
    storedName: req.file.filename,
    size: req.file.size
  } : null;

  if (website && website.trim() !== '') {
    return res.json({ success: false, reason: 'Spam detected' });
  }

  const tsNum = parseInt(ts, 10) || 0;
  if ((Date.now() - tsNum) < 3000) {
    return res.json({ success: false, reason: 'Form submitted too quickly' });
  }

  if (!name || !recipientEmail || !subject || !message) {
    return res.json({ success: false, reason: 'Missing required fields' });
  }

  if (!isValidEmail(recipientEmail)) {
    return res.json({ success: false, reason: 'Invalid recipient email address.' });
  }

  if (!ALLOWED_REPLY_TO_ADDRESSES.has(replyToAddress)) {
    return res.json({ success: false, reason: 'Invalid sender email selection.' });
  }

  const attachments = [];
  const footerLogoAttachment = getFooterLogoAttachment();

  if (footerLogoAttachment) {
    attachments.push(footerLogoAttachment);
  }

  if (req.file) {
    attachments.push({
      filename: req.file.originalname,
      path: req.file.path,
      contentType: req.file.mimetype
    });
  }

  const senderAddress = getSenderAddress();

  if (!isValidEmail(senderAddress)) {
    return res.json({
      success: false,
      reason: 'SMTP sender is not configured. Set MAIL_FROM or MAIL_USER to the authenticated sending address.'
    });
  }

  const mailOptions = {
    from: { name: 'RE/MAX', address: senderAddress },
    to: recipientEmail,
    subject: subject || 'Thank you for registering! Please verify your email.',
    messageId: createMessageId(senderAddress),
    headers: {
      'X-Mailer': 'RE/MAX Global Homes Contact App',
      'X-Selected-Reply-To': replyToAddress
    },
    text: buildTextBody({ name, messageHtml: message }),
    html: buildEmailHtml({ name, email: recipientEmail, messageHtml: message }),
    replyTo: replyToAddress,
    envelope: {
      from: senderAddress,
      to: recipientEmail
    },
    attachments
  };

  try {
    const domainHealth = process.env.MAIL_SKIP_DNS_CHECK === 'true'
      ? { ok: true, issues: [], records: {}, skipped: true }
      : await getSenderDomainHealth(senderAddress);

    if (!domainHealth.ok) {
      console.warn('Email send blocked because sender domain DNS is not healthy:', domainHealth);
      const fallbackFiles = saveFallbackEmail(mailOptions.html, mailOptions.text);

      return res.status(502).json({
        success: false,
        reason: `Email was not sent because ${getEmailDomain(senderAddress)} is not publicly verifiable. iCloud and custom-domain inboxes commonly reject mail when sender DNS, SPF, or DMARC cannot be resolved.`,
        data: {
          selectedEmail: replyToAddress,
          name,
          email: recipientEmail,
          subject,
          message,
          fileInfo,
          receivedAt: new Date().toISOString(),
          mailInfo: {
            messageId: null,
            previewUrl: null,
            fallback: fallbackFiles,
            deliveryMode: 'blocked-dns-preflight',
            senderDomainHealth: domainHealth
          }
        },
        previewUrl: null,
        fallback: fallbackFiles,
        senderDomainHealth: domainHealth
      });
    }

    const { transporter, deliveryMode } = await createTransporter(senderAddress);
    if (deliveryMode === 'smtp' && typeof transporter.verify === 'function') {
      await transporter.verify();
    }

    const info = await transporter.sendMail(mailOptions);
    const previewUrl = nodemailer.getTestMessageUrl ? nodemailer.getTestMessageUrl(info) : null;
    const fallback = (!previewUrl && info.message) ? saveFallbackEmail(mailOptions.html, mailOptions.text) : null;
    const accepted = Array.isArray(info.accepted) ? info.accepted.map(normalizeEmail) : [];
    const rejected = Array.isArray(info.rejected) ? info.rejected.map(normalizeEmail) : [];

    if (deliveryMode === 'preview') {
      return res.json({
        success: false,
        reason: 'Email was not sent because SMTP is not configured. A local preview was generated instead.',
        previewUrl,
        fallback
      });
    }

    if (rejected.length > 0 || (accepted.length > 0 && !accepted.includes(recipientEmail))) {
      console.warn('Email recipient was rejected:', { recipientEmail, accepted, rejected });
      return res.json({
        success: false,
        reason: `SMTP did not accept delivery for ${recipientEmail}.`,
        accepted,
        rejected,
        smtpResponse: info.response || null
      });
    }

    const responseData = {
      selectedEmail: replyToAddress,
      name,
      email: recipientEmail,
      subject,
      message,
      fileInfo,
      receivedAt: new Date().toISOString(),
      mailInfo: {
        messageId: info.messageId,
        previewUrl,
        fallback,
        deliveryMode,
        accepted,
        rejected,
        smtpResponse: info.response || null
      }
    };

    console.log('Contact submission received:', responseData);
    return res.json({ success: true, data: responseData, previewUrl, fallback });
  } catch (error) {
    const smtpError = {
      code: error.code || null,
      command: error.command || null,
      responseCode: error.responseCode || null,
      message: error.message || 'Unknown SMTP error'
    };
    console.warn('Email send failed; saved a local preview instead:', smtpError);
    const fallbackFiles = saveFallbackEmail(mailOptions.html, mailOptions.text);
    return res.status(502).json({
      success: false,
      reason: smtpError.code === 'EAUTH'
        ? 'SMTP authentication failed. Check MAIL_USER, MAIL_PASS, and whether the mailbox requires an app password.'
        : 'Email could not be sent over SMTP. A local preview was saved, but the recipient was not emailed.',
      data: {
        selectedEmail: replyToAddress,
        name,
        email: recipientEmail,
        subject,
        message,
        fileInfo,
        receivedAt: new Date().toISOString(),
        mailInfo: {
          messageId: null,
          previewUrl: null,
          fallback: fallbackFiles,
          deliveryMode: 'local-preview'
        }
      },
      previewUrl: null,
      fallback: fallbackFiles,
      errorCode: smtpError.code,
      smtpError,
      smtpResponse: error.response || error.responseCode || null,
      note: 'Email could not be sent over SMTP; preview saved locally.'
    });
  }
});

app.get('/api/status', (req, res) => {
  res.json({ status: 'ok', environment: process.env.NODE_ENV || 'development' });
});

app.listen(PORT, () => {
  console.log(`Server running at http://localhost:${PORT}`);
});
