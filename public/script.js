const contactForm = document.getElementById('contactForm');
const statusText = document.getElementById('formStatus');
const signOutBtn = document.getElementById('signOutBtn');
const successBanner = document.getElementById('successBanner');

signOutBtn.addEventListener('click', () => {
    alert('Signed out successfully.');
});

// Initialize Quill rich text editor
const quill = new Quill('#editor', {
    theme: 'snow',
    placeholder: 'Write your message here...'
});

function initAntiSpamFields() {
    document.getElementById('ts').value = String(Date.now());
    document.getElementById('website').value = '';
}

initAntiSpamFields();

function validateForm() {
    const name = document.getElementById('name').value.trim();
    const email = document.getElementById('email').value.trim();
    const subject = document.getElementById('subject').value.trim();
    const messageHtml = quill.root.innerHTML.trim();
    const plain = quill.getText().trim();
    const website = document.getElementById('website').value.trim();
    const ts = parseInt(document.getElementById('ts').value, 10) || 0;

    if (website) return { ok: false, reason: 'Bot detected' };
    if ((Date.now() - ts) < 3000) return { ok: false, reason: 'Form submitted too quickly' };
    if (!name) return { ok: false, reason: 'Name is required' };
    if (!email || !/^\S+@\S+\.\S+$/.test(email)) return { ok: false, reason: 'Valid email required' };
    if (!subject) return { ok: false, reason: 'Subject is required' };
    if (!plain) return { ok: false, reason: 'Message is required' };

    return { ok: true };
}

contactForm.addEventListener('submit', async (event) => {
    event.preventDefault();

    // place editor HTML into hidden input
    document.getElementById('message').value = quill.root.innerHTML;

    const valid = validateForm();
    if (!valid.ok) {
        statusText.textContent = valid.reason;
        return;
    }

    statusText.textContent = 'Sending message...';

    const formData = new FormData(contactForm);

    try {
        const response = await fetch('/api/contact', {
            method: 'POST',
            body: formData
        });

        const result = await response.json();
        if (result.success) {
            statusText.textContent = '';
            statusText.classList.remove('error');
            successBanner.hidden = false;
            if (result.previewUrl) {
                successBanner.innerHTML = `Message generated successfully. <a href="${result.previewUrl}" target="_blank" rel="noopener noreferrer">View email preview</a>`;
            } else if (result.fallback?.htmlPath) {
                successBanner.innerHTML = `Message generated successfully. <a href="${result.fallback.htmlPath}" target="_blank" rel="noopener noreferrer">View local email preview</a>`;
            } else {
                successBanner.textContent = 'Message generated successfully.';
            }
            setTimeout(() => { successBanner.hidden = true; }, 5000);
            contactForm.reset();
            quill.setContents([{ insert: '\n' }]);
            initAntiSpamFields();
        } else {
            successBanner.hidden = true;
            statusText.classList.add('error');
            statusText.textContent = result.reason || 'Failed to send message. Please try again.';
            if (result.fallback?.htmlPath) {
                statusText.innerHTML = `${statusText.textContent} <a href="${result.fallback.htmlPath}" target="_blank" rel="noopener noreferrer">View local preview</a>`;
            }
            initAntiSpamFields();
        }
    } catch (error) {
        console.error('Contact form error:', error);
        statusText.textContent = 'Unable to send message. Check your network.';
        initAntiSpamFields();
    }
});
