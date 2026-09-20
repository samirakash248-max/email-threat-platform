import os

os.makedirs("samples/demo_dataset", exist_ok=True)

# Email A: impersonating executive, reply-to mismatch, lookalike domain, suspicious URL, urgency, HTML link mismatch
email_a = """From: "CEO John Doe" <ceo@trustd-bank.com>
To: employee@trusted-bank.com
Reply-To: attacker@evil.com
Subject: URGENT: Wire Transfer Authorization
Date: Tue, 19 Sep 2026 10:00:00 +0000
Message-ID: <a1@trustd-bank.com>
MIME-Version: 1.0
Content-Type: text/html; charset="utf-8"

<p>Please process this wire transfer immediately!</p>
<p>Log in here to authorize: <a href="http://192.168.1.100/login.zip">https://trusted-bank.com/secure-login</a></p>

<p>Thanks,<br>John</p>
"""

# Email B: same malicious infrastructure (domain/IP)
email_b = """From: "IT Support" <support@trustd-bank.com>
To: employee2@trusted-bank.com
Subject: Mandatory Password Reset
Date: Tue, 19 Sep 2026 10:10:00 +0000
Message-ID: <b1@trustd-bank.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="utf-8"

Update your password: http://192.168.1.100/login.zip
"""

# Email C: dangerous attachment
email_c = """From: "Vendor" <vendor@somewhere.com>
To: employee@trusted-bank.com
Subject: Invoice 12345
Date: Tue, 19 Sep 2026 10:20:00 +0000
Message-ID: <c1@somewhere.com>
MIME-Version: 1.0
Content-Type: multipart/mixed; boundary="boundary-c"

--boundary-c
Content-Type: text/plain; charset="utf-8"

Please see the attached invoice.
--boundary-c
Content-Type: application/x-msdownload; name="invoice.exe"
Content-Disposition: attachment; filename="invoice.exe"

MZ...
--boundary-c--
"""

# Email D: unrelated benign email
email_d = """From: "HR" <hr@trusted-bank.com>
To: employee@trusted-bank.com
Subject: Company Picnic
Date: Tue, 19 Sep 2026 10:30:00 +0000
Message-ID: <d1@trusted-bank.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="utf-8"

Don't forget the company picnic this Friday!
"""

with open("samples/demo_dataset/email_a_exec.eml", "w") as f: f.write(email_a)
with open("samples/demo_dataset/email_b_infra.eml", "w") as f: f.write(email_b)
with open("samples/demo_dataset/email_c_attach.eml", "w") as f: f.write(email_c)
with open("samples/demo_dataset/email_d_benign.eml", "w") as f: f.write(email_d)
