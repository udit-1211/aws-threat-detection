# Build a Real-Time Threat Detection on AWS | GuardDuty, CloudTrail, Lambda & SNS 🛡️

<div align="center">

  <br />
      <img src="https://github.com/user-attachments/assets/f2592643-7018-4932-8738-495e94505c86" alt="Project Banner">
  <br />

<h3 align="center">Build a Real-time threat detection and response system on AWS using GuardDuty, SNS, and Lambda. </h3>

</div>

## <a name="introduction">🤖 Introduction</a>

In this hands-on project, we'll build a real-time  threat detection and response system on AWS using GuardDuty, SNS, and Lambda. This setup will enable you to automatically detect threats and take immediate action, significantly improving your security posture. Simulate abnormal behavior in an AWS environment and use tools to detect, respond, and notify you in real time.

## <a name="steps">🛠 Tech Stack: </a>

This project showcases a real-time AI-powered security pipeline using:

- Amazon CloudTrail (log API activity)
- Amazon GuardDuty (AI-based threat detection)
- Amazon EventBridge (trigger on GuardDuty findings)
- AWS Lambda (automated response)
- Amazon SNS (send real-time email/SMS alerts)


Simulated GuardDuty findings, trigger SNS alerts and a Lambda function that sends a clean, human-readable security alert.

## 🔧 Prerequisites

✅ An AWS account<br>
✅ AWS CLI configured<br>


## ➡️ Step 1 - Enable CloudTrail

Amazon CloudTrail records all AWS API calls and activity in your account. GuardDuty analyzes these logs.

How to do it:

1. Go to the CloudTrail console
2. If it’s not already enabled: Click “Create trail”
3. Choose “Management events”
4. Choose to log to an S3 bucket
6. Click “Create trail”

✅ Now your account logs all actions taken by users, roles, and services.

## ➡️ Step 2 - Enable Amazon GuardDuty

Amazon GuardDuty will analyze CloudTrail, DNS, VPC Flow Logs, and more using ML + threat intel to detect suspicious behavior.

How to do it:

1. Go to the GuardDuty console
2. Click “Enable GuardDuty”
3. Wait 5-10 mins, it starts analyzing logs.

✅ GuardDuty is now scanning your account for threats like credential theft, unusual login behavior, port scanning, and more.

## ➡️ Step 3 - Set Up an SNS Topic for Notifications

Next, we'll create an SNS topic to send alerts to you or your security team whenever a threat is detected.

How to do it:

1. Go to Amazon SNS → Topics → Create topic
2. Type: Standard
3. Name: `GuardDuty-Threat-Alerts`
4. Click Create topic
5. Click “Create subscription”
- Protocol: Email
- Endpoint: your email address
6. Confirm the email by coying the link in your inbox:
- Copy the Confirm subscription URL
- Go back to your subscription page, click on Confirm subscription button
- Paste the URL in the dialog box, and click Confirm subscription.

✅ SNS is now ready to send you alerts.

## ➡️ Step 4 - Create a Lambda Function - Our Alert Processor

We'll create a Lambda function that takes the complicated JSON output from GuardDuty and turns it into a simple message.

🔹 Create the Lambda IAM Role:

Go to the IAM console and create a new role:
1. For the trusted entity, select AWS service, and for the use case, choose Lambda.
2. On the permissions screen, add the `AWSLambdaBasicExecutionRole` policy. This allows our function to write logs to CloudWatch, which is essential for debugging.
3. Name the role something like `GuardDuty-Lambda-Role` and create it.

🔹 Create the Lambda Function:

1. Go to the Lambda console and click Create function.
2. Select Author from scratch.
3. Function name: `GuardDuty-Automated-Response`
4. Runtime: Python `3.13`
5. Architecture: `x86_64`
6. Permissions: Choose Use an existing role and select the IAM role you just created.
7. Click Create function.

Now, let's paste in our Python code. This code will parse the GuardDuty finding, pull out the most important details, and format a clean message.

<details>
<summary><code>GuardDuty-Automated-Response.py</code></summary>

```python
import boto3
import json
from datetime import datetime

# ==== CONFIGURATION ====
SNS_TOPIC_ARN = "YOUR_SNS_ARN"
AUTHOR = "Udit Parekh"
GITHUB_LINK = "https://github.com/udit-1211/aws-threat-detection"

sns = boto3.client("sns")

def format_time(ts: str) -> str:
    try:
        return datetime.fromisoformat(ts.replace("Z", "+00:00")).strftime("%Y-%m-%d %H:%M:%S UTC")
    except Exception:
        return ts

def build_message(detail: dict, region: str, time: str) -> str:
    title = detail.get("title", "S3 Malicious File Detected")
    description = detail.get("description", "No description")
    severity = detail.get("severity", "N/A")
    account_id = detail.get("accountId", "N/A")

    # Extract bucket/object info
    bucket_details = detail.get("resource", {}).get("s3BucketDetails", [{}])[0]
    bucket_name = bucket_details.get("name", "N/A")
    object_details = bucket_details.get("s3ObjectDetails", [{}])[0]
    object_key = object_details.get("key", "N/A")
    object_arn = object_details.get("objectArn", "N/A")

    # Extract threat name if present
    threats = detail.get("service", {}).get("malwareScanDetails", {}).get("threats", [])
    threat_name = threats[0].get("name") if threats else "Unknown Threat"

    message = f"""
🚨 GuardDuty Security Alert: Malicious S3 File

🔹 Account: {account_id}
🔹 Region: {region}
🔹 Severity: {severity}
🔹 Time: {format_time(time)}

📘 Description:
{description}

📂 Affected S3 Resource:
- Bucket: {bucket_name}
- Object Key: {object_key}
- Object ARN: {object_arn}
- Threat Detected: {threat_name}

🧠 Recommended Actions:
- Quarantine or delete the infected object.
- Review bucket permissions to prevent unauthorized uploads.
- Enable S3 Object Lock or versioning to prevent tampering.
- Consider enabling AWS Macie & Security Hub for better visibility.

—
Made by {AUTHOR}
{GITHUB_LINK}
    """.strip()

    return message

def lambda_handler(event, context):
    try:
        detail = event["detail"]
        region = event.get("region", "N/A")
        time = detail.get("service", {}).get("eventFirstSeen", event.get("time", "N/A"))

        if not detail.get("type", "").startswith("Object:S3/MaliciousFile"):
            return {"statusCode": 200, "body": "Skipped non-S3 malicious file alert"}

        message = build_message(detail, region, time)

        sns.publish(
            TopicArn=SNS_TOPIC_ARN,
            Subject="🚨 GuardDuty Alert: Malicious S3 File",
            Message=message
        )

        return {"statusCode": 200, "body": "S3 malicious file alert processed successfully"}
    except Exception as e:
        return {"statusCode": 500, "body": f"Error processing event: {str(e)}"}
```
</details>

🔹 Configure Environment Variables:

1. In your Lambda function's configuration, go to the Environment variables tab and click Edit.
2. Add a new variable:
<br>• Key: `SNS_TOPIC_ARN`
<br>• Value: Paste the ARN of the SNS topic you created in Step 3.

🔹 Attach a Policy to Allow SNS Publish:

1. In your Lambda function in the AWS Console
2. Go to Configuration > Permissions
3. Click the role name `GuardDuty-Lambda-Role`  this will take you to the IAM Role details.
4. From the IAM Role page, "Add permissions" > "Attach policies"
5. Choose “Create inline policy” (for full control)
6. Create and Attach Inline Policy, use the following JSON in the JSON tab:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": "sns:Publish",
      "Resource": "arn:aws:sns:your-region:your-account-id:your-topic-name"
    }
  ]
}
```

⚠️ Note: Replace `your-region` `your-account-id` `your-topic-name` with your actual values.

7. Click Next, give it a name like `AllowSNSPublish`
8. Click Create policy

Now this role can successfully publish to your SNS topic!

## ➡️ Step 5 - Integrate Services with Amazon EventBridge

Now, we'll create an EventBridge rule to trigger our Lambda function and send a notification when GuardDuty detects a specific type of threat.

1. Go to the Amazon EventBridge console.
2. In the left navigation pane, click Rules, then Create rule.
3. Give it a name like `GuardDuty-EC2-Threat-Rule`
4. Event bus: default
5. Rule type: Rule with an event pattern
6. Click Next.
7. Event source: AWS events or EventBridge partner events
8. Event pattern:
  <br>• Event source: AWS services
  <br>• AWS service: GuardDuty
  <br>• Event type: GuardDuty Finding

```json
{
  "source": ["aws.guardduty"],
  "detail-type": ["GuardDuty Finding"],
  "detail": {
    "type": ["Object:S3/MaliciousFile"]
  }
}
```
9. Click Next.
10. Select a target:
<br>• Target 1:
      <br>• Target types: AWS service
      <br>• Select a target: Lambda function
      <br>• Function: Select the `GuardDuty-Automated-Response` function.

11. Click Next and then Create rule.

### 🏆 Let's Test It!

We will use the Node app to upload malicious file on S3 bucket.

1. Use this node snippet
<details>
<summary><code>app.js</code></summary>
  
```javascript
   // app.js
  const express = require("express");
  const bodyParser = require("body-parser");
  const { S3Client, PutObjectCommand } = require("@aws-sdk/client-s3");
  const AbortController = global.AbortController;

  const app = express();
  const port = 3000;

  // ==== AWS Details ====
  const REGION = "YOUR_BUCKET_REGION";
  const BUCKET_NAME = "YOUR_BUCKET_NAME";
  const ACCESS_KEY = "YOUR_ACCESS_KEY";
  const SECRET_KEY = "YOUR_SECRET_KEY";

  // ==== S3 Client ====
  const s3 = new S3Client({
    region: REGION,
    credentials: { accessKeyId: ACCESS_KEY, secretAccessKey: SECRET_KEY },
  });

  app.use(bodyParser.json({ limit: "200mb" }));

  // ==== UI Page ====
  app.get("/", (req, res) => {
    res.type("html").send(`<!doctype html>
  <html lang="en">
  <head>
    <meta charset="utf-8"/>
    <title>S3 Upload</title>
    <style>
      body {
        margin: 0;
        font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
        background: linear-gradient(135deg, #667eea, #764ba2);
        height: 100vh;
        display: flex;
        justify-content: center;
        align-items: center;
        color: #333;
      }
      .card {
        background: #fff;
        padding: 30px;
        border-radius: 16px;
      box-shadow: 0 8px 20px rgba(0,0,0,0.15);
      width: 400px;
      text-align: center;
    }
    h2 {
      margin-bottom: 20px;
      color: #444;
    }
    #dropZone {
      border: 2px dashed #888;
      border-radius: 12px;
      padding: 30px;
      margin-bottom: 20px;
      transition: background 0.3s, border-color 0.3s;
      cursor: pointer;
    }
    #dropZone.dragover {
      background: #f0f8ff;
      border-color: #4a90e2;
    }
    button {
      background: #4a90e2;
      color: white;
      border: none;
      padding: 12px 24px;
      border-radius: 8px;
      cursor: pointer;
      font-size: 15px;
      transition: background 0.3s;
    }
    button:hover {
      background: #357ABD;
    }
    #status {
      margin-top: 15px;
      font-weight: 500;
    }
    #log {
      margin-top: 15px;
      text-align: left;
      background: #f9f9f9;
      border-radius: 8px;
      padding: 10px;
      max-height: 200px;
      overflow-y: auto;
      font-size: 13px;
      color: #555;
    }
  </style>
</head>
<body>
  <div class="card">
    <h2>S3 Upload</h2>
    <div id="dropZone">Drag & Drop file here<br>or click to select</div>
    <input type="file" id="fileInput" style="display:none"/>
    <button id="uploadBtn">Upload</button>
    <p id="status"></p>
    <pre id="log"></pre>
  </div>

<script>
const dropZone = document.getElementById('dropZone');
const fileInput = document.getElementById('fileInput');
const uploadBtn = document.getElementById('uploadBtn');
const status = document.getElementById('status');
const log = document.getElementById('log');
let selectedFile = null;

function write(msg) {
  log.textContent += msg + "\\n";
  log.scrollTop = log.scrollHeight;
}

// Drag & Drop
dropZone.addEventListener('click', () => fileInput.click());
dropZone.addEventListener('dragover', (e) => {
  e.preventDefault();
  dropZone.classList.add('dragover');
});
dropZone.addEventListener('dragleave', () => dropZone.classList.remove('dragover'));
dropZone.addEventListener('drop', (e) => {
  e.preventDefault();
  dropZone.classList.remove('dragover');
  selectedFile = e.dataTransfer.files[0];
  if (selectedFile) {
    write("Selected: " + selectedFile.name + " (" + selectedFile.size + " bytes)");
  }
});

fileInput.addEventListener('change', (e) => {
  selectedFile = e.target.files[0];
  if (selectedFile) {
    write("Selected: " + selectedFile.name + " (" + selectedFile.size + " bytes)");
  }
});

// Upload
uploadBtn.addEventListener('click', async () => {
  if (!selectedFile) {
    status.textContent = '⚠️ Pick a file first';
    return;
  }
  status.textContent = 'Starting upload...';
  write("Uploading " + selectedFile.name);

  const reader = new FileReader();
  reader.onload = async () => {
    const dataUrl = reader.result;
    const base64 = dataUrl.split(',')[1];

    try {
      const res = await fetch('/upload-base64', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          filename: selectedFile.name,
          mimeType: selectedFile.type || 'application/octet-stream',
          data: base64
        })
      });
      const json = await res.json();
      if (res.ok) {
        status.textContent = '✅ Upload success: ' + json.key;
        write("S3 key = " + json.key);
      } else {
        status.textContent = '❌ Upload failed: ' + (json.error || res.status);
        write("Error: " + JSON.stringify(json));
      }
    } catch (err) {
      status.textContent = '❌ Network/JS error';
      write("fetch error: " + err);
    }
  };
  reader.readAsDataURL(selectedFile);
});
</script>
</body>
</html>`);
});

// ==== Base64 Upload Route ====
app.post("/upload-base64", async (req, res) => {
  try {
    const { filename, mimeType, data } = req.body;
    if (!filename || !data) {
      return res.status(400).json({ status: "fail", error: "missing fields" });
    }

    console.log(`[${new Date().toISOString()}] Uploading ${filename}, size=${data.length}`);
    const buffer = Buffer.from(data, "base64");

    const key = filename; // keep original filename

    const ac = new AbortController();
    req.on("aborted", () => {
      console.warn(`Client aborted upload: ${filename}`);
      try { ac.abort(); } catch {}
    });

    await s3.send(new PutObjectCommand({
      Bucket: BUCKET_NAME,
      Key: key,
      Body: buffer,
      ContentType: mimeType || "application/octet-stream",
    }), { abortSignal: ac.signal });

    console.log(`✅ Uploaded ${key} to S3`);
    res.json({ status: "success", key });
  } catch (err) {
    console.error("Upload error:", err.message);
    if (!res.headersSent) res.status(500).json({ status: "fail", error: err.message });
  }
});

// ==== Start Server ====
app.listen(port, () => console.log("🚀 S3 Upload UI running at http://localhost:" + port));

```
</details>

2. Upload test malicious file (Eg. EICAAR Test file)

3. You can see findings in GuardDuty dashboard

### Verification - Check the Results ✅

Now, let's verify that each component of our project worked as expected.

1. Check for the SNS Notification
<br>• Go to your email inbox that you subscribed to the SNS topic.

2. Check GuardDuty Findings
<br>• Go to GuardDuty Console, you'll now see a full list of GuardDuty findings, each row representing a detection event:
<br>• Finding Type:
   <br>`Object:S3/MaliciousFile`
<br>• Severity Type: `High`

3. Check the Lambda Function Logs
<br>• Navigate to the Lambda console and select your `GuardDuty-Automated-Response` function.
<br>• Click on the Monitor tab, and then View CloudWatch logs.

## Tutorial




https://github.com/user-attachments/assets/96030cdb-897b-4eb3-948b-cabec331e11d



## 🗑️ Cleaning Up

When you are finished with the project, you can destroy all the created AWS resources to avoid incurring further costs.
