package main

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/smtp"
	"os"
	"strings"
	"time"

	"github.com/joho/godotenv"
	"github.com/robfig/cron/v3"
)

type CertInfo struct {
	URL          string
	Name         string
	ExpiryDate   time.Time
	DaysRemaining int
	CommonName   string
}

var (
	logFile *os.File
	logger  *log.Logger
)

func main() {
	// Initialize logging
	initLogger()
	defer logFile.Close()

	logger.Println("SSL Certificate Monitor started")

	// Load environment variables
	err := godotenv.Load()
	if err != nil {
		logger.Fatal("Error loading .env file")
	}

	// Run immediately on start
	checkCertificates()

	// Setup cron job to run daily at 12:00 AM
	c := cron.New()
	_, err = c.AddFunc("0 0 * * *", checkCertificates)
	if err != nil {
		logger.Fatalf("Error setting up cron job: %v", err)
	}

	logger.Println("Scheduled daily check at 12:00 AM")
	c.Start()

	// Keep the program running
	select {}
}

func initLogger() {
	var err error
	logFile, err = os.OpenFile("ssl_monitor.log", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		log.Fatal(err)
	}
	logger = log.New(logFile, "", log.LstdFlags)
}

func checkCertificates() {
	logger.Println("Starting certificate check...")

	urls := getURLsFromEnv()
	if len(urls) == 0 {
		logger.Println("No URLs found in environment variables")
		return
	}

	var expiringCerts []CertInfo
	var allCerts []CertInfo

	for name, url := range urls {
		certInfo, err := getCertificateInfo(url, name)
		if err != nil {
			logger.Printf("Error checking %s (%s): %v", name, url, err)
			continue
		}

		allCerts = append(allCerts, certInfo)
		logger.Printf("%s (%s): Expires in %d days", name, url, certInfo.DaysRemaining)

		if certInfo.DaysRemaining <= 14 {
			expiringCerts = append(expiringCerts, certInfo)
		}
	}

	// Send email with all certificates
	if len(allCerts) > 0 {
		sendEmail(allCerts, expiringCerts)
	}

	// Send Slack notification only for expiring certificates
	if len(expiringCerts) > 0 {
		sendSlackNotification(expiringCerts)
	}

	logger.Println("Certificate check completed")
}

func getURLsFromEnv() map[string]string {
	urls := make(map[string]string)

	// Load URLs from environment variables
	// Format: URL_NAME_1=https://example.com, URL_NAME_2=https://example2.com
	for _, env := range os.Environ() {
		pair := strings.SplitN(env, "=", 2)
		if len(pair) == 2 && strings.HasPrefix(pair[0], "URL_") {
			name := strings.TrimPrefix(pair[0], "URL_")
			urls[name] = pair[1]
		}
	}

	return urls
}

func getCertificateInfo(url, name string) (CertInfo, error) {
	// Remove protocol if present
	url = strings.TrimPrefix(url, "https://")
	url = strings.TrimPrefix(url, "http://")

	// Add port if not present
	if !strings.Contains(url, ":") {
		url += ":443"
	}

	conn, err := tls.Dial("tcp", url, &tls.Config{
		InsecureSkipVerify: false,
	})
	if err != nil {
		return CertInfo{}, err
	}
	defer conn.Close()

	certs := conn.ConnectionState().PeerCertificates
	if len(certs) == 0 {
		return CertInfo{}, fmt.Errorf("no certificates found")
	}

	cert := certs[0]
	expiryDate := cert.NotAfter
	daysRemaining := int(time.Until(expiryDate).Hours() / 24)

	return CertInfo{
		URL:          url,
		Name:         name,
		ExpiryDate:   expiryDate,
		DaysRemaining: daysRemaining,
		CommonName:   cert.Subject.CommonName,
	}, nil
}

func sendEmail(allCerts []CertInfo, expiringCerts []CertInfo) {
	smtpHost := os.Getenv("SMTP_HOST")
	smtpPort := os.Getenv("SMTP_PORT")
	smtpUser := os.Getenv("SMTP_USER")
	smtpPass := os.Getenv("SMTP_PASS")
	emailFrom := os.Getenv("EMAIL_FROM")
	emailTo := os.Getenv("EMAIL_TO")

	if smtpHost == "" || smtpPort == "" || emailFrom == "" || emailTo == "" {
		logger.Println("Email configuration missing, skipping email notification")
		return
	}

	subject := "SSL Certificate Monitoring Report"
	body := buildEmailBody(allCerts, expiringCerts)

	msg := []byte(fmt.Sprintf("From: %s\r\n"+
		"To: %s\r\n"+
		"Subject: %s\r\n"+
		"MIME-Version: 1.0\r\n"+
		"Content-Type: text/html; charset=UTF-8\r\n"+
		"\r\n"+
		"%s\r\n", emailFrom, emailTo, subject, body))

	auth := smtp.PlainAuth("", smtpUser, smtpPass, smtpHost)
	err := smtp.SendMail(smtpHost+":"+smtpPort, auth, emailFrom, []string{emailTo}, msg)
	if err != nil {
		logger.Printf("Error sending email: %v", err)
		return
	}

	logger.Println("Email sent successfully")
}

func buildEmailBody(allCerts []CertInfo, expiringCerts []CertInfo) string {
	body := `<!DOCTYPE html>
<html>
<head>
	<meta charset="UTF-8">
	<meta name="viewport" content="width=device-width, initial-scale=1.0">
	<style>
		* {
			margin: 0;
			padding: 0;
			box-sizing: border-box;
		}
		body {
			font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif;
			background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
			padding: 20px;
			line-height: 1.6;
		}
		.container {
			max-width: 900px;
			margin: 0 auto;
			background: #ffffff;
			border-radius: 16px;
			box-shadow: 0 20px 60px rgba(0, 0, 0, 0.3);
			overflow: hidden;
		}
		.header {
			background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
			color: white;
			padding: 40px;
			text-align: center;
		}
		.header h1 {
			font-size: 32px;
			font-weight: 700;
			margin-bottom: 10px;
			text-shadow: 0 2px 4px rgba(0, 0, 0, 0.2);
		}
		.header p {
			font-size: 16px;
			opacity: 0.9;
		}
		.content {
			padding: 40px;
		}
		.alert-section {
			background: linear-gradient(135deg, #ff6b6b 0%, #ee5a6f 100%);
			color: white;
			padding: 30px;
			border-radius: 12px;
			margin-bottom: 30px;
			box-shadow: 0 4px 12px rgba(255, 107, 107, 0.3);
		}
		.alert-section h2 {
			font-size: 24px;
			margin-bottom: 20px;
			display: flex;
			align-items: center;
			gap: 10px;
		}
		.section-title {
			font-size: 24px;
			color: #333;
			margin-bottom: 20px;
			padding-bottom: 10px;
			border-bottom: 3px solid #667eea;
			font-weight: 600;
		}
		.cert-card {
			background: #f8f9fa;
			border-left: 4px solid #667eea;
			padding: 20px;
			margin-bottom: 15px;
			border-radius: 8px;
			transition: transform 0.2s, box-shadow 0.2s;
		}
		.cert-card:hover {
			transform: translateX(5px);
			box-shadow: 0 4px 12px rgba(0, 0, 0, 0.1);
		}
		.cert-card.critical {
			border-left-color: #dc3545;
			background: #fff5f5;
		}
		.cert-card.warning {
			border-left-color: #ffc107;
			background: #fffbf0;
		}
		.cert-card.caution {
			border-left-color: #ff9800;
			background: #fff8f0;
		}
		.cert-header {
			display: flex;
			justify-content: space-between;
			align-items: center;
			margin-bottom: 12px;
			flex-wrap: wrap;
			gap: 10px;
		}
		.cert-name {
			font-size: 18px;
			font-weight: 700;
			color: #333;
		}
		.cert-badge {
			display: inline-block;
			padding: 6px 16px;
			border-radius: 20px;
			font-size: 14px;
			font-weight: 600;
			color: white;
		}
		.badge-critical {
			background: linear-gradient(135deg, #dc3545 0%, #c82333 100%);
			animation: pulse 2s infinite;
		}
		.badge-warning {
			background: linear-gradient(135deg, #ffc107 0%, #e0a800 100%);
		}
		.badge-caution {
			background: linear-gradient(135deg, #ff9800 0%, #e68900 100%);
		}
		.badge-ok {
			background: linear-gradient(135deg, #28a745 0%, #218838 100%);
		}
		@keyframes pulse {
			0%, 100% { opacity: 1; }
			50% { opacity: 0.7; }
		}
		.cert-details {
			display: grid;
			grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
			gap: 12px;
			color: #555;
			font-size: 14px;
		}
		.cert-detail-item {
			display: flex;
			gap: 8px;
		}
		.cert-detail-label {
			font-weight: 600;
			color: #333;
		}
		.cert-url {
			color: #667eea;
			text-decoration: none;
			word-break: break-all;
		}
		.stats-container {
			display: grid;
			grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
			gap: 20px;
			margin-bottom: 30px;
		}
		.stat-card {
			background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
			color: white;
			padding: 25px;
			border-radius: 12px;
			text-align: center;
			box-shadow: 0 4px 12px rgba(102, 126, 234, 0.3);
		}
		.stat-number {
			font-size: 36px;
			font-weight: 700;
			margin-bottom: 8px;
		}
		.stat-label {
			font-size: 14px;
			opacity: 0.9;
			text-transform: uppercase;
			letter-spacing: 1px;
		}
		.footer {
			background: #f8f9fa;
			padding: 30px;
			text-align: center;
			color: #666;
			font-size: 14px;
			border-top: 1px solid #e0e0e0;
		}
		.footer a {
			color: #667eea;
			text-decoration: none;
			font-weight: 600;
		}
		@media (max-width: 600px) {
			.header h1 {
				font-size: 24px;
			}
			.content {
				padding: 20px;
			}
			.cert-header {
				flex-direction: column;
				align-items: flex-start;
			}
		}
	</style>
</head>
<body>
	<div class="container">
		<div class="header">
			<h1>🔒 SSL Certificate Monitor</h1>
			<p>Generated: ` + time.Now().Format("Monday, January 2, 2006 at 3:04 PM") + `</p>
		</div>
		<div class="content">`

	// Statistics
	criticalCount := 0
	warningCount := 0
	cautionCount := 0
	okCount := 0

	for _, cert := range allCerts {
		if cert.DaysRemaining <= 7 {
			criticalCount++
		} else if cert.DaysRemaining <= 14 {
			warningCount++
		} else if cert.DaysRemaining <= 30 {
			cautionCount++
		} else {
			okCount++
		}
	}

	body += `<div class="stats-container">`
	body += fmt.Sprintf(`
		<div class="stat-card">
			<div class="stat-number">%d</div>
			<div class="stat-label">Total Certificates</div>
		</div>`, len(allCerts))
	
	if criticalCount > 0 {
		body += fmt.Sprintf(`
		<div class="stat-card" style="background: linear-gradient(135deg, #dc3545 0%, #c82333 100%);">
			<div class="stat-number">%d</div>
			<div class="stat-label">Critical (≤7 days)</div>
		</div>`, criticalCount)
	}
	
	if warningCount > 0 {
		body += fmt.Sprintf(`
		<div class="stat-card" style="background: linear-gradient(135deg, #ffc107 0%, #e0a800 100%);">
			<div class="stat-number">%d</div>
			<div class="stat-label">Warning (8-14 days)</div>
		</div>`, warningCount)
	}
	
	body += `</div>`

	// Expiring certificates section
	if len(expiringCerts) > 0 {
		body += `<div class="alert-section">
			<h2><span style="font-size: 28px;">⚠️</span> Certificates Expiring Soon</h2>
			<p style="margin-bottom: 20px; opacity: 0.9;">The following certificates need immediate attention:</p>`

		for _, cert := range expiringCerts {
			badgeClass := "badge-warning"
			cardClass := "warning"
			if cert.DaysRemaining <= 7 {
				badgeClass = "badge-critical"
				cardClass = "critical"
			}

			body += fmt.Sprintf(`
			<div class="cert-card %s" style="background: white; border-left-color: white;">
				<div class="cert-header">
					<div class="cert-name" style="color: #333;">%s</div>
					<span class="cert-badge %s">%d days remaining</span>
				</div>
				<div class="cert-details">
					<div class="cert-detail-item">
						<span class="cert-detail-label">URL:</span>
						<span>%s</span>
					</div>
					<div class="cert-detail-item">
						<span class="cert-detail-label">Certificate:</span>
						<span>%s</span>
					</div>
					<div class="cert-detail-item">
						<span class="cert-detail-label">Expires:</span>
						<span>%s</span>
					</div>
				</div>
			</div>`,
				cardClass, cert.Name, badgeClass, cert.DaysRemaining,
				cert.URL, cert.CommonName, cert.ExpiryDate.Format("January 2, 2006"))
		}

		body += `</div>`
	}

	// All certificates section
	body += `<h2 class="section-title">📋 All Monitored Certificates</h2>`

	for _, cert := range allCerts {
		badgeClass := "badge-ok"
		cardClass := ""
		badgeText := fmt.Sprintf("%d days", cert.DaysRemaining)

		if cert.DaysRemaining <= 7 {
			badgeClass = "badge-critical"
			cardClass = "critical"
		} else if cert.DaysRemaining <= 14 {
			badgeClass = "badge-warning"
			cardClass = "warning"
		} else if cert.DaysRemaining <= 30 {
			badgeClass = "badge-caution"
			cardClass = "caution"
		}

		body += fmt.Sprintf(`
		<div class="cert-card %s">
			<div class="cert-header">
				<div class="cert-name">%s</div>
				<span class="cert-badge %s">%s</span>
			</div>
			<div class="cert-details">
				<div class="cert-detail-item">
					<span class="cert-detail-label">🌐 URL:</span>
					<span class="cert-url">%s</span>
				</div>
				<div class="cert-detail-item">
					<span class="cert-detail-label">📜 Certificate:</span>
					<span>%s</span>
				</div>
				<div class="cert-detail-item">
					<span class="cert-detail-label">📅 Expires:</span>
					<span>%s</span>
				</div>
			</div>
		</div>`,
			cardClass, cert.Name, badgeClass, badgeText,
			cert.URL, cert.CommonName, cert.ExpiryDate.Format("January 2, 2006"))
	}

	body += `
		</div>
		<div class="footer">
			<p>Automated SSL Certificate Monitoring System</p>
			<p style="margin-top: 10px; font-size: 12px;">This is an automated notification. Please do not reply to this email.</p>
		</div>
	</div>
</body>
</html>`

	return body
}

func sendSlackNotification(certs []CertInfo) {
	slackWebhookURL := os.Getenv("SLACK_WEBHOOK_URL")

	if slackWebhookURL == "" {
		logger.Println("Slack webhook URL missing, skipping Slack notification")
		return
	}

	message := "🚨 *SSL Certificates Expiring Soon*\\n\\n"
	for _, cert := range certs {
		emoji := "⚠️"
		if cert.DaysRemaining <= 7 {
			emoji = "🔴"
		}
		message += fmt.Sprintf("%s *%s* (%s)\\n• Certificate: %s\\n• Days Remaining: *%d*\\n• Expires: %s\\n\\n",
			emoji, cert.Name, cert.URL, cert.CommonName, cert.DaysRemaining, cert.ExpiryDate.Format("2006-01-02"))
	}

	payload := map[string]interface{}{
		"text": message,
		"blocks": []map[string]interface{}{
			{
				"type": "header",
				"text": map[string]string{
					"type": "plain_text",
					"text": "🚨 SSL Certificates Expiring Soon",
				},
			},
			{
				"type": "section",
				"text": map[string]string{
					"type": "mrkdwn",
					"text": message,
				},
			},
		},
	}

	jsonData, err := json.Marshal(payload)
	if err != nil {
		logger.Printf("Error marshaling Slack payload: %v", err)
		return
	}

	resp, err := http.Post(slackWebhookURL, "application/json", bytes.NewBuffer(jsonData))
	if err != nil {
		logger.Printf("Error sending Slack notification: %v", err)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		logger.Printf("Slack notification failed with status: %d", resp.StatusCode)
		return
	}

	logger.Println("Slack notification sent successfully")
}
