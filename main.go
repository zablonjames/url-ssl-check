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
	body := `<html><body style="font-family: Arial, sans-serif;">`
	body += `<h2>SSL Certificate Monitoring Report</h2>`
	body += fmt.Sprintf(`<p>Report generated: %s</p>`, time.Now().Format("2006-01-02 15:04:05"))

	if len(expiringCerts) > 0 {
		body += `<h3 style="color: #d9534f;">⚠️ Certificates Expiring Soon (≤14 days)</h3>`
		body += `<table border="1" cellpadding="8" cellspacing="0" style="border-collapse: collapse; width: 100%;">`
		body += `<tr style="background-color: #f8d7da;"><th>Name</th><th>URL</th><th>Certificate Name</th><th>Days Remaining</th><th>Expiry Date</th></tr>`

		for _, cert := range expiringCerts {
			color := "#d9534f"
			if cert.DaysRemaining > 7 {
				color = "#f0ad4e"
			}
			body += fmt.Sprintf(`<tr><td>%s</td><td>%s</td><td>%s</td><td style="color: %s; font-weight: bold;">%d</td><td>%s</td></tr>`,
				cert.Name, cert.URL, cert.CommonName, color, cert.DaysRemaining, cert.ExpiryDate.Format("2006-01-02"))
		}
		body += `</table><br>`
	}

	body += `<h3>All Monitored Certificates</h3>`
	body += `<table border="1" cellpadding="8" cellspacing="0" style="border-collapse: collapse; width: 100%;">`
	body += `<tr style="background-color: #f0f0f0;"><th>Name</th><th>URL</th><th>Certificate Name</th><th>Days Remaining</th><th>Expiry Date</th></tr>`

	for _, cert := range allCerts {
		rowColor := "#ffffff"
		if cert.DaysRemaining <= 14 {
			rowColor = "#f8d7da"
		} else if cert.DaysRemaining <= 30 {
			rowColor = "#fff3cd"
		}
		body += fmt.Sprintf(`<tr style="background-color: %s;"><td>%s</td><td>%s</td><td>%s</td><td>%d</td><td>%s</td></tr>`,
			rowColor, cert.Name, cert.URL, cert.CommonName, cert.DaysRemaining, cert.ExpiryDate.Format("2006-01-02"))
	}

	body += `</table></body></html>`
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
