import requests
import time
from selenium import webdriver
from selenium.webdriver.chrome.service import Service
from webdriver_manager.chrome import ChromeDriverManager

# CHANGED: Use the logging endpoint instead of the manual check endpoint
API_ENDPOINT = "http://localhost:5000/api/log-url"

def send_to_dashboard(url):
    """Sends the captured URL to the phishing detection backend for logging."""
    try:
        # Added 'source' so the dashboard knows where this came from
        payload = {
            "url": url,
            "source": "selenium_script" 
        }
        response = requests.post(API_ENDPOINT, json=payload, timeout=5)
        
        if response.ok:
            data = response.json()
            # This will show in your terminal so you can see it's working
            print(f"Captured & Logged: {url}")
            print(f"Result: [{data.get('status').upper()}] Score: {data.get('score')}/100")
        else:
            print(f"Failed to reach dashboard: Status {response.status_code}")
    except Exception as e:
        print(f"Error connecting to dashboard: {e}")

service = Service(ChromeDriverManager().install())
driver = webdriver.Chrome(service=service)

try:
    # Start with the initial page
    target_url = "https://www.scrapethissite.com"
    driver.get(target_url)
    
    last_url = driver.current_url
    send_to_dashboard(last_url)

    print("\n--- 🟢 LIVE LOGGING ACTIVE ---")
    print("Every website you visit in this Chrome window will be sent to the dashboard.")
    
    while True:
        # Check if the URL has changed every 1 second
        if driver.current_url != last_url:
            last_url = driver.current_url
            send_to_dashboard(last_url)
        time.sleep(1) 

except KeyboardInterrupt:
    print("\nStopping script...")
finally:
    driver.quit()